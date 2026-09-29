// Package node runs one member of a hive-immune swarm: it accepts signed
// envelopes (from its own sensors and from peers), keeps the shared
// pheromone field, gossips new signals to every peer, and evaluates the
// swarm's response levels.
package node

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hive-immune/hive-immune/pkg/cluster"
	"github.com/hive-immune/hive-immune/pkg/envelope"
	"github.com/hive-immune/hive-immune/pkg/pheromone"
	"github.com/hive-immune/hive-immune/pkg/swarm"
)

var (
	// ErrDuplicate means the signal was already received (gossip echo or
	// replay within the acceptance window). It is not a failure.
	ErrDuplicate = errors.New("node: duplicate signal")
	// ErrStale means the signal is older than the acceptance window.
	ErrStale = errors.New("node: stale signal")
	// ErrOverloaded means the replay cache is full; the signal is refused
	// rather than accepted without replay protection.
	ErrOverloaded = errors.New("node: replay cache full")
)

// Config configures a node.
type Config struct {
	Self    pheromone.NodeID
	Cluster cluster.Config
	Field   pheromone.Config
	Params  swarm.Params
	// MaxAge is the acceptance window: older signals are rejected, and
	// digests are remembered this long to stop replays.
	MaxAge time.Duration
	// MaxSeen bounds the replay cache.
	MaxSeen int
	// QueueSize bounds each peer's outbound queue; overflow is dropped.
	QueueSize int
	Client    *http.Client
	Logger    *slog.Logger
	Now       func() time.Time
}

// DefaultConfig returns production defaults for self in c.
func DefaultConfig(self pheromone.NodeID, c cluster.Config) Config {
	fc := pheromone.DefaultConfig()
	fc.HalfLife = 2 * time.Minute
	return Config{
		Self: self, Cluster: c, Field: fc, Params: swarm.DefaultParams(),
		MaxAge: 10 * time.Minute, MaxSeen: 200_000, QueueSize: 4096,
		Client: &http.Client{Timeout: 5 * time.Second},
		Logger: slog.Default(), Now: time.Now,
	}
}

// Stats are cumulative counters.
type Stats struct {
	Accepted   uint64 `json:"accepted"`
	Duplicates uint64 `json:"duplicates"`
	Rejected   uint64 `json:"rejected"`
	Forwarded  uint64 `json:"forwarded"`
	Dropped    uint64 `json:"dropped"`     // outbound queue full
	SendErrors uint64 `json:"send_errors"` // failed deliveries to peers
}

type counters struct {
	accepted, duplicates, rejected, forwarded, dropped, sendErrors atomic.Uint64
}

// Node is one running swarm member. Create it with New and start gossip
// with Run.
type Node struct {
	cfg   Config
	ring  *envelope.Keyring
	field *pheromone.Field
	peers []*peer
	stats counters

	mu   sync.Mutex
	seen map[[32]byte]time.Time
}

// New validates cfg and builds a node.
func New(cfg Config) (*Node, error) {
	if err := cfg.Cluster.Validate(); err != nil {
		return nil, err
	}
	if _, ok := cfg.Cluster.Member(cfg.Self); !ok {
		return nil, fmt.Errorf("node: %q is not a member of the cluster", cfg.Self)
	}
	if err := cfg.Params.Validate(); err != nil {
		return nil, err
	}
	switch {
	case cfg.MaxAge <= 0, cfg.MaxSeen <= 0, cfg.QueueSize <= 0:
		return nil, errors.New("node: MaxAge, MaxSeen and QueueSize must be positive")
	case cfg.Client == nil || cfg.Logger == nil || cfg.Now == nil:
		return nil, errors.New("node: Client, Logger and Now must be set")
	}
	ring, err := cfg.Cluster.Keyring()
	if err != nil {
		return nil, err
	}
	field, err := pheromone.NewField(cfg.Field)
	if err != nil {
		return nil, err
	}
	n := &Node{cfg: cfg, ring: ring, field: field, seen: make(map[[32]byte]time.Time)}
	for _, m := range cfg.Cluster.Peers(cfg.Self) {
		n.peers = append(n.peers, newPeer(m, cfg.QueueSize))
	}
	return n, nil
}

// Self returns this node's id.
func (n *Node) Self() pheromone.NodeID { return n.cfg.Self }

// Peers returns the members this node gossips to.
func (n *Node) Peers() []cluster.Member {
	out := make([]cluster.Member, len(n.peers))
	for i, p := range n.peers {
		out[i] = p.member
	}
	return out
}

// Receive verifies an envelope and, if it is new, adds it to the field and
// queues it for every peer.
func (n *Node) Receive(env envelope.Envelope) error {
	err := n.receive(env)
	switch {
	case err == nil:
		n.stats.accepted.Add(1)
	case errors.Is(err, ErrDuplicate):
		n.stats.duplicates.Add(1)
	default:
		n.stats.rejected.Add(1)
	}
	return err
}

func (n *Node) receive(env envelope.Envelope) error {
	sig, err := n.ring.Open(env)
	if err != nil {
		return err
	}
	now := n.cfg.Now()
	if now.Sub(sig.At) > n.cfg.MaxAge {
		return fmt.Errorf("%w: signal from %s at %s", ErrStale, sig.Origin, sig.At.Format(time.RFC3339))
	}
	digest := envelope.Digest(sig)
	if err := n.remember(digest, sig.At, now); err != nil {
		return err
	}
	if err := n.field.Deposit(sig, now); err != nil {
		n.forget(digest)
		return err
	}
	n.forward(env)
	return nil
}

// remember records digest, failing if it was already seen. Expired entries
// are evicted when the cache fills up.
func (n *Node) remember(digest [32]byte, at, now time.Time) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if _, dup := n.seen[digest]; dup {
		return ErrDuplicate
	}
	if len(n.seen) >= n.cfg.MaxSeen {
		for d, t := range n.seen {
			if now.Sub(t) > n.cfg.MaxAge {
				delete(n.seen, d)
			}
		}
		if len(n.seen) >= n.cfg.MaxSeen {
			return ErrOverloaded
		}
	}
	n.seen[digest] = at
	return nil
}

func (n *Node) forget(digest [32]byte) {
	n.mu.Lock()
	defer n.mu.Unlock()
	delete(n.seen, digest)
}

func (n *Node) forward(env envelope.Envelope) {
	for _, p := range n.peers {
		select {
		case p.queue <- env:
			n.stats.forwarded.Add(1)
		default:
			n.stats.dropped.Add(1)
		}
	}
}

// Evaluate returns the swarm's current view of every member.
func (n *Node) Evaluate() []swarm.Status {
	return swarm.Evaluate(n.field, n.cfg.Cluster.Members, n.cfg.Now(), n.cfg.Params)
}

// Stats returns a snapshot of the counters.
func (n *Node) Stats() Stats {
	return Stats{
		Accepted: n.stats.accepted.Load(), Duplicates: n.stats.duplicates.Load(),
		Rejected: n.stats.rejected.Load(), Forwarded: n.stats.forwarded.Load(),
		Dropped: n.stats.dropped.Load(), SendErrors: n.stats.sendErrors.Load(),
	}
}

// Prune drops faded signals and expired replay-cache entries.
func (n *Node) Prune() {
	now := n.cfg.Now()
	n.field.Prune(now, 0.01)
	n.mu.Lock()
	defer n.mu.Unlock()
	for d, t := range n.seen {
		if now.Sub(t) > n.cfg.MaxAge {
			delete(n.seen, d)
		}
	}
}
