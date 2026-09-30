// swarmfeed lets the gateway read the swarm's response level for its own
// agent from the local node's status endpoint, closing the loop: what the
// field says about this agent is what the next call is judged against.
//
// The feed is cached (a status fetch per call would be absurd) and stays
// deliberately sticky on failure: a flapping node must not reset a contain
// decision to "all clear". After Config.MaxStale without a successful
// refresh it forgets, because an agent frozen forever by a dead node is
// also a failure - the policy, taint and capability gates still hold when
// the swarm is silent.
package gateway

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/123456342g-lang/hive-immune/pkg/node"
	"github.com/123456342g-lang/hive-immune/pkg/quorum"
)

const (
	// DefaultStatusTTL is how long a fetched level is reused.
	DefaultStatusTTL = 2 * time.Second
	// DefaultStatusMaxStale is how long the last good level survives a
	// node that stopped answering.
	DefaultStatusMaxStale = time.Minute
	// nodeClientTimeout bounds every swarm request; the gateway serves
	// from cache when the node is slow.
	nodeClientTimeout = 2 * time.Second
	// maxStatusBytes bounds the status response.
	maxStatusBytes = 4 << 20
)

// swarmFeed fetches and caches one agent's response level.
type swarmFeed struct {
	url    string
	agent  string
	client *http.Client
	now    func() time.Time
	log    *slog.Logger
	ttl    time.Duration
	stale  time.Duration

	mu       sync.Mutex
	level    quorum.Level
	have     bool
	attempt  time.Time // last fetch attempt, successful or not
	lastOK   time.Time // last successful fetch
	fetching bool      // an earlier fetch is still in flight
}

func newSwarmFeed(baseURL, agent string, client *http.Client, now func() time.Time, log *slog.Logger, ttl, stale time.Duration) *swarmFeed {
	return &swarmFeed{
		url: baseURL + node.StatusPath, agent: agent, client: client, now: now, log: log,
		ttl: ttl, stale: stale,
	}
}

// Level returns the swarm's current level for this agent.
func (f *swarmFeed) Level() quorum.Level {
	f.mu.Lock()
	defer f.mu.Unlock()

	t := f.now()
	// Every fetch attempt - successful or not - restarts the TTL, so a
	// dead node cannot add its timeout to each call the gateway handles.
	if !f.attempt.IsZero() && t.Sub(f.attempt) < f.ttl {
		return f.current(t)
	}
	if f.fetching {
		return f.current(t)
	}
	f.fetching = true
	lvl, err := f.fetch()
	f.fetching, f.attempt = false, t
	if err != nil {
		f.log.Warn("swarm status unavailable", "err", err)
		return f.current(t)
	}
	f.level, f.have, f.lastOK = lvl, true, t
	return lvl
}

// current returns the last good level while it is fresh enough, otherwise
// none. Callers hold f.mu.
func (f *swarmFeed) current(t time.Time) quorum.Level {
	if f.have && t.Sub(f.lastOK) <= f.stale {
		return f.level
	}
	return quorum.LevelNone
}

func (f *swarmFeed) fetch() (quorum.Level, error) {
	resp, err := f.client.Get(f.url)
	if err != nil {
		return quorum.LevelNone, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return quorum.LevelNone, fmt.Errorf("status endpoint: %s", resp.Status)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxStatusBytes+1))
	if err != nil {
		return quorum.LevelNone, err
	}
	if len(raw) > maxStatusBytes {
		return quorum.LevelNone, fmt.Errorf("status response larger than %d bytes", maxStatusBytes)
	}
	var report struct {
		Members []struct {
			Node  string       `json:"node"`
			Level quorum.Level `json:"level"`
		} `json:"members"`
	}
	if err := json.Unmarshal(raw, &report); err != nil {
		return quorum.LevelNone, fmt.Errorf("status response: %w", err)
	}
	for _, m := range report.Members {
		if m.Node == f.agent {
			return m.Level, nil
		}
	}
	// The agent is not a swarm member (yet). Say so once per fetch rather
	// than pretending the swarm declared it healthy.
	return quorum.LevelNone, fmt.Errorf("agent %q is not listed in the node's status; is it in peers.json?", f.agent)
}
