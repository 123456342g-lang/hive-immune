package sensor

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/hive-immune/hive-immune/pkg/pheromone"
)

var (
	// ErrForeignHost means the event was reported for a different host than
	// the one this agent speaks for.
	ErrForeignHost = errors.New("sensor: event from foreign host")
	// ErrStale means the event is too old, or implausibly far in the future.
	ErrStale = errors.New("sensor: event outside the accepted time window")
	// ErrThrottled means an equal or stronger signal of the same kind was
	// emitted within the cooldown.
	ErrThrottled = errors.New("sensor: event throttled")
)

// MapperConfig controls how events become signals.
type MapperConfig struct {
	// Node is the identity signals are issued for (and signed as).
	Node pheromone.NodeID
	// Host, if set, is the only sensor host name accepted. This stops a
	// shared or misrouted event stream from making one agent report on
	// another machine.
	Host string
	// MinStrength drops events below this severity.
	MinStrength float64
	// MaxAge drops events older than this, e.g. when replaying old logs.
	MaxAge time.Duration
	// MaxSkew drops events timestamped further than this in the future.
	MaxSkew time.Duration
	// Cooldown suppresses repeats of the same kind unless they are stronger.
	// The pheromone field already caps per-origin intensity; this keeps a
	// noisy rule from flooding the network with redundant signals.
	Cooldown time.Duration
}

// DefaultMapperConfig returns defaults for node: Falco "Warning" and above,
// events up to five minutes old, and at most one signal per kind every ten
// seconds.
func DefaultMapperConfig(node pheromone.NodeID) MapperConfig {
	return MapperConfig{
		Node: node, MinStrength: 0.5,
		MaxAge: 5 * time.Minute, MaxSkew: 5 * time.Second, Cooldown: 10 * time.Second,
	}
}

// Validate reports whether the config is usable.
func (c MapperConfig) Validate() error {
	switch {
	case c.Node == "":
		return errors.New("sensor: Node must be set")
	case !(c.MinStrength > 0 && c.MinStrength <= 1):
		return fmt.Errorf("sensor: MinStrength %v outside (0, 1]", c.MinStrength)
	case c.MaxAge <= 0:
		return errors.New("sensor: MaxAge must be positive")
	case c.MaxSkew < 0:
		return errors.New("sensor: MaxSkew must not be negative")
	case c.Cooldown < 0:
		return errors.New("sensor: Cooldown must not be negative")
	}
	return nil
}

type emission struct {
	at       time.Time
	strength float64
}

// Mapper turns events into signals about its own node. It is safe for
// concurrent use.
type Mapper struct {
	cfg  MapperConfig
	mu   sync.Mutex
	last map[string]emission
}

// NewMapper validates cfg and returns a Mapper.
func NewMapper(cfg MapperConfig) (*Mapper, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &Mapper{cfg: cfg, last: make(map[string]emission)}, nil
}

// Map converts e into a signal, or returns why it was dropped. now is the
// agent's current time.
func (m *Mapper) Map(e Event, now time.Time) (pheromone.Signal, error) {
	if m.cfg.Host != "" && e.Host != m.cfg.Host {
		return pheromone.Signal{}, fmt.Errorf("%w: %q", ErrForeignHost, e.Host)
	}
	if e.Severity < m.cfg.MinStrength {
		return pheromone.Signal{}, ErrSkip
	}
	if now.Sub(e.At) > m.cfg.MaxAge || e.At.Sub(now) > m.cfg.MaxSkew {
		return pheromone.Signal{}, fmt.Errorf("%w: event at %s", ErrStale, e.At.Format(time.RFC3339))
	}

	kind := e.Source + "." + e.Rule
	m.mu.Lock()
	defer m.mu.Unlock()
	if prev, ok := m.last[kind]; ok && now.Sub(prev.at) < m.cfg.Cooldown && e.Severity <= prev.strength {
		return pheromone.Signal{}, ErrThrottled
	}
	if _, tracked := m.last[kind]; !tracked && len(m.last) >= maxTrackedKinds {
		m.evictExpired(now)
		if len(m.last) >= maxTrackedKinds {
			return pheromone.Signal{}, fmt.Errorf("%w: too many distinct kinds", ErrThrottled)
		}
	}
	m.last[kind] = emission{at: now, strength: e.Severity}

	return pheromone.Signal{
		Origin: m.cfg.Node, Subject: m.cfg.Node, Kind: kind, Strength: e.Severity, At: e.At,
	}, nil
}

// maxTrackedKinds bounds cooldown state, since rule names come from
// untrusted input and could otherwise grow memory without limit.
const maxTrackedKinds = 4096

// evictExpired drops cooldown entries that no longer suppress anything.
// The caller must hold m.mu.
func (m *Mapper) evictExpired(now time.Time) {
	for kind, prev := range m.last {
		if now.Sub(prev.at) >= m.cfg.Cooldown {
			delete(m.last, kind)
		}
	}
}
