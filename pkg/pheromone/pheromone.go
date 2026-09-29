// Package pheromone implements the stigmergy layer of hive-immune: a shared,
// time-decaying, spatially weighted field of threat signals.
//
// Agents never coordinate directly. Each one deposits signals about what it
// observes, and every agent reads the accumulated "scent" around a node to
// decide how alarmed it should be. Sporadic noise fades on its own, while a
// real, spreading attack keeps reinforcing the field along its path.
package pheromone

import (
	"errors"
	"fmt"
	"math"
	"sync"
	"time"
)

// NodeID identifies a node in the swarm.
type NodeID string

// Signal is a single threat observation deposited into the field.
type Signal struct {
	Origin   NodeID    `json:"origin"`   // node that made the observation (and signed it)
	Subject  NodeID    `json:"subject"`  // node the observation is about
	Kind     string    `json:"kind"`     // detector category, e.g. "falco.Read sensitive file untrusted"
	Strength float64   `json:"strength"` // confidence in [0, 1]
	At       time.Time `json:"at"`       // observation time
}

// Proximity reports how strongly a signal about subject is felt at node at.
// It must return a value in [0, 1]; out-of-range values are clamped.
type Proximity func(at, subject NodeID) float64

// ErrInvalidSignal is returned when a signal fails validation.
var ErrInvalidSignal = errors.New("pheromone: invalid signal")

// ErrInvalidConfig is returned when a Config fails validation.
var ErrInvalidConfig = errors.New("pheromone: invalid config")

// Config tunes the field.
type Config struct {
	// HalfLife is the time for a signal to lose half of its strength.
	HalfLife time.Duration
	// MaxSignals bounds memory. When exceeded, the oldest signals are evicted.
	MaxSignals int
	// MaxSkew rejects signals timestamped further than this into the future,
	// so a skewed or malicious clock cannot plant signals that never decay.
	MaxSkew time.Duration
	// OriginCap is the maximum intensity any single origin may contribute at a
	// node. It stops one compromised agent from flooding the field alone.
	OriginCap float64
}

// DefaultConfig returns conservative defaults.
func DefaultConfig() Config {
	return Config{
		HalfLife:   30 * time.Second,
		MaxSignals: 10_000,
		MaxSkew:    5 * time.Second,
		OriginCap:  1.0,
	}
}

// Validate reports whether the config is usable.
func (c Config) Validate() error {
	switch {
	case c.HalfLife <= 0:
		return fmt.Errorf("%w: HalfLife must be positive", ErrInvalidConfig)
	case c.MaxSignals <= 0:
		return fmt.Errorf("%w: MaxSignals must be positive", ErrInvalidConfig)
	case c.MaxSkew < 0:
		return fmt.Errorf("%w: MaxSkew must not be negative", ErrInvalidConfig)
	case !(c.OriginCap > 0): // also rejects NaN
		return fmt.Errorf("%w: OriginCap must be positive", ErrInvalidConfig)
	}
	return nil
}

// Field is a concurrency-safe pheromone field.
type Field struct {
	cfg     Config
	mu      sync.RWMutex
	signals []Signal
}

// NewField creates an empty field.
func NewField(cfg Config) (*Field, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &Field{cfg: cfg}, nil
}

// Deposit adds a signal to the field. now is the receiver's current time.
func (f *Field) Deposit(s Signal, now time.Time) error {
	if err := validateSignal(s); err != nil {
		return err
	}
	if s.At.After(now.Add(f.cfg.MaxSkew)) {
		return fmt.Errorf("%w: timestamp %s is too far in the future", ErrInvalidSignal, s.At.Format(time.RFC3339Nano))
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	f.signals = append(f.signals, s)
	if over := len(f.signals) - f.cfg.MaxSignals; over > 0 {
		// Copy so the evicted prefix can be garbage collected.
		f.signals = append([]Signal(nil), f.signals[over:]...)
	}
	return nil
}

// Intensity returns the accumulated threat intensity felt at node at.
// Each origin's contribution is capped at Config.OriginCap.
func (f *Field) Intensity(at NodeID, now time.Time, prox Proximity) float64 {
	f.mu.RLock()
	defer f.mu.RUnlock()

	perOrigin := make(map[NodeID]float64)
	for _, s := range f.signals {
		w := clamp01(prox(at, s.Subject))
		if w == 0 {
			continue
		}
		perOrigin[s.Origin] += decay(s.Strength, now.Sub(s.At), f.cfg.HalfLife) * w
	}

	total := 0.0
	for _, v := range perOrigin {
		total += math.Min(v, f.cfg.OriginCap)
	}
	return total
}

// Contributions returns, for every origin that has reported on exactly
// subject, the decayed strength of its signals, capped at OriginCap. Unlike
// Intensity it keeps origins apart, so each one can be treated as a vote.
func (f *Field) Contributions(subject NodeID, now time.Time) map[NodeID]float64 {
	f.mu.RLock()
	defer f.mu.RUnlock()

	out := make(map[NodeID]float64)
	for _, s := range f.signals {
		if s.Subject == subject {
			out[s.Origin] += decay(s.Strength, now.Sub(s.At), f.cfg.HalfLife)
		}
	}
	for origin, v := range out {
		out[origin] = math.Min(v, f.cfg.OriginCap)
	}
	return out
}

// Prune drops signals whose decayed strength has fallen below epsilon and
// returns how many were removed.
func (f *Field) Prune(now time.Time, epsilon float64) int {
	f.mu.Lock()
	defer f.mu.Unlock()

	kept := make([]Signal, 0, len(f.signals))
	for _, s := range f.signals {
		if decay(s.Strength, now.Sub(s.At), f.cfg.HalfLife) >= epsilon {
			kept = append(kept, s)
		}
	}
	removed := len(f.signals) - len(kept)
	f.signals = kept
	return removed
}

// Len returns the number of signals currently held.
func (f *Field) Len() int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return len(f.signals)
}

// Saturate maps an unbounded intensity to [0, 1). scale is the intensity at
// which the result reaches ~63%; a larger scale demands more independent
// origins before the field looks alarming.
func Saturate(intensity, scale float64) float64 {
	if !(intensity > 0) || !(scale > 0) {
		return 0
	}
	return 1 - math.Exp(-intensity/scale)
}

func validateSignal(s Signal) error {
	switch {
	case s.Origin == "":
		return fmt.Errorf("%w: empty origin", ErrInvalidSignal)
	case s.Subject == "":
		return fmt.Errorf("%w: empty subject", ErrInvalidSignal)
	case math.IsNaN(s.Strength) || s.Strength < 0 || s.Strength > 1:
		return fmt.Errorf("%w: strength %v outside [0, 1]", ErrInvalidSignal, s.Strength)
	case s.At.IsZero():
		return fmt.Errorf("%w: zero timestamp", ErrInvalidSignal)
	}
	return nil
}

// decay applies exponential half-life decay. Signals from the (bounded) near
// future are treated as fresh rather than amplified.
func decay(strength float64, age, halfLife time.Duration) float64 {
	if age < 0 {
		age = 0
	}
	return strength * math.Exp2(-float64(age)/float64(halfLife))
}

func clamp01(v float64) float64 {
	switch {
	case math.IsNaN(v) || v <= 0:
		return 0
	case v >= 1:
		return 1
	}
	return v
}
