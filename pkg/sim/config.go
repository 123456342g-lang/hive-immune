// Package sim is a deterministic, single-process simulation of a hive-immune
// swarm defending a grid network against a spreading intruder while a
// minority of its own agents lie.
//
// It exists to make the swarm's behaviour observable and testable before any
// real sensor or transport is involved. The simulation is an idealisation:
// in particular, reputation learning is fed with ground truth, standing in
// for the post-incident confirmation a real deployment would rely on.
package sim

import (
	"errors"
	"fmt"
	"time"

	"github.com/hive-immune/hive-immune/pkg/pheromone"
	"github.com/hive-immune/hive-immune/pkg/quorum"
)

// ErrInvalidConfig is returned when a Config fails validation.
var ErrInvalidConfig = errors.New("sim: invalid config")

// maxTicks bounds run length.
const maxTicks = 100_000

// Config describes one simulation run.
type Config struct {
	Width, Height int
	Ticks         int
	Seed          uint64
	TickInterval  time.Duration

	MaliciousRatio float64 // fraction of agents that lie (Byzantine)
	NoiseRate      float64 // chance per neighbour per tick of a false alarm
	SpreadRate     float64 // chance per tick an active intruder hops to a neighbour
	DetectRate     float64 // chance per tick a neighbour notices a stealthy intruder
	VoteRadius     int     // hops within which agents vote on a suspect
	FieldScale     float64 // field intensity at which suspicion reaches ~63%
	Falloff        float64 // spatial decay of the pheromone field per hop
	DepositMin     float64 // minimum observation score worth reporting
	MinReputation  float64 // origins below this weight are not heard
	LearningRate   float64 // how fast reputation reacts to outcomes

	SnapshotEvery int // record a map every N ticks; 0 disables

	Policy quorum.Policy
	Field  pheromone.Config
}

// DefaultConfig returns the reference scenario: a 20×20 network, one
// intruder starting in the middle, and 10% of agents acting maliciously.
func DefaultConfig() Config {
	return Config{
		Width: 20, Height: 20, Ticks: 60, Seed: 42, TickInterval: 5 * time.Second,
		MaliciousRatio: 0.10, NoiseRate: 0.02, SpreadRate: 0.05, DetectRate: 0.4,
		VoteRadius: 2, FieldScale: 3, Falloff: 1.5, DepositMin: 0.3,
		MinReputation: 0.3, LearningRate: 0.1,
		SnapshotEvery: 10,
		Policy:        quorum.DefaultPolicy(),
		Field:         pheromone.DefaultConfig(),
	}
}

// Validate reports whether the config is usable.
func (c Config) Validate() error {
	checks := []struct {
		ok  bool
		msg string
	}{
		{c.Width >= 3 && c.Height >= 3 && c.Width <= maxSide && c.Height <= maxSide, fmt.Sprintf("grid must be between 3x3 and %dx%d", maxSide, maxSide)},
		{c.Ticks >= 1 && c.Ticks <= maxTicks, fmt.Sprintf("Ticks must be in [1, %d]", maxTicks)},
		{c.TickInterval > 0, "TickInterval must be positive"},
		{inRange(c.MaliciousRatio, 0, 1, false), "MaliciousRatio must be in [0, 1)"},
		{inRange(c.NoiseRate, 0, 1, true), "NoiseRate must be in [0, 1]"},
		{inRange(c.SpreadRate, 0, 1, true), "SpreadRate must be in [0, 1]"},
		{inRange(c.DetectRate, 0, 1, true), "DetectRate must be in [0, 1]"},
		{c.VoteRadius >= 1, "VoteRadius must be at least 1"},
		{c.FieldScale > 0, "FieldScale must be positive"},
		{c.Falloff >= 0, "Falloff must not be negative"},
		{c.DepositMin > 0 && c.DepositMin <= 1, "DepositMin must be in (0, 1]"},
		{inRange(c.MinReputation, 0, 1, false), "MinReputation must be in [0, 1)"},
		{c.LearningRate > 0 && c.LearningRate <= 1, "LearningRate must be in (0, 1]"},
		{c.SnapshotEvery >= 0, "SnapshotEvery must not be negative"},
	}
	for _, ch := range checks {
		if !ch.ok {
			return fmt.Errorf("%w: %s", ErrInvalidConfig, ch.msg)
		}
	}
	if err := c.Policy.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}
	if err := c.Field.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}
	return nil
}

// inRange reports lo <= v < hi (or <= hi when inclusive). NaN is rejected.
func inRange(v, lo, hi float64, inclusive bool) bool {
	if inclusive {
		return v >= lo && v <= hi
	}
	return v >= lo && v < hi
}
