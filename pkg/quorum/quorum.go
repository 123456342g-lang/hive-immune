// Package quorum turns individual suspicion votes into a collective response,
// modelled on bacterial quorum sensing: no single agent can trigger a strong
// reaction, only a sufficiently large and trusted local majority can.
//
// # Byzantine bound
//
// Decide uses a reputation-weighted mean of vote scores. If honest voters
// score a healthy node at most h, and voters controlled by an attacker hold a
// weight fraction m, the resulting score is at most m + (1-m)*h. With the
// default policy (ContainAt = 0.4), attackers holding under 1/3 of the voting
// weight cannot force even containment of a healthy node as long as honest
// voters score it at or below 0.1. The property is exercised in the tests.
package quorum

import (
	"errors"
	"fmt"
	"math"
	"slices"

	"github.com/hive-immune/hive-immune/pkg/pheromone"
)

// Level is the strength of the collective response.
type Level int

// Response levels, from weakest to strongest.
const (
	LevelNone    Level = iota // no action
	LevelObserve              // raise sampling, cross-check neighbours
	LevelContain              // micro-segment, rate-limit, force re-auth
	LevelIsolate              // cut the node off, divert to deception
)

func (l Level) String() string {
	switch l {
	case LevelNone:
		return "none"
	case LevelObserve:
		return "observe"
	case LevelContain:
		return "contain"
	case LevelIsolate:
		return "isolate"
	}
	return fmt.Sprintf("Level(%d)", int(l))
}

// Vote is one agent's suspicion that Suspect is compromised.
type Vote struct {
	Voter   pheromone.NodeID
	Suspect pheromone.NodeID
	Score   float64 // [0, 1]; out-of-range values are clamped, NaN is ignored
}

// ErrInvalidPolicy is returned when a Policy fails validation.
var ErrInvalidPolicy = errors.New("quorum: invalid policy")

// Policy holds the quorum thresholds.
type Policy struct {
	// MinVoters is the number of distinct, weighted voters required before
	// the response may exceed LevelObserve.
	MinVoters int
	// Thresholds on the weighted mean score. Must satisfy
	// 0 < ObserveAt <= ContainAt <= IsolateAt <= 1.
	ObserveAt, ContainAt, IsolateAt float64
}

// DefaultPolicy returns thresholds that satisfy the package's Byzantine bound.
func DefaultPolicy() Policy {
	return Policy{MinVoters: 3, ObserveAt: 0.2, ContainAt: 0.4, IsolateAt: 0.6}
}

// Validate reports whether the policy is usable.
func (p Policy) Validate() error {
	if p.MinVoters < 1 {
		return fmt.Errorf("%w: MinVoters must be at least 1", ErrInvalidPolicy)
	}
	if !(0 < p.ObserveAt && p.ObserveAt <= p.ContainAt && p.ContainAt <= p.IsolateAt && p.IsolateAt <= 1) {
		return fmt.Errorf("%w: need 0 < ObserveAt <= ContainAt <= IsolateAt <= 1", ErrInvalidPolicy)
	}
	return nil
}

// Decision is the outcome of a quorum round for one suspect.
type Decision struct {
	Suspect pheromone.NodeID
	Level   Level
	Score   float64 // reputation-weighted mean suspicion
	Voters  int     // distinct voters with positive weight
}

// Weigher reports how much a voter's opinion counts, in [0, 1].
type Weigher interface {
	Weight(pheromone.NodeID) float64
}

// Decide aggregates votes about suspect. Votes about other nodes, self-votes
// and NaN scores are ignored; if a voter votes more than once, only its last
// vote counts.
func (p Policy) Decide(suspect pheromone.NodeID, votes []Vote, w Weigher) Decision {
	latest := make(map[pheromone.NodeID]float64)
	for _, v := range votes {
		if v.Suspect != suspect || v.Voter == suspect || math.IsNaN(v.Score) {
			continue
		}
		latest[v.Voter] = math.Max(0, math.Min(1, v.Score))
	}

	// Sum in a fixed order so identical inputs always yield bit-identical
	// scores; map iteration order would otherwise make boundary cases flaky.
	ids := make([]pheromone.NodeID, 0, len(latest))
	for id := range latest {
		ids = append(ids, id)
	}
	slices.Sort(ids)

	var sum, weight float64
	voters := 0
	for _, voter := range ids {
		score := latest[voter]
		vw := math.Min(w.Weight(voter), 1) // no voter may outweigh a fully trusted one
		if !(vw > 0) {
			continue
		}
		sum += vw * score
		weight += vw
		voters++
	}

	d := Decision{Suspect: suspect, Voters: voters}
	if weight == 0 {
		return d
	}
	d.Score = sum / weight
	d.Level = p.level(d.Score, voters)
	return d
}

func (p Policy) level(score float64, voters int) Level {
	lvl := p.Classify(score)
	if voters < p.MinVoters && lvl > LevelObserve {
		return LevelObserve
	}
	return lvl
}

// Classify maps a score to a level using the policy thresholds alone,
// without the MinVoters rule.
func (p Policy) Classify(score float64) Level {
	switch {
	case score >= p.IsolateAt:
		return LevelIsolate
	case score >= p.ContainAt:
		return LevelContain
	case score >= p.ObserveAt:
		return LevelObserve
	}
	return LevelNone
}

// MarshalText encodes the level by name, e.g. in JSON.
func (l Level) MarshalText() ([]byte, error) { return []byte(l.String()), nil }

// UnmarshalText decodes a level name produced by MarshalText.
func (l *Level) UnmarshalText(b []byte) error {
	for c := LevelNone; c <= LevelIsolate; c++ {
		if c.String() == string(b) {
			*l = c
			return nil
		}
	}
	return fmt.Errorf("quorum: unknown level %q", b)
}
