package quorum

import (
	"fmt"
	"math"

	"github.com/hive-immune/hive-immune/pkg/pheromone"
)

// Ledger tracks how trustworthy each voter has proven to be. It is an
// immutable value: Record returns a new Ledger and never changes the
// receiver, so a Ledger can be shared across goroutines without locking.
//
// Weights move toward 1 when a voter's judgement is later confirmed and
// toward 0 when it is refuted, so agents that keep raising false alarms (or
// keep hiding real attacks) gradually lose their say.
type Ledger struct {
	weights map[pheromone.NodeID]float64
	initial float64
	rate    float64
}

// NewLedger creates a ledger in which unknown voters start at initial weight
// and each outcome moves a weight by rate toward its target. Both values must
// lie in (0, 1].
func NewLedger(initial, rate float64) (Ledger, error) {
	if !(initial > 0 && initial <= 1) || !(rate > 0 && rate <= 1) {
		return Ledger{}, fmt.Errorf("quorum: ledger initial and rate must be in (0, 1], got %v and %v", initial, rate)
	}
	return Ledger{initial: initial, rate: rate}, nil
}

// Weight returns the voter's current weight in [0, 1].
func (l Ledger) Weight(id pheromone.NodeID) float64 {
	if w, ok := l.weights[id]; ok {
		return w
	}
	return l.initial
}

// Record returns a new ledger updated with confirmed outcomes: true means the
// voter judged correctly, false means it did not.
func (l Ledger) Record(outcomes map[pheromone.NodeID]bool) Ledger {
	next := make(map[pheromone.NodeID]float64, len(l.weights)+len(outcomes))
	for id, w := range l.weights {
		next[id] = w
	}
	for id, correct := range outcomes {
		target := 0.0
		if correct {
			target = 1
		}
		w := l.Weight(id)
		next[id] = math.Max(0, math.Min(1, w+l.rate*(target-w)))
	}
	return Ledger{weights: next, initial: l.initial, rate: l.rate}
}

// Uniform gives every voter the same weight. Useful when no reputation
// history exists yet.
type Uniform struct{}

// Weight always returns 1.
func (Uniform) Weight(pheromone.NodeID) float64 { return 1 }
