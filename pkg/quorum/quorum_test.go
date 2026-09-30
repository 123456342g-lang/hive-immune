package quorum

import (
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"testing"

	"github.com/123456342g-lang/hive-immune/pkg/pheromone"
)

func votesFor(suspect pheromone.NodeID, scores ...float64) []Vote {
	out := make([]Vote, len(scores))
	for i, s := range scores {
		out[i] = Vote{Voter: pheromone.NodeID(fmt.Sprintf("v%d", i)), Suspect: suspect, Score: s}
	}
	return out
}

func TestDecideLevels(t *testing.T) {
	p := DefaultPolicy()
	cases := []struct {
		scores []float64
		want   Level
	}{
		{[]float64{0, 0, 0}, LevelNone},
		{[]float64{0.2, 0.2, 0.2}, LevelObserve},
		{[]float64{0.5, 0.5, 0.3}, LevelContain},
		{[]float64{0.9, 0.8, 0.7}, LevelIsolate},
	}
	for _, tc := range cases {
		d := p.Decide("x", votesFor("x", tc.scores...), Uniform{})
		if d.Level != tc.want {
			t.Errorf("scores %v: want %v, got %v (score %.3f)", tc.scores, tc.want, d.Level, d.Score)
		}
	}
}

func TestTooFewVotersCapsAtObserve(t *testing.T) {
	d := DefaultPolicy().Decide("x", votesFor("x", 1, 1), Uniform{})

	if d.Level != LevelObserve || d.Voters != 2 {
		t.Fatalf("two voters must not isolate, got %v with %d voters", d.Level, d.Voters)
	}
}

func TestIgnoredVotes(t *testing.T) {
	votes := []Vote{
		{Voter: "x", Suspect: "x", Score: 0},          // self-vote
		{Voter: "a", Suspect: "other", Score: 1},      // different suspect
		{Voter: "b", Suspect: "x", Score: math.NaN()}, // NaN
		{Voter: "c", Suspect: "x", Score: 5},          // clamped to 1
		{Voter: "d", Suspect: "x", Score: 0},          // replaced below
		{Voter: "d", Suspect: "x", Score: 1},
		{Voter: "e", Suspect: "x", Score: -2}, // clamped to 0
	}

	d := DefaultPolicy().Decide("x", votes, Uniform{})

	if d.Voters != 3 || math.Abs(d.Score-2.0/3) > 1e-9 {
		t.Fatalf("want 3 voters and score 2/3, got %d and %v", d.Voters, d.Score)
	}
}

func TestNoWeightMeansNoAction(t *testing.T) {
	zero := weights{"v0": 0, "v1": 0, "v2": 0}
	d := DefaultPolicy().Decide("x", votesFor("x", 1, 1, 1), zero)

	if d.Level != LevelNone || d.Voters != 0 {
		t.Fatalf("zero-weight voters must not count, got %+v", d)
	}
}

// TestByzantineMinorityCannotForceContainment checks the bound documented in
// the package comment across many random swarm sizes and vote patterns.
func TestByzantineMinorityCannotForceContainment(t *testing.T) {
	p := DefaultPolicy()
	rng := rand.New(rand.NewPCG(1, 2))

	for trial := 0; trial < 5000; trial++ {
		n := 3 + rng.IntN(60)
		malicious := rng.IntN((n-1)/3 + 1) // strictly fewer than n/3
		var votes []Vote
		for i := 0; i < n; i++ {
			score := rng.Float64() * 0.1 // honest view of a healthy node
			if i < malicious {
				score = 1 // attacker-controlled voters scream "compromised"
			}
			votes = append(votes, Vote{Voter: pheromone.NodeID(fmt.Sprint(i)), Suspect: "victim", Score: score})
		}

		d := p.Decide("victim", votes, Uniform{})

		if d.Level >= LevelContain {
			t.Fatalf("trial %d: %d/%d malicious voters forced %v (score %.3f)", trial, malicious, n, d.Level, d.Score)
		}
	}
}

func TestPolicyValidate(t *testing.T) {
	if err := DefaultPolicy().Validate(); err != nil {
		t.Fatalf("default policy invalid: %v", err)
	}
	bad := []Policy{
		{MinVoters: 0, ObserveAt: 0.2, ContainAt: 0.4, IsolateAt: 0.6},
		{MinVoters: 3, ObserveAt: 0, ContainAt: 0.4, IsolateAt: 0.6},
		{MinVoters: 3, ObserveAt: 0.5, ContainAt: 0.4, IsolateAt: 0.6},
		{MinVoters: 3, ObserveAt: 0.2, ContainAt: 0.4, IsolateAt: 1.1},
		{MinVoters: 3, ObserveAt: math.NaN(), ContainAt: 0.4, IsolateAt: 0.6},
	}
	for i, p := range bad {
		if err := p.Validate(); !errors.Is(err, ErrInvalidPolicy) {
			t.Errorf("case %d: want ErrInvalidPolicy, got %v", i, err)
		}
	}
}

func TestLevelString(t *testing.T) {
	if b, err := LevelContain.MarshalText(); err != nil || string(b) != "contain" {
		t.Fatalf("MarshalText: %q %v", b, err)
	}
	var l Level
	if err := l.UnmarshalText([]byte("isolate")); err != nil || l != LevelIsolate {
		t.Fatalf("UnmarshalText: %v %v", l, err)
	}
	if err := l.UnmarshalText([]byte("panic")); err == nil {
		t.Fatal("unknown level must fail")
	}
	if DefaultPolicy().Classify(0.99) != LevelIsolate || DefaultPolicy().Classify(0.1) != LevelNone {
		t.Fatal("Classify thresholds")
	}
	want := map[Level]string{LevelNone: "none", LevelObserve: "observe", LevelContain: "contain", LevelIsolate: "isolate", Level(9): "Level(9)"}
	for l, s := range want {
		if l.String() != s {
			t.Errorf("want %q, got %q", s, l.String())
		}
	}
}

func TestLedgerRecordIsImmutable(t *testing.T) {
	l, err := NewLedger(0.5, 0.5)
	if err != nil {
		t.Fatal(err)
	}

	next := l.Record(map[pheromone.NodeID]bool{"good": true, "bad": false})

	if l.Weight("good") != 0.5 || l.Weight("bad") != 0.5 {
		t.Fatal("Record must not modify the receiver")
	}
	if next.Weight("good") != 0.75 || next.Weight("bad") != 0.25 {
		t.Fatalf("got good=%v bad=%v", next.Weight("good"), next.Weight("bad"))
	}
	if next.Weight("unknown") != 0.5 {
		t.Fatal("unknown voters start at the initial weight")
	}
}

func TestLedgerSilencesPersistentLiars(t *testing.T) {
	l, _ := NewLedger(0.5, 0.2)
	for i := 0; i < 30; i++ {
		l = l.Record(map[pheromone.NodeID]bool{"liar": false, "honest": true})
	}

	if l.Weight("liar") > 0.01 || l.Weight("honest") < 0.99 {
		t.Fatalf("liar=%v honest=%v", l.Weight("liar"), l.Weight("honest"))
	}
}

func TestNewLedgerValidation(t *testing.T) {
	for _, args := range [][2]float64{{0, 0.1}, {1.5, 0.1}, {0.5, 0}, {0.5, 2}, {math.NaN(), 0.1}} {
		if _, err := NewLedger(args[0], args[1]); err == nil {
			t.Errorf("NewLedger(%v, %v) should fail", args[0], args[1])
		}
	}
}

type weights map[pheromone.NodeID]float64

func (w weights) Weight(id pheromone.NodeID) float64 { return w[id] }
