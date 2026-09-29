package sim

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestGridTopology(t *testing.T) {
	g, err := NewGrid(3, 3)
	if err != nil {
		t.Fatal(err)
	}

	if g.Center() != "n-1-1" || len(g.Nodes()) != 9 {
		t.Fatalf("center %s, nodes %d", g.Center(), len(g.Nodes()))
	}
	if n := g.Neighbors(g.ID(0, 0)); len(n) != 2 {
		t.Fatalf("corner must have 2 neighbours, got %v", n)
	}
	if n := g.Neighbors(g.Center()); len(n) != 4 {
		t.Fatalf("center must have 4 neighbours, got %v", n)
	}
	if h := g.Hops(g.ID(0, 0), g.ID(2, 2)); h != 4 {
		t.Fatalf("want 4 hops, got %d", h)
	}
	if g.Hops("nope", g.Center()) != -1 || g.Within("nope", 1) != nil {
		t.Fatal("unknown nodes must be handled")
	}
	prox := g.Proximity(1, 1)
	if prox(g.Center(), g.Center()) != 1 || prox(g.ID(0, 0), g.ID(2, 2)) != 0 || prox("nope", g.Center()) != 0 {
		t.Fatal("proximity out of expected range")
	}
	if _, err := NewGrid(0, 5); err == nil {
		t.Fatal("empty grid must fail")
	}
}

func TestRunIsDeterministic(t *testing.T) {
	a, err := Run(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	b, err := Run(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(a, b) {
		t.Fatal("same config must produce the same result")
	}
}

func TestForgedSignalsNeverReachTheField(t *testing.T) {
	res, err := Run(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}

	if res.Counters.ForgeriesRejected == 0 {
		t.Fatal("malicious agents forge every tick; forgeries must be observed and rejected")
	}
	if res.Counters.InvalidRejected != 0 {
		t.Fatalf("honest agents never emit malformed signals, got %d", res.Counters.InvalidRejected)
	}
}

func TestReputationSeparatesLiarsFromHonestAgents(t *testing.T) {
	res, err := Run(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}

	if !(res.HonestTrust > 0.9 && res.LiarTrust < 0.1) {
		t.Fatalf("honest %.2f, liars %.2f", res.HonestTrust, res.LiarTrust)
	}
}

// TestSwarmContainsSlowIntruder is a regression guard on the reference
// scenario: across many seeds the swarm must usually contain the intruder
// while keeping collateral damage low.
func TestSwarmContainsSlowIntruder(t *testing.T) {
	const seeds = 20
	contained, falseIso, compromised := 0, 0, 0
	for s := uint64(1); s <= seeds; s++ {
		cfg := DefaultConfig()
		cfg.Seed = s
		cfg.SnapshotEvery = 0
		res, err := Run(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if res.ContainedAt >= 0 {
			contained++
		}
		falseIso += res.Final().FalseIsolated
		compromised += res.Final().Compromised
	}

	if contained < seeds*7/10 {
		t.Errorf("contained only %d/%d runs", contained, seeds)
	}
	if falseIso > seeds/4 {
		t.Errorf("%d false isolations across %d runs", falseIso, seeds)
	}
	if avg := float64(compromised) / seeds; avg > 10 {
		t.Errorf("average %.1f nodes compromised", avg)
	}
}

func TestNoAttackersMeansNoMaliciousTrust(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaliciousRatio = 0
	cfg.SpreadRate = 0

	res, err := Run(cfg)
	if err != nil {
		t.Fatal(err)
	}

	if res.Final().FalseIsolated != 0 || res.Malicious != 0 || res.LiarTrust != 0 {
		t.Fatalf("unexpected: %+v, malicious=%d", res.Final(), res.Malicious)
	}
}

func TestSnapshotsAndSummary(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Ticks = 25
	cfg.SnapshotEvery = 10

	res, err := Run(cfg)
	if err != nil {
		t.Fatal(err)
	}

	if len(res.Frames) != 4 || res.Frames[3].Tick != 24 {
		t.Fatalf("want frames at 0,10,20,24, got %d", len(res.Frames))
	}
	if lines := strings.Count(res.Frames[0].Map, "\n"); lines != cfg.Height {
		t.Fatalf("map must have %d rows, got %d", cfg.Height, lines)
	}
	for _, want := range []string{"first detection", "false isolations", "forgeries rejected", "reputation"} {
		if !strings.Contains(res.Summary(), want) {
			t.Errorf("summary missing %q", want)
		}
	}
	if (Result{}).Final() != (TickStats{}) {
		t.Fatal("empty result must have zero final stats")
	}
	if tickOrNever(-1, cfg) != "never" {
		t.Fatal("negative tick must read never")
	}
}

func TestConfigValidation(t *testing.T) {
	bad := []func(*Config){
		func(c *Config) { c.Width = 2 },
		func(c *Config) { c.Height = maxSide + 1 },
		func(c *Config) { c.Ticks = 0 },
		func(c *Config) { c.TickInterval = 0 },
		func(c *Config) { c.MaliciousRatio = 1 },
		func(c *Config) { c.NoiseRate = -0.1 },
		func(c *Config) { c.SpreadRate = 2 },
		func(c *Config) { c.DetectRate = 2 },
		func(c *Config) { c.VoteRadius = 0 },
		func(c *Config) { c.FieldScale = 0 },
		func(c *Config) { c.Falloff = -1 },
		func(c *Config) { c.DepositMin = 0 },
		func(c *Config) { c.MinReputation = 1 },
		func(c *Config) { c.LearningRate = 0 },
		func(c *Config) { c.SnapshotEvery = -1 },
		func(c *Config) { c.Policy.MinVoters = 0 },
		func(c *Config) { c.Field.HalfLife = 0 },
	}
	for i, mutate := range bad {
		cfg := DefaultConfig()
		mutate(&cfg)
		if _, err := Run(cfg); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("case %d: want ErrInvalidConfig, got %v", i, err)
		}
	}
}
