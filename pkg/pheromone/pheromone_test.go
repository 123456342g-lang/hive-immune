package pheromone

import (
	"errors"
	"math"
	"sync"
	"testing"
	"time"
)

var t0 = time.Unix(1_700_000_000, 0)

func everywhere(_, _ NodeID) float64 { return 1 }

func newTestField(t *testing.T, mutate func(*Config)) *Field {
	t.Helper()
	cfg := DefaultConfig()
	if mutate != nil {
		mutate(&cfg)
	}
	f, err := NewField(cfg)
	if err != nil {
		t.Fatalf("NewField: %v", err)
	}
	return f
}

func sig(origin NodeID, strength float64, at time.Time) Signal {
	return Signal{Origin: origin, Subject: "target", Kind: "test", Strength: strength, At: at}
}

func approx(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

func TestIntensityDecaysByHalfLife(t *testing.T) {
	f := newTestField(t, nil)
	if err := f.Deposit(sig("a", 0.8, t0), t0); err != nil {
		t.Fatal(err)
	}

	got := f.Intensity("target", t0.Add(30*time.Second), everywhere)

	if !approx(got, 0.4) {
		t.Fatalf("after one half-life want 0.4, got %v", got)
	}
}

func TestSingleOriginCannotFloodTheField(t *testing.T) {
	f := newTestField(t, nil)
	for i := 0; i < 1000; i++ {
		if err := f.Deposit(sig("flooder", 1, t0), t0); err != nil {
			t.Fatal(err)
		}
	}

	got := f.Intensity("target", t0, everywhere)

	if !approx(got, 1.0) {
		t.Fatalf("one origin must be capped at OriginCap=1, got %v", got)
	}
}

func TestIndependentOriginsAccumulate(t *testing.T) {
	f := newTestField(t, nil)
	for _, o := range []NodeID{"a", "b", "c"} {
		if err := f.Deposit(sig(o, 0.5, t0), t0); err != nil {
			t.Fatal(err)
		}
	}

	if got := f.Intensity("target", t0, everywhere); !approx(got, 1.5) {
		t.Fatalf("want 1.5, got %v", got)
	}
}

func TestProximityWeightsAndClamps(t *testing.T) {
	f := newTestField(t, nil)
	if err := f.Deposit(sig("a", 1, t0), t0); err != nil {
		t.Fatal(err)
	}

	cases := map[string]struct {
		prox Proximity
		want float64
	}{
		"half":      {func(_, _ NodeID) float64 { return 0.5 }, 0.5},
		"negative":  {func(_, _ NodeID) float64 { return -3 }, 0},
		"above one": {func(_, _ NodeID) float64 { return 7 }, 1},
		"nan":       {func(_, _ NodeID) float64 { return math.NaN() }, 0},
	}
	for name, tc := range cases {
		if got := f.Intensity("target", t0, tc.prox); !approx(got, tc.want) {
			t.Errorf("%s: want %v, got %v", name, tc.want, got)
		}
	}
}

func TestDepositRejectsInvalidSignals(t *testing.T) {
	f := newTestField(t, nil)
	bad := map[string]Signal{
		"empty origin":  {Subject: "x", Strength: 0.5, At: t0},
		"empty subject": {Origin: "x", Strength: 0.5, At: t0},
		"negative":      {Origin: "x", Subject: "y", Strength: -0.1, At: t0},
		"above one":     {Origin: "x", Subject: "y", Strength: 1.1, At: t0},
		"nan":           {Origin: "x", Subject: "y", Strength: math.NaN(), At: t0},
		"zero time":     {Origin: "x", Subject: "y", Strength: 0.5},
		"far future":    {Origin: "x", Subject: "y", Strength: 0.5, At: t0.Add(time.Hour)},
	}
	for name, s := range bad {
		if err := f.Deposit(s, t0); !errors.Is(err, ErrInvalidSignal) {
			t.Errorf("%s: want ErrInvalidSignal, got %v", name, err)
		}
	}
	if f.Len() != 0 {
		t.Fatalf("no invalid signal should be stored, have %d", f.Len())
	}
}

func TestNearFutureSignalIsNotAmplified(t *testing.T) {
	f := newTestField(t, nil)
	if err := f.Deposit(sig("a", 0.6, t0.Add(2*time.Second)), t0); err != nil {
		t.Fatal(err)
	}

	if got := f.Intensity("target", t0, everywhere); !approx(got, 0.6) {
		t.Fatalf("want 0.6, got %v", got)
	}
}

func TestMaxSignalsEvictsOldest(t *testing.T) {
	f := newTestField(t, func(c *Config) { c.MaxSignals = 3 })
	for _, o := range []NodeID{"old", "b", "c", "d"} {
		if err := f.Deposit(sig(o, 1, t0), t0); err != nil {
			t.Fatal(err)
		}
	}

	if f.Len() != 3 {
		t.Fatalf("want 3 signals, got %d", f.Len())
	}
	// Three distinct origins remain, each capped at 1.
	if got := f.Intensity("target", t0, everywhere); !approx(got, 3) {
		t.Fatalf("want intensity 3, got %v", got)
	}
}

func TestPruneRemovesFadedSignals(t *testing.T) {
	f := newTestField(t, nil)
	later := t0.Add(10 * time.Minute)
	if err := f.Deposit(sig("old", 1, t0), t0); err != nil {
		t.Fatal(err)
	}
	if err := f.Deposit(sig("new", 1, later), later); err != nil {
		t.Fatal(err)
	}

	removed := f.Prune(later, 0.01)

	if removed != 1 || f.Len() != 1 {
		t.Fatalf("want 1 removed and 1 kept, got removed=%d len=%d", removed, f.Len())
	}
}

func TestConfigValidation(t *testing.T) {
	bad := []func(*Config){
		func(c *Config) { c.HalfLife = 0 },
		func(c *Config) { c.MaxSignals = 0 },
		func(c *Config) { c.MaxSkew = -1 },
		func(c *Config) { c.OriginCap = 0 },
		func(c *Config) { c.OriginCap = math.NaN() },
	}
	for i, mutate := range bad {
		cfg := DefaultConfig()
		mutate(&cfg)
		if _, err := NewField(cfg); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("case %d: want ErrInvalidConfig, got %v", i, err)
		}
	}
}

func TestContributionsSeparateOriginsAndCap(t *testing.T) {
	f := newTestField(t, nil)
	for i := 0; i < 5; i++ {
		if err := f.Deposit(sig("loud", 0.9, t0), t0); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Deposit(sig("quiet", 0.3, t0), t0); err != nil {
		t.Fatal(err)
	}
	other := Signal{Origin: "x", Subject: "elsewhere", Strength: 1, At: t0}
	if err := f.Deposit(other, t0); err != nil {
		t.Fatal(err)
	}

	got := f.Contributions("target", t0.Add(30*time.Second))

	if len(got) != 2 || !approx(got["loud"], 1) || !approx(got["quiet"], 0.15) {
		t.Fatalf("got %v", got)
	}
}

func TestSaturate(t *testing.T) {
	if Saturate(0, 1) != 0 || Saturate(-1, 1) != 0 || Saturate(1, 0) != 0 || Saturate(math.NaN(), 1) != 0 {
		t.Fatal("degenerate inputs must saturate to 0")
	}
	if got := Saturate(1, 1); !approx(got, 1-math.Exp(-1)) {
		t.Fatalf("got %v", got)
	}
	if Saturate(1e9, 1) > 1 {
		t.Fatal("must never exceed 1")
	}
}

func TestConcurrentDepositAndRead(t *testing.T) {
	f := newTestField(t, nil)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		origin := NodeID(rune('a' + i))
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				_ = f.Deposit(sig(origin, 0.5, t0), t0)
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				_ = f.Intensity("target", t0, everywhere)
			}
		}()
	}
	wg.Wait()

	if f.Len() != 8*200 {
		t.Fatalf("want %d signals, got %d", 8*200, f.Len())
	}
}
