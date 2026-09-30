package sensor

import (
	"errors"
	"os"
	"testing"
	"unicode/utf8"
)

func seedFuzz(f *testing.F, file string) {
	raw, err := os.ReadFile("testdata/" + file)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"time":"2026-09-28T11:22:27Z","rule":"r","priority":"Warning"}`))
	f.Add([]byte(`{"process_kprobe":{"policy_name":"hive-sensitive-files"},"time":"2026-09-28T11:25:28Z"}`))
}

// checkEvent asserts the invariants every accepted event must satisfy.
func checkEvent(t *testing.T, ev Event, err error) {
	if err != nil {
		if !errors.Is(err, ErrSkip) && !errors.Is(err, ErrMalformed) {
			t.Fatalf("unexpected error class: %v", err)
		}
		return
	}
	if !(ev.Severity > 0 && ev.Severity <= 1) {
		t.Fatalf("severity %v outside (0, 1]", ev.Severity)
	}
	if ev.Rule == "" || len(ev.Rule) > MaxRuleLen || !utf8.ValidString(ev.Rule) || ev.At.IsZero() {
		t.Fatalf("invalid event accepted: %+v", ev)
	}
}

func FuzzFalcoParse(f *testing.F) {
	seedFuzz(f, "falco.jsonl")
	// Regression: valid RFC3339 for the zero time must be rejected.
	f.Add([]byte(`{"time":"0001-01-01T00:00:00Z","rule":"r","priority":"warning"}`))
	f.Fuzz(func(t *testing.T, line []byte) {
		ev, err := Falco{}.Parse(line)
		checkEvent(t, ev, err)
	})
}

func FuzzTetragonParse(f *testing.F) {
	seedFuzz(f, "tetragon.jsonl")
	p, err := NewTetragon(testPolicies())
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, line []byte) {
		ev, err := p.Parse(line)
		checkEvent(t, ev, err)
	})
}
