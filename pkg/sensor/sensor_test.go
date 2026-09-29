package sensor

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hive-immune/hive-immune/pkg/envelope"
	"github.com/hive-immune/hive-immune/pkg/pheromone"
)

// Times of the real events captured in testdata.
var (
	falcoAt    = time.Date(2026, 9, 28, 11, 22, 27, 918448895, time.UTC)
	tetragonAt = time.Date(2026, 9, 28, 11, 25, 28, 406235185, time.UTC)
)

func fixture(t *testing.T, name string) [][]byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	var lines [][]byte
	for _, l := range bytes.Split(bytes.TrimSpace(raw), []byte("\n")) {
		lines = append(lines, bytes.TrimRight(l, "\r"))
	}
	return lines
}

func testPolicies() map[string]float64 {
	return map[string]float64{"hive-sensitive-files": 0.8, "hive-tcp-connect": 0.1}
}

func TestFalcoParsesRealAlert(t *testing.T) {
	ev, err := Falco{}.Parse(fixture(t, "falco.jsonl")[0])
	if err != nil {
		t.Fatal(err)
	}

	want := Event{Source: "falco", Rule: "Read sensitive file untrusted", Host: "058ec5cda6f7", Severity: 0.6, At: falcoAt}
	if ev != want {
		t.Fatalf("got %+v\nwant %+v", ev, want)
	}
}

func TestFalcoRejectsBadInput(t *testing.T) {
	bad := map[string]string{
		"not json":         `{`,
		"no rule":          `{"time":"2026-09-28T11:22:27Z","priority":"Warning"}`,
		"unknown priority": `{"time":"2026-09-28T11:22:27Z","rule":"r","priority":"Scary"}`,
		"bad time":         `{"time":"yesterday","rule":"r","priority":"Warning"}`,
		"control chars":    `{"time":"2026-09-28T11:22:27Z","rule":"r\u0007","priority":"Warning"}`,
		"rule too long":    `{"time":"2026-09-28T11:22:27Z","rule":"` + strings.Repeat("a", MaxRuleLen+1) + `","priority":"Warning"}`,
	}
	for name, line := range bad {
		if _, err := (Falco{}).Parse([]byte(line)); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: want ErrMalformed, got %v", name, err)
		}
	}
	if (Falco{}).Name() != "falco" {
		t.Fatal("name")
	}
}

func TestFalcoPriorityIsCaseInsensitive(t *testing.T) {
	ev, err := Falco{}.Parse([]byte(`{"time":"2026-09-28T11:22:27Z","rule":"r","priority":"CRITICAL"}`))
	if err != nil || ev.Severity != 1 {
		t.Fatalf("got %+v, %v", ev, err)
	}
}

func TestTetragonParsesRealEvents(t *testing.T) {
	p, err := NewTetragon(testPolicies())
	if err != nil {
		t.Fatal(err)
	}
	lines := fixture(t, "tetragon.jsonl")

	if _, err := p.Parse(lines[0]); !errors.Is(err, ErrSkip) {
		t.Errorf("process_exec must be skipped, got %v", err)
	}
	ev, err := p.Parse(lines[1])
	if err != nil {
		t.Fatal(err)
	}
	want := Event{Source: "tetragon", Rule: "hive-sensitive-files", Host: "17c37bca5df7", Severity: 0.8, At: tetragonAt}
	if ev != want {
		t.Fatalf("got %+v\nwant %+v", ev, want)
	}
	if ev, err := p.Parse(lines[2]); err != nil || ev.Rule != "hive-tcp-connect" || ev.Severity != 0.1 {
		t.Fatalf("tcp-connect: got %+v, %v", ev, err)
	}
}

func TestTetragonSkipsUnlistedPoliciesAndRejectsGarbage(t *testing.T) {
	p, err := NewTetragon(map[string]float64{"only-this": 0.5})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Parse(fixture(t, "tetragon.jsonl")[1]); !errors.Is(err, ErrSkip) {
		t.Errorf("unlisted policy must be skipped, got %v", err)
	}
	if _, err := p.Parse([]byte(`[]`)); !errors.Is(err, ErrMalformed) {
		t.Errorf("want ErrMalformed, got %v", err)
	}
	if _, err := p.Parse([]byte(`{"process_lsm":{"policy_name":"only-this"},"time":"now"}`)); !errors.Is(err, ErrMalformed) {
		t.Errorf("bad time: want ErrMalformed, got %v", err)
	}
	if p.Name() != "tetragon" {
		t.Fatal("name")
	}
}

func TestNewTetragonValidation(t *testing.T) {
	bad := []map[string]float64{nil, {"": 0.5}, {"p": 0}, {"p": 1.5}, {"p\n": 0.5}}
	for i, m := range bad {
		if _, err := NewTetragon(m); err == nil {
			t.Errorf("case %d should fail", i)
		}
	}
}

func TestTetragonCopiesPolicyMap(t *testing.T) {
	policies := map[string]float64{"p": 0.5}
	parser, err := NewTetragon(policies)
	if err != nil {
		t.Fatal(err)
	}
	delete(policies, "p")

	if _, err := parser.Parse([]byte(`{"process_kprobe":{"policy_name":"p"},"time":"2026-09-28T11:25:28Z"}`)); err != nil {
		t.Fatalf("parser must keep its own copy of the policy map: %v", err)
	}
}

func newMapper(t *testing.T, mutate func(*MapperConfig)) *Mapper {
	t.Helper()
	cfg := DefaultMapperConfig("node-a")
	if mutate != nil {
		mutate(&cfg)
	}
	m, err := NewMapper(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func event(sev float64, at time.Time) Event {
	return Event{Source: "falco", Rule: "r", Host: "h", Severity: sev, At: at}
}

func TestMapperProducesSelfSignal(t *testing.T) {
	m := newMapper(t, nil)

	sig, err := m.Map(event(0.6, falcoAt), falcoAt.Add(time.Second))

	if err != nil {
		t.Fatal(err)
	}
	want := pheromone.Signal{Origin: "node-a", Subject: "node-a", Kind: "falco.r", Strength: 0.6, At: falcoAt}
	if sig != want {
		t.Fatalf("got %+v", sig)
	}
}

func TestMapperFilters(t *testing.T) {
	now := falcoAt
	cases := map[string]struct {
		ev   Event
		want error
	}{
		"weak":         {event(0.4, now), ErrSkip},
		"stale":        {event(1, now.Add(-time.Hour)), ErrStale},
		"future":       {event(1, now.Add(time.Minute)), ErrStale},
		"foreign host": {Event{Source: "falco", Rule: "r", Host: "other", Severity: 1, At: now}, ErrForeignHost},
	}
	for name, tc := range cases {
		m := newMapper(t, func(c *MapperConfig) { c.Host = "h" })
		if _, err := m.Map(tc.ev, now); !errors.Is(err, tc.want) {
			t.Errorf("%s: want %v, got %v", name, tc.want, err)
		}
	}
}

func TestMapperCooldown(t *testing.T) {
	m := newMapper(t, nil)
	now := falcoAt

	if _, err := m.Map(event(0.6, now), now); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Map(event(0.6, now), now.Add(time.Second)); !errors.Is(err, ErrThrottled) {
		t.Fatalf("repeat within cooldown: got %v", err)
	}
	if _, err := m.Map(event(0.8, now), now.Add(2*time.Second)); err != nil {
		t.Fatalf("stronger repeat must pass: %v", err)
	}
	if _, err := m.Map(event(0.8, now), now.Add(time.Minute)); err != nil {
		t.Fatalf("after cooldown the same kind must pass again: %v", err)
	}
}

func TestMapperBoundsCooldownState(t *testing.T) {
	m := newMapper(t, nil)
	now := falcoAt
	for i := 0; i < maxTrackedKinds; i++ {
		e := event(0.6, now)
		e.Rule = "rule-" + string(rune('A'+i%26)) + strings.Repeat("x", i/26)
		if _, err := m.Map(e, now); err != nil {
			t.Fatalf("kind %d: %v", i, err)
		}
	}

	extra := event(0.6, now)
	extra.Rule = "one-too-many"
	if _, err := m.Map(extra, now); !errors.Is(err, ErrThrottled) {
		t.Fatalf("state must be bounded, got %v", err)
	}
	if _, err := m.Map(extra, now.Add(time.Minute)); err != nil {
		t.Fatalf("expired entries must be evicted, got %v", err)
	}
}

func TestMapperConfigValidation(t *testing.T) {
	bad := []func(*MapperConfig){
		func(c *MapperConfig) { c.Node = "" },
		func(c *MapperConfig) { c.MinStrength = 0 },
		func(c *MapperConfig) { c.MaxAge = 0 },
		func(c *MapperConfig) { c.MaxSkew = -1 },
		func(c *MapperConfig) { c.Cooldown = -1 },
	}
	for i, mutate := range bad {
		cfg := DefaultMapperConfig("n")
		mutate(&cfg)
		if _, err := NewMapper(cfg); err == nil {
			t.Errorf("case %d should fail", i)
		}
	}
}

func testSigner(t *testing.T, id pheromone.NodeID) (*envelope.Signer, *envelope.Keyring) {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	s, err := envelope.NewSigner(id, key)
	if err != nil {
		t.Fatal(err)
	}
	ring, err := envelope.NewKeyring(map[pheromone.NodeID]ed25519.PublicKey{id: key.Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	return s, ring
}

// TestPipelineEndToEnd pushes the real captured sensor output, plus hostile
// lines, through the full pipeline and verifies every emitted envelope.
func TestPipelineEndToEnd(t *testing.T) {
	signer, ring := testSigner(t, "node-a")
	tetragon, err := NewTetragon(testPolicies())
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		parser Parser
		file   string
		now    time.Time
		want   Stats
	}{
		{Falco{}, "falco.jsonl", falcoAt, Stats{Lines: 4, Emitted: 1, Malformed: 3}},
		// tcp-connect maps to 0.1, below the default MinStrength of 0.5.
		{tetragon, "tetragon.jsonl", tetragonAt, Stats{Lines: 6, Emitted: 1, Skipped: 2, Malformed: 3}},
	}
	for _, tc := range cases {
		input := string(bytes.Join(fixture(t, tc.file), []byte("\n"))) +
			"\nnot json\n" + strings.Repeat("A", MaxLineBytes+10) + "\n\n{\"truncated\":\r\n"
		mapper := newMapper(t, nil)
		var emitted []envelope.Envelope
		p := Pipeline{
			Parser: tc.parser, Mapper: mapper, Signer: signer,
			Emit: func(e envelope.Envelope) error { emitted = append(emitted, e); return nil },
			Now:  func() time.Time { return tc.now },
		}

		st, err := p.Run(context.Background(), strings.NewReader(input))

		if err != nil {
			t.Fatalf("%s: %v", tc.file, err)
		}
		if st != tc.want {
			t.Errorf("%s: stats %+v, want %+v", tc.file, st, tc.want)
		}
		for _, e := range emitted {
			if _, err := ring.Open(e); err != nil {
				t.Errorf("%s: emitted envelope does not verify: %v", tc.file, err)
			}
		}
	}
}

func TestPipelineErrors(t *testing.T) {
	signer, _ := testSigner(t, "node-a")
	line := strings.NewReader(string(fixture(t, "falco.jsonl")[0]))
	base := Pipeline{
		Parser: Falco{}, Mapper: newMapper(t, nil), Signer: signer,
		Emit: func(envelope.Envelope) error { return errors.New("disk full") },
		Now:  func() time.Time { return falcoAt },
	}

	if _, err := base.Run(context.Background(), line); err == nil || !strings.Contains(err.Error(), "disk full") {
		t.Errorf("emit failure must surface, got %v", err)
	}

	incomplete := base
	incomplete.Emit = nil
	if _, err := incomplete.Run(context.Background(), line); err == nil {
		t.Error("missing component must fail")
	}

	mismatch := base
	mismatch.Mapper = newMapper(t, func(c *MapperConfig) { c.Node = "someone-else" })
	if _, err := mismatch.Run(context.Background(), line); err == nil {
		t.Error("mapper/signer identity mismatch must fail")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := base.Run(ctx, line); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled context: got %v", err)
	}

	if _, err := base.Run(context.Background(), iotestErrReader{}); err == nil {
		t.Error("read failure must surface")
	}
}

type iotestErrReader struct{}

// Regression: Windows PowerShell 5.1 prepends a UTF-8 BOM when piping into a
// native program, which made the first real Falco alert look malformed.
func TestPipelineToleratesLeadingBOM(t *testing.T) {
	signer, _ := testSigner(t, "node-a")
	emitted := 0
	p := Pipeline{
		Parser: Falco{}, Mapper: newMapper(t, nil), Signer: signer,
		Emit: func(envelope.Envelope) error { emitted++; return nil },
		Now:  func() time.Time { return falcoAt },
	}
	input := "\xEF\xBB\xBF" + string(fixture(t, "falco.jsonl")[0]) + "\n"

	st, err := p.Run(context.Background(), strings.NewReader(input))

	if err != nil || st.Malformed != 0 || emitted != 1 {
		t.Fatalf("stats %+v, emitted %d, err %v", st, emitted, err)
	}
}

func (iotestErrReader) Read([]byte) (int, error) { return 0, errors.New("broken pipe") }

func TestReadLineHandlesLongAndCRLFLines(t *testing.T) {
	br := bufio.NewReaderSize(strings.NewReader("a\r\n"+strings.Repeat("b", MaxLineBytes+1)+"\nc"), 16)

	l1, long1, _ := readLine(br)
	_, long2, _ := readLine(br)
	l3, long3, err := readLine(br)

	if string(l1) != "a" || long1 || !long2 || string(l3) != "c" || long3 || err == nil {
		t.Fatalf("got %q %v / %v / %q %v %v", l1, long1, long2, l3, long3, err)
	}
}
