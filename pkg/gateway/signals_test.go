package gateway

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/123456342g-lang/hive-immune/pkg/envelope"
	"github.com/123456342g-lang/hive-immune/pkg/node"
	"github.com/123456342g-lang/hive-immune/pkg/pheromone"
)

func TestSignalStrengthMapping(t *testing.T) {
	cases := []struct {
		rule string
		want float64
		ok   bool
	}{
		{"taint.egress", 0.6, true},
		{"taint.write-internal", 0.5, true},
		{"capability.expired", 0.4, true},
		{"capability.tool-out-of-scope", 0.4, true},
		{"limits.rate", 0.3, true},
		{"limits.budget", 0.3, true},
		{"malformed.call", 0.2, true},
		// The swarm's own verdicts and configuration problems must never
		// feed back into the field.
		{"level.isolate", 0, false},
		{"level.observe", 0, false},
		{"degraded.deny", 0, false},
		{"risk.read", 0, false},
	}
	for _, c := range cases {
		got, ok := signalStrength(c.rule)
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("signalStrength(%q) = %v,%v want %v,%v", c.rule, got, ok, c.want, c.ok)
		}
	}
}

// fakeNode accepts envelope batches and verifies them against the signer.
func fakeNode(t *testing.T, respond func(w http.ResponseWriter)) (*httptest.Server, *[]envelope.Envelope, *sync.Mutex) {
	t.Helper()
	var mu sync.Mutex
	var got []envelope.Envelope
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != node.EnvelopesPath {
			t.Errorf("path = %q, want %q", r.URL.Path, node.EnvelopesPath)
		}
		var batch []envelope.Envelope
		if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
			t.Errorf("body: %v", err)
		}
		mu.Lock()
		got = append(got, batch...)
		mu.Unlock()
		respond(w)
	}))
	t.Cleanup(ts.Close)
	return ts, &got, &mu
}

func newTestEmitter(t *testing.T, url string, cooldown time.Duration, logs *bytes.Buffer) *emitter {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := envelope.NewSigner("a1", priv)
	if err != nil {
		t.Fatal(err)
	}
	h := slog.NewTextHandler(logs, nil)
	return newEmitter(signer, url, http.DefaultClient, time.Now, cooldown, slog.New(h))
}

func TestEmitterDepositsSignedSignal(t *testing.T) {
	var logs bytes.Buffer
	ts, got, mu := fakeNode(t, func(w http.ResponseWriter) {
		_, _ = io.WriteString(w, `{"accepted":1}`)
	})
	e := newTestEmitter(t, ts.URL, time.Minute, &logs)

	e.notify("taint.egress")

	mu.Lock()
	defer mu.Unlock()
	if len(*got) != 1 {
		t.Fatalf("got %d envelopes, want 1", len(*got))
	}
	sig := (*got)[0].Signal
	if sig.Origin != "a1" || sig.Subject != "a1" {
		t.Fatalf("signal identity = %s/%s, want a self-report", sig.Origin, sig.Subject)
	}
	if sig.Kind != "gateway.taint.egress" || sig.Strength != 0.6 {
		t.Fatalf("signal = %+v", sig)
	}
	if logs.Len() != 0 {
		t.Fatalf("unexpected log output: %q", logs.String())
	}
}

func mustSigner(t *testing.T, id pheromone.NodeID, key ed25519.PrivateKey) *envelope.Signer {
	t.Helper()
	s, err := envelope.NewSigner(id, key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestEmitterCooldown: the same rule is reported once per cooldown, other
// rules are not suppressed with it.
func TestEmitterCooldown(t *testing.T) {
	var logs bytes.Buffer
	ts, got, mu := fakeNode(t, func(w http.ResponseWriter) {
		_, _ = io.WriteString(w, `{"accepted":1}`)
	})
	e := newTestEmitter(t, ts.URL, 30*time.Second, &logs)

	e.notify("taint.egress")
	e.notify("taint.egress")
	e.notify("taint.egress")
	e.notify("limits.rate")

	mu.Lock()
	defer mu.Unlock()
	if len(*got) != 2 {
		t.Fatalf("got %d envelopes, want 2 (one per rule)", len(*got))
	}
	if (*got)[1].Signal.Kind != "gateway.limits.rate" {
		t.Fatalf("second signal = %q", (*got)[1].Signal.Kind)
	}
}

// TestEmitterSurvivesNodeTrouble: a dead or rejecting node is logged, not
// raised - the refusal already reached the client and the audit log.
func TestEmitterSurvivesNodeTrouble(t *testing.T) {
	t.Run("rejected", func(t *testing.T) {
		var logs bytes.Buffer
		ts, _, _ := fakeNode(t, func(w http.ResponseWriter) {
			_, _ = io.WriteString(w, `{"accepted":0,"rejected":1}`)
		})
		e := newTestEmitter(t, ts.URL, time.Minute, &logs)
		e.notify("limits.rate")
		if !strings.Contains(logs.String(), "node rejected signal") {
			t.Fatalf("log = %q", logs.String())
		}
	})
	t.Run("http error", func(t *testing.T) {
		var logs bytes.Buffer
		ts, _, _ := fakeNode(t, func(w http.ResponseWriter) {
			http.Error(w, "nope", http.StatusServiceUnavailable)
		})
		e := newTestEmitter(t, ts.URL, time.Minute, &logs)
		e.notify("limits.rate")
		if !strings.Contains(logs.String(), "signal deposit refused") {
			t.Fatalf("log = %q", logs.String())
		}
	})
	t.Run("unreachable", func(t *testing.T) {
		var logs bytes.Buffer
		e := newTestEmitter(t, "http://127.0.0.1:1", time.Minute, &logs)
		e.notify("limits.rate")
		if !strings.Contains(logs.String(), "signal deposit failed") {
			t.Fatalf("log = %q", logs.String())
		}
	})
}

// TestEmitterSealsWithOwnKey: the signature must verify against the
// agent's public half, exactly as the node's keyring will check it.
func TestEmitterSealsWithOwnKey(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ring, err := envelope.NewKeyring(map[pheromone.NodeID]ed25519.PublicKey{"a1": priv.Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	var sealed []envelope.Envelope
	ts, got, mu := fakeNode(t, func(w http.ResponseWriter) {
		_, _ = io.WriteString(w, `{"accepted":1}`)
	})
	e := newEmitter(mustSigner(t, "a1", priv), ts.URL, http.DefaultClient, time.Now, 0, slog.New(slog.NewTextHandler(&logs, nil)))
	e.notify("capability.expired")

	mu.Lock()
	sealed = append(sealed, (*got)...)
	mu.Unlock()
	if len(sealed) != 1 {
		t.Fatalf("got %d envelopes", len(sealed))
	}
	if _, err := ring.Open(sealed[0]); err != nil {
		t.Fatalf("node-side verification failed: %v", err)
	}
	// Cooldown defaults when unset.
	e2 := newEmitter(mustSigner(t, "a1", priv), ts.URL, http.DefaultClient, time.Now, 0, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if e2.cooldown != DefaultSignalCooldown {
		t.Fatalf("cooldown = %v, want the default", e2.cooldown)
	}
}
