package credential

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/123456342g-lang/hive-immune/pkg/dsse"
)

type fakeDecision struct {
	Tool   string `json:"tool"`
	Action string `json:"action"`
}

func newKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func TestAppendAndVerify(t *testing.T) {
	key := newKey(t)
	path := filepath.Join(t.TempDir(), "credentials.jsonl")
	log, err := Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := log.Append(fakeDecision{Tool: "read_file", Action: "allow"}); err != nil {
		t.Fatal(err)
	}
	if err := log.Append(fakeDecision{Tool: "send_email", Action: "deny"}); err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	if err := log.Append(fakeDecision{Tool: "x"}); err == nil {
		t.Fatal("appending to a closed log must fail loudly")
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines", len(lines))
	}
	var env dsse.Envelope
	if err := json.Unmarshal([]byte(lines[0]), &env); err != nil {
		t.Fatalf("line is not an envelope: %v", err)
	}
	if env.PayloadType != PayloadType {
		t.Fatalf("payload type = %q", env.PayloadType)
	}
	if env.Signatures[0].KeyID != KeyID(key) {
		t.Fatalf("key id = %q, want %q", env.Signatures[0].KeyID, KeyID(key))
	}

	p, err := Verify(env, key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if p.Schema != Schema {
		t.Fatalf("schema = %q", p.Schema)
	}
	var d fakeDecision
	if err := json.Unmarshal(p.Decision, &d); err != nil {
		t.Fatal(err)
	}
	if d.Tool != "read_file" || d.Action != "allow" {
		t.Fatalf("decision = %+v", d)
	}

	// The wrong key sees no valid signature.
	other := newKey(t)
	if _, err := Verify(env, other.Public().(ed25519.PublicKey)); err == nil {
		t.Fatal("the wrong public key must fail")
	}
}

func TestNilLogDiscards(t *testing.T) {
	var l *Log
	if err := l.Append(fakeDecision{Tool: "x"}); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	l2, err := Open("", newKey(t))
	if err != nil || l2 != nil {
		t.Fatalf("empty path: log=%v err=%v, want nil,nil", l2, err)
	}
}

func TestOpenRejectsBadInput(t *testing.T) {
	if _, err := Open(filepath.Join(t.TempDir(), "x.jsonl"), make([]byte, 4)); err == nil {
		t.Fatal("a short signing key must be rejected")
	}
	dir := t.TempDir()
	if _, err := Open(dir, newKey(t)); err == nil {
		t.Fatal("a directory must be rejected")
	}
}

func TestVerifyRejectsWrongSchema(t *testing.T) {
	key := newKey(t)
	env, err := dsse.Sign(PayloadType, []byte(`{"schema":"other/v9","decision":{}}`), key, KeyID(key))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(env, key.Public().(ed25519.PublicKey)); err == nil {
		t.Fatal("a payload with another schema must be refused")
	}
	if _, err := Verify(dsse.Envelope{}, key.Public().(ed25519.PublicKey)); err == nil {
		t.Fatal("an empty envelope must be refused")
	}
	badJSON := env
	badJSON.Payload = "bm90IGpzb24=" // "not json"
	if _, err := Verify(badJSON, key.Public().(ed25519.PublicKey)); err == nil {
		t.Fatal("a non-JSON payload must be refused")
	}
}

// TestConcurrentAppend: the pumps and the admin endpoint may write at the
// same time; lines must not interleave.
func TestConcurrentAppend(t *testing.T) {
	key := newKey(t)
	path := filepath.Join(t.TempDir(), "credentials.jsonl")
	log, err := Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := log.Append(fakeDecision{Tool: "t", Action: "allow"}); err != nil {
				t.Errorf("append: %v", err)
			}
		}()
	}
	wg.Wait()
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 20 {
		t.Fatalf("got %d lines, want 20", len(lines))
	}
	pub := key.Public().(ed25519.PublicKey)
	for i, line := range lines {
		var env dsse.Envelope
		if err := json.Unmarshal([]byte(line), &env); err != nil {
			t.Fatalf("line %d: %v", i, err)
		}
		if _, err := Verify(env, pub); err != nil {
			t.Fatalf("line %d: %v", i, err)
		}
	}
}
