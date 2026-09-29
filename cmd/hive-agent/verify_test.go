package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hive-immune/hive-immune/pkg/credential"
	"github.com/hive-immune/hive-immune/pkg/dsse"
)

// testDecision mirrors the fields verify prints.
type testDecision struct {
	Time   time.Time `json:"time"`
	Agent  string    `json:"agent"`
	Tool   string    `json:"tool"`
	Action string    `json:"action"`
	Rule   string    `json:"rule"`
	Reason string    `json:"reason"`
}

func newSigningKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

// writeCredentials signs decisions into a JSONL file the way the gateway does.
func writeCredentials(t *testing.T, key ed25519.PrivateKey, path string, recs ...testDecision) {
	t.Helper()
	log, err := credential.Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range recs {
		if err := log.Append(r); err != nil {
			t.Fatal(err)
		}
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyCommand(t *testing.T) {
	key := newSigningKey(t)
	path := filepath.Join(t.TempDir(), "credentials.jsonl")
	writeCredentials(t, key, path,
		testDecision{Time: time.Unix(1_700_000_000, 0), Agent: "a1", Tool: "read_file", Action: "allow", Rule: "risk.read"},
		testDecision{Time: time.Unix(1_700_000_001, 0), Agent: "a1", Tool: "send_email", Action: "deny", Rule: "taint.egress", Reason: "external content"},
	)

	var out, logs bytes.Buffer
	err := dispatch([]string{"verify", "-in", path, "-pub", hex.EncodeToString(key.Public().(ed25519.PublicKey))},
		strings.NewReader(""), &out, &logs)

	if err != nil {
		t.Fatalf("verify: %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "agent=a1 tool=read_file action=allow rule=risk.read") {
		t.Fatalf("first line missing:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "action=deny rule=taint.egress") {
		t.Fatalf("second line missing:\n%s", out.String())
	}
	if !strings.Contains(logs.String(), "verified 2 credentials") {
		t.Fatalf("summary missing: %q", logs.String())
	}
}

// TestVerifyCommandFromStdin: the reviewer can pipe the trail instead of
// pointing at a file.
func TestVerifyCommandFromStdin(t *testing.T) {
	key := newSigningKey(t)
	path := filepath.Join(t.TempDir(), "credentials.jsonl")
	writeCredentials(t, key, path, testDecision{Agent: "a1", Tool: "read_file", Action: "allow", Rule: "risk.read"})
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	var out, logs bytes.Buffer
	if err := dispatch([]string{"verify", "-pub", hex.EncodeToString(key.Public().(ed25519.PublicKey))},
		bytes.NewReader(raw), &out, &logs); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !strings.Contains(out.String(), "ok   line 1") {
		t.Fatalf("output = %q", out.String())
	}
}

// TestVerifyRejectsTampering: an edited line and a line from another key
// both fail, and the count in the error tells the reviewer how far the
// trail can be trusted.
func TestVerifyRejectsTampering(t *testing.T) {
	key := newSigningKey(t)
	other := newSigningKey(t)
	path := filepath.Join(t.TempDir(), "credentials.jsonl")
	writeCredentials(t, key, path, testDecision{Agent: "a1", Tool: "read_file", Action: "allow", Rule: "risk.read"})

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o640)
	if err != nil {
		t.Fatal(err)
	}
	// A credential signed by somebody else.
	env, err := dsse.Sign(credential.PayloadType, []byte(`{"schema":"`+credential.Schema+`","decision":{}}`), other, "x")
	if err != nil {
		t.Fatal(err)
	}
	line, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		t.Fatal(err)
	}
	// And a line that is not a credential at all.
	if _, err := f.WriteString("this is not JSON\n"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	var out, logs bytes.Buffer
	err = dispatch([]string{"verify", "-in", path, "-pub", hex.EncodeToString(key.Public().(ed25519.PublicKey))},
		strings.NewReader(""), &out, &logs)
	if err == nil {
		t.Fatal("a tampered trail must fail")
	}
	if !strings.Contains(err.Error(), "2 of 3 credentials failed") {
		t.Fatalf("error = %v", err)
	}
	if !strings.Contains(out.String(), "ok   line 1") {
		t.Fatalf("the intact line must still be reported:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "fail line 2") || !strings.Contains(out.String(), "fail line 3") {
		t.Fatalf("failures must name their line:\n%s", out.String())
	}
}

// TestVerifyWrongKey: the same trail under a different public key fails
// completely - the signature is the whole point.
func TestVerifyWrongKey(t *testing.T) {
	key := newSigningKey(t)
	other := newSigningKey(t)
	path := filepath.Join(t.TempDir(), "credentials.jsonl")
	writeCredentials(t, key, path, testDecision{Agent: "a1", Tool: "read_file", Action: "allow"})

	var out, logs bytes.Buffer
	err := dispatch([]string{"verify", "-in", path, "-pub", hex.EncodeToString(other.Public().(ed25519.PublicKey))},
		strings.NewReader(""), &out, &logs)
	if err == nil || !strings.Contains(err.Error(), "1 of 1") {
		t.Fatalf("error = %v, want 1 of 1 failed", err)
	}
}

func TestVerifyRejectsBadUsage(t *testing.T) {
	dir := t.TempDir()
	key := newSigningKey(t)
	pub := hex.EncodeToString(key.Public().(ed25519.PublicKey))
	empty := filepath.Join(dir, "empty.jsonl")
	if err := os.WriteFile(empty, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	bad := [][]string{
		{"verify"},                     // no -pub
		{"verify", "-pub", "zz"},       // not hex
		{"verify", "-pub", "deadbeef"}, // too short
		{"verify", "-pub", pub, "-in", filepath.Join(dir, "missing")}, // missing file
		{"verify", "-pub", pub, "-in", empty},                         // empty trail
		{"verify", "-pub", pub, "-in", dir},                           // directory
		{"verify", "-pub", pub, "-bogus"},                             // unknown flag
	}
	for _, args := range bad {
		var out bytes.Buffer
		if err := dispatch(args, strings.NewReader(""), &out, &out); err == nil {
			t.Errorf("%v: want error", args)
		}
	}
}
