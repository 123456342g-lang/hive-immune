package gateway

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/123456342g-lang/hive-immune/pkg/credential"
	"github.com/123456342g-lang/hive-immune/pkg/dsse"
)

// openCredential starts a credential log for the test and returns it with
// the public key a reviewer would hold.
func openCredential(t *testing.T) (*credential.Log, ed25519.PublicKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "credentials.jsonl")
	log, err := credential.Open(path, priv)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	return log, pub, path
}

// readCredentials parses the credential file into verified decisions.
func readCredentials(t *testing.T, path string, pub ed25519.PublicKey) []Record {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read credentials: %v", err)
	}
	var out []Record
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var env dsse.Envelope
		if err := json.Unmarshal([]byte(line), &env); err != nil {
			t.Fatalf("credential line is not an envelope: %v", err)
		}
		p, err := credential.Verify(env, pub)
		if err != nil {
			t.Fatalf("credential verify: %v", err)
		}
		var rec Record
		if err := json.Unmarshal(p.Decision, &rec); err != nil {
			t.Fatalf("credential decision: %v", err)
		}
		out = append(out, rec)
	}
	return out
}

// TestCredentialWritten: an allowed call produces a signed copy of the
// audit record, so a third party can check the decision without the log.
func TestCredentialWritten(t *testing.T) {
	log, pub, path := openCredential(t)
	s, out := testServer(t, func(c *Config) {
		c.PolicyPath = withPolicy(t)
		c.Credential = log
	})

	feed(t, s, callLine(1, "read_file"))
	answer(t, s, out, `{"jsonrpc":"2.0","id":1,"result":{"content":[]}}`)

	recs := readCredentials(t, path, pub)
	if len(recs) != 1 {
		t.Fatalf("got %d credentials, want 1", len(recs))
	}
	if recs[0].Tool != "read_file" || recs[0].Action != ActionAllow || recs[0].Rule == "" {
		t.Fatalf("signed decision = %+v", recs[0])
	}
	// The signed copy must match the audit line it was derived from.
	audit := mustTail(t, s, 1)
	want, err := json.Marshal(audit[0])
	if err != nil {
		t.Fatal(err)
	}
	got, err := json.Marshal(recs[0])
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("credential %s != audit %s", got, want)
	}
}

// TestCredentialForDenial: refusals are signed too - that is the record
// the operator needs when someone asks why the agent was stopped.
func TestCredentialForDenial(t *testing.T) {
	log, pub, path := openCredential(t)
	s, _ := testServer(t, func(c *Config) { c.Credential = log })

	feed(t, s, callLine(1, "read_file"))

	recs := readCredentials(t, path, pub)
	if len(recs) != 1 {
		t.Fatalf("got %d credentials, want 1", len(recs))
	}
	if recs[0].Action != ActionDeny || recs[0].Rule != "degraded.deny" {
		t.Fatalf("signed decision = %+v", recs[0])
	}
}

// TestCredentialFailureIsNotFatal: if the credential file breaks, the
// audit log still holds the decision and the call is not dropped.
func TestCredentialFailureIsNotFatal(t *testing.T) {
	log, _, path := openCredential(t)
	if err := log.Close(); err != nil { // simulate a broken sink
		t.Fatal(err)
	}
	s, out := testServer(t, func(c *Config) { c.Credential = log })
	feed(t, s, callLine(1, "read_file"))
	if !strings.Contains(out.String(), "hive-gateway denied") {
		t.Fatalf("client output = %q", out.String())
	}
	if recs := mustTail(t, s, 1); len(recs) != 1 || recs[0].Action != ActionDeny {
		t.Fatalf("audit = %+v", recs)
	}
	if raw, err := os.ReadFile(path); err != nil || len(raw) != 0 {
		t.Fatalf("credentials file = %q, err = %v (nothing should be written after close)", raw, err)
	}
}
