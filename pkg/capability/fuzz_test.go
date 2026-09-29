package capability

import (
	"crypto/ed25519"
	"fmt"
	"testing"
	"time"
)

// fuzzRoot is a fixed root key so the valid corpus token stays reproducible.
func fuzzRoot() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
}

var fuzzNow = time.Unix(1_700_000_000, 0)

// FuzzNewChecker: token bytes come from whoever holds them, so decoding
// must never panic. Anything that passes the signature proof must then
// answer Check the same way twice.
func FuzzNewChecker(f *testing.F) {
	root := fuzzRoot()
	tok, err := Issue(root, IssueRequest{
		Subject: "agent-1", Tools: []string{"read_file"}, TTL: time.Hour,
	}, fuzzNow)
	if err != nil {
		f.Fatal(err)
	}
	pub := root.Public().(ed25519.PublicKey)

	f.Add(tok, []byte(pub))
	f.Add("", []byte(pub))
	f.Add("not base64 at all!", []byte(pub))
	f.Add(tok, []byte("short"))
	f.Add(tok, []byte{})

	f.Fuzz(func(t *testing.T, token string, root []byte) {
		if len(root) != ed25519.PublicKeySize {
			return
		}
		c, err := NewChecker(token, ed25519.PublicKey(root))
		if err != nil {
			return
		}
		first := c.Check("agent-1", "read_file", fuzzNow)
		second := c.Check("agent-1", "read_file", fuzzNow)
		if fmt.Sprint(first) != fmt.Sprint(second) {
			t.Fatalf("check disagreed with itself: %v vs %v", first, second)
		}
	})
}

// FuzzIssue: subject and tool names are operator input. A token the issuer
// accepts must round-trip through the checker, and a rejected input must
// be rejected with an error, never a panic.
func FuzzIssue(f *testing.F) {
	root := fuzzRoot()
	pub := root.Public().(ed25519.PublicKey)

	f.Add("agent-1", "read_file", int64(time.Hour))
	f.Add("", "", int64(0))
	f.Add("agent; check if true", "tool with spaces", int64(-1))
	f.Add("agent-1", `evil"); allow if true; check "`, int64(time.Hour))
	f.Add("agent-1", "read_file", int64(1<<62))

	f.Fuzz(func(t *testing.T, subject, tool string, ttl int64) {
		tok, err := Issue(root, IssueRequest{
			Subject: subject, Tools: []string{tool}, TTL: time.Duration(ttl),
		}, fuzzNow)
		if err != nil {
			return
		}
		c, err := NewChecker(tok, pub)
		if err != nil {
			t.Fatalf("accepted token does not verify: %v", err)
		}
		if err := c.Check(subject, tool, fuzzNow); err != nil {
			t.Fatalf("issued token refused its own subject/tool: %v", err)
		}
	})
}
