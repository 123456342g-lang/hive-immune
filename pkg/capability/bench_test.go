package capability

import (
	"crypto/ed25519"
	"testing"
	"time"
)

// BenchmarkCheck measures the per-call cost of the three datalog gates.
func BenchmarkCheck(b *testing.B) {
	root := fuzzRoot()
	tok, err := Issue(root, IssueRequest{
		Subject: "agent-1", Tools: []string{"read_file"}, TTL: time.Hour,
	}, fuzzNow)
	if err != nil {
		b.Fatal(err)
	}
	c, err := NewChecker(tok, root.Public().(ed25519.PublicKey))
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := c.Check("agent-1", "read_file", fuzzNow); err != nil {
			b.Fatal(err)
		}
	}
}
