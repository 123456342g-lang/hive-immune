package gateway

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/hive-immune/hive-immune/pkg/capability"
)

// issueToken builds a checker for one subject and tool set, anchored at the
// fixed clock testServer uses.
func issueToken(t *testing.T, subject string, tools []string, ttl time.Duration, issuedAt time.Time) *capability.Checker {
	t.Helper()
	_, root, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	token, err := capability.Issue(root, capability.IssueRequest{Subject: subject, Tools: tools, TTL: ttl}, issuedAt)
	if err != nil {
		t.Fatal(err)
	}
	c, err := capability.NewChecker(token, root.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

var testClock = time.Unix(1_700_000_000, 0)

// TestCapabilityScopeDenies: a token without a tool is refused before the
// policy engine looks at risk or taint, and the audit rule says so.
func TestCapabilityScopeDenies(t *testing.T) {
	s, _ := testServer(t, func(c *Config) {
		c.PolicyPath = withPolicy(t)
		c.Capability = issueToken(t, "agent-1", []string{"read_file"}, time.Hour, testClock)
	})

	up := feed(t, s, callLine(1, "send_email"))
	if up.Len() != 0 {
		t.Fatal("an out-of-scope tool reached the upstream")
	}
	recs := mustTail(t, s, 10)
	if recs[0].Action != ActionDeny || recs[0].Rule != "capability.tool-out-of-scope" {
		t.Fatalf("record = %+v", recs[0])
	}
	if recs[0].Reason == "" {
		t.Fatal("the model must be told why")
	}

	// The in-scope tool still works, even though it is egress: the token
	// narrows, it does not replace, the policy.
	up = feed(t, s, callLine(2, "read_file"))
	if up.Len() == 0 {
		t.Fatal("an in-scope read must be forwarded")
	}
	if c := s.session.Count(); c.OutOfScope != 1 || c.Denied != 1 || c.Calls != 2 {
		t.Fatalf("counters = %+v", c)
	}
}

func TestCapabilityExpired(t *testing.T) {
	// Issued two hours before the session's clock, valid for one hour, so
	// the token died an hour ago - even though the tool is a plain read.
	s, _ := testServer(t, func(c *Config) {
		c.PolicyPath = withPolicy(t)
		c.Capability = issueToken(t, "agent-1", []string{"read_file"}, time.Hour, testClock.Add(-2*time.Hour))
	})
	up := feed(t, s, callLine(1, "read_file"))
	if up.Len() != 0 {
		t.Fatal("an expired token must stop even reads")
	}
	if recs := mustTail(t, s, 1); recs[0].Rule != "capability.expired" {
		t.Fatalf("rule = %s", recs[0].Rule)
	}
}

func TestCapabilitySubjectMismatch(t *testing.T) {
	s, _ := testServer(t, func(c *Config) {
		c.PolicyPath = withPolicy(t)
		c.Capability = issueToken(t, "someone-else", []string{"read_file"}, time.Hour, testClock)
	})
	feed(t, s, callLine(1, "read_file"))
	if recs := mustTail(t, s, 1); recs[0].Rule != "capability.subject" {
		t.Fatalf("rule = %s", recs[0].Rule)
	}
}

// TestCapabilityIsNotEnrichable: the swarm hook runs first, the capability
// gate runs last, so a compromised or buggy Enrich cannot switch the check
// off.
func TestCapabilityIsNotEnrichable(t *testing.T) {
	s, _ := testServer(t, func(c *Config) {
		c.PolicyPath = withPolicy(t)
		c.Capability = issueToken(t, "agent-1", []string{"read_file"}, time.Hour, testClock)
		c.Enrich = func(in *Input) { in.CapabilityDenied = "" }
	})
	up := feed(t, s, callLine(1, "send_email"))
	if up.Len() != 0 {
		t.Fatal("Enrich must not be able to clear the capability denial")
	}
	if recs := mustTail(t, s, 1); recs[0].Rule != "capability.tool-out-of-scope" {
		t.Fatalf("rule = %s", recs[0].Rule)
	}
}

// TestNoCapabilityIsNotRequired: without a token configured nothing changes.
func TestNoCapabilityIsNotRequired(t *testing.T) {
	s, _ := testServer(t, func(c *Config) { c.PolicyPath = withPolicy(t) })
	up := feed(t, s, callLine(1, "read_file"))
	if up.Len() == 0 {
		t.Fatal("no token configured must mean no token required")
	}
}
