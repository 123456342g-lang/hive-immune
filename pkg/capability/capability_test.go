package capability

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

func newRoot(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func TestIssueAndCheckRoundTrip(t *testing.T) {
	root := newRoot(t)
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	token, err := Issue(root, IssueRequest{
		Subject: "agent-1", Tools: []string{"read_file", "send_email"}, TTL: time.Hour,
	}, now)
	if err != nil {
		t.Fatal(err)
	}

	c, err := NewChecker(token, root.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Check("agent-1", "send_email", now.Add(time.Minute)); err != nil {
		t.Fatalf("in-scope call refused: %v", err)
	}
	if err := c.Check("agent-1", "read_file", now.Add(59*time.Minute)); err != nil {
		t.Fatalf("in-scope call refused: %v", err)
	}

	// Out of scope.
	assertDenied(t, c, "agent-1", "shell_exec", now, ReasonOutOfScope)
	// Wrong subject.
	assertDenied(t, c, "agent-2", "send_email", now, ReasonSubject)
	// Expiry: still valid at exactly +1h, expired after.
	if err := c.Check("agent-1", "send_email", now.Add(time.Hour)); err != nil {
		t.Fatalf("call exactly at expiry must still pass: %v", err)
	}
	assertDenied(t, c, "agent-1", "send_email", now.Add(time.Hour+time.Second), ReasonExpired)
	// A session that runs past the token's lifetime is cut off mid-flight.
	assertDenied(t, c, "agent-1", "read_file", now.Add(2*time.Hour), ReasonExpired)
}

func assertDenied(t *testing.T, c *Checker, subject, tool string, now time.Time, want string) {
	t.Helper()
	err := c.Check(subject, tool, now)
	if err == nil {
		t.Fatalf("%s calling %s: want denial", subject, tool)
	}
	d, ok := err.(*Denied)
	if !ok {
		t.Fatalf("%s calling %s: error %T is not a Denied: %v", subject, tool, err, err)
	}
	if d.Reason != want {
		t.Fatalf("%s calling %s: reason %q, want %q (%v)", subject, tool, d.Reason, want, err)
	}
	if d.Error() == "" || d.Detail == "" {
		t.Fatalf("denial must carry a human sentence: %+v", d)
	}
}

func TestIssueRejectsBadRequests(t *testing.T) {
	root := newRoot(t)
	now := time.Now()
	for name, req := range map[string]IssueRequest{
		"no subject":   {Subject: "", Tools: []string{"a"}, TTL: time.Hour},
		"bad subject":  {Subject: `agent" drop`, Tools: []string{"a"}, TTL: time.Hour},
		"no tools":     {Subject: "a", Tools: nil, TTL: time.Hour},
		"bad tool":     {Subject: "a", Tools: []string{"tool with space"}, TTL: time.Hour},
		"no ttl":       {Subject: "a", Tools: []string{"t"}, TTL: 0},
		"negative ttl": {Subject: "a", Tools: []string{"t"}, TTL: -time.Second},
	} {
		if _, err := Issue(root, req, now); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
	// Repeating a tool is not an error, just redundant.
	if _, err := Issue(root, IssueRequest{Subject: "a", Tools: []string{"t", "t"}, TTL: time.Hour}, now); err != nil {
		t.Errorf("duplicate tool: %v", err)
	}
	if _, err := Issue(make([]byte, 4), IssueRequest{Subject: "a", Tools: []string{"t"}, TTL: time.Hour}, now); err == nil {
		t.Error("a short root key must be rejected")
	}
}

func TestNewCheckerRejectsForgery(t *testing.T) {
	root := newRoot(t)
	other := newRoot(t)
	now := time.Now()
	token, err := Issue(root, IssueRequest{Subject: "a", Tools: []string{"t"}, TTL: time.Hour}, now)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := NewChecker(token, other.Public().(ed25519.PublicKey)); err == nil {
		t.Error("a token signed by another root must be rejected")
	}
	if _, err := NewChecker(token+"AAAA", root.Public().(ed25519.PublicKey)); err == nil {
		t.Error("a tampered token must be rejected")
	}
	if _, err := NewChecker("not base64 at all!", root.Public().(ed25519.PublicKey)); err == nil {
		t.Error("garbage must be rejected")
	}
	if _, err := NewChecker(token, make([]byte, 4)); err == nil {
		t.Error("a short root public key must be rejected")
	}
}

func TestCheckRejectsBadNames(t *testing.T) {
	root := newRoot(t)
	token, err := Issue(root, IssueRequest{Subject: "agent-1", Tools: []string{"t"}, TTL: time.Hour}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewChecker(token, root.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	err = c.Check("agent\" 1", "t", time.Now())
	if err == nil || !strings.Contains(err.Error(), "alphabet") {
		t.Fatalf("err = %v", err)
	}
	if got := err.(*Denied).Reason; got != ReasonMalformed {
		t.Fatalf("reason = %q", got)
	}
}
