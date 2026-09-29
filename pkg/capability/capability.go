// Package capability issues and verifies the biscuit tokens that say what
// one agent session is allowed to do.
//
// A token is an unforgeable, attenuable capability: the operator issues it
// with a root key and it names a subject (the agent), the tools it may call
// and an expiry. The gateway verifies the signature chain once at startup
// and then, for every tools/call, asks the token's datalog whether this
// subject may call this tool now. Nothing else in the system can widen the
// scope: only the holder of the root key can issue, and anyone holding a
// token can narrow it further with a biscuit attenuation block.
//
// Denial reasons are stable strings ("expired", "tool-out-of-scope",
// "subject") because the gateway turns them into audit rules. Key files and
// their encoding are deliberately someone else's problem: the caller passes
// ed25519 keys, and cmd/hive-gateway stores them with pkg/keyfile.
package capability

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"regexp"
	"time"

	"github.com/biscuit-auth/biscuit-go/v2"
	"github.com/biscuit-auth/biscuit-go/v2/parser"
)

// The per-call denial reasons. They become audit rules
// ("capability.tool-out-of-scope") and must stay stable across releases.
const (
	ReasonSubject      = "subject"
	ReasonExpired      = "expired"
	ReasonOutOfScope   = "tool-out-of-scope"
	ReasonMalformed    = "malformed"
	ReasonUnauthorized = "unauthorized"
)

// nameRe is the character set allowed in subjects and tool names. Datalog
// strings are quoted, but keeping the alphabet small means a tool name can
// never be mistaken for syntax.
var nameRe = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,128}$`)

// Denied is a capability check that did not pass. Reason is the stable
// short form; Error() is the human sentence that goes to the model.
type Denied struct {
	Reason string
	Detail string
}

func (d *Denied) Error() string {
	return "capability token does not permit this call: " + d.Detail
}

func denied(reason, detail string) error { return &Denied{Reason: reason, Detail: detail} }

// IssueRequest describes one token to issue.
type IssueRequest struct {
	// Subject is the agent id the token belongs to; the gateway compares it
	// against its own -agent flag.
	Subject string
	// Tools are the tool names the subject may call.
	Tools []string
	// TTL is how long the token stays valid from now. It must be positive:
	// an immortal capability is a liability.
	TTL time.Duration
}

// Issue mints a token for one subject, signed by root.
func Issue(root ed25519.PrivateKey, req IssueRequest, now time.Time) (string, error) {
	if len(root) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("capability: root key must be %d bytes", ed25519.PrivateKeySize)
	}
	if !nameRe.MatchString(req.Subject) {
		return "", fmt.Errorf("capability: subject %q must match %s", req.Subject, nameRe)
	}
	if len(req.Tools) == 0 {
		return "", fmt.Errorf("capability: at least one tool must be named")
	}
	if req.TTL <= 0 {
		return "", fmt.Errorf("capability: ttl must be positive, got %s", req.TTL)
	}
	b := biscuit.NewBuilder(root)
	if err := addFact(b.AddAuthorityFact, fmt.Sprintf("subject(%q)", req.Subject)); err != nil {
		return "", err
	}
	seen := make(map[string]bool, len(req.Tools))
	for _, tool := range req.Tools {
		if !nameRe.MatchString(tool) {
			return "", fmt.Errorf("capability: tool %q must match %s", tool, nameRe)
		}
		if seen[tool] {
			continue
		}
		seen[tool] = true
		if err := addFact(b.AddAuthorityFact, fmt.Sprintf("tool(%q)", tool)); err != nil {
			return "", err
		}
	}
	notAfter := now.Add(req.TTL).UTC().Truncate(time.Second)
	if err := addFact(b.AddAuthorityFact, fmt.Sprintf("not_after(%s)", notAfter.Format(time.RFC3339))); err != nil {
		return "", err
	}
	tok, err := b.Build()
	if err != nil {
		return "", fmt.Errorf("capability: building token: %w", err)
	}
	raw, err := tok.Serialize()
	if err != nil {
		return "", fmt.Errorf("capability: serializing token: %w", err)
	}
	// The biscuit spec mandates URL-safe base64 for textual tokens.
	return base64.URLEncoding.EncodeToString(raw), nil
}

// addFunc is the signature of the builder's fact hooks.
type addFunc func(biscuit.Fact) error

func addFact(add addFunc, code string) error {
	f, err := parser.FromStringFact(code)
	if err != nil {
		return fmt.Errorf("capability: internal fact %q: %w", code, err)
	}
	if err := add(f); err != nil {
		return fmt.Errorf("capability: adding fact %q: %w", code, err)
	}
	return nil
}

// Checker verifies one token against one root key. The signature chain is
// checked once, when the checker is built; per call only the datalog
// checks run, so a long-lived session can still expire mid-flight.
type Checker struct {
	tok  *biscuit.Biscuit
	root ed25519.PublicKey
}

// NewChecker decodes a token and proves it was signed by root. Anything a
// forger could have written fails here, at startup, not on the first call.
func NewChecker(token string, root ed25519.PublicKey) (*Checker, error) {
	if len(root) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("capability: root public key must be %d bytes", ed25519.PublicKeySize)
	}
	raw, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return nil, fmt.Errorf("capability: token is not url-safe base64: %w", err)
	}
	tok, err := biscuit.Unmarshal(raw)
	if err != nil {
		return nil, fmt.Errorf("capability: token: %w", err)
	}
	if _, err := tok.Authorizer(root); err != nil {
		return nil, fmt.Errorf("capability: token signature: %w", err)
	}
	return &Checker{tok: tok, root: root}, nil
}

// Check answers "may subject call tool at now?". A nil error means yes.
// The three reasons are reported separately so the audit log says which
// gate refused.
func (c *Checker) Check(subject, tool string, now time.Time) error {
	if !nameRe.MatchString(subject) || !nameRe.MatchString(tool) {
		return denied(ReasonMalformed, "subject or tool name is outside the allowed alphabet")
	}
	// Identity: the token must belong to the agent in front of us.
	if err := c.authorize(fmt.Sprintf(
		"expect_subject(%q); check if subject($s), expect_subject($s);", subject)); err != nil {
		return denied(ReasonSubject, "token belongs to a different agent")
	}
	// Expiry: checked on every call, so a session cannot outlive it.
	if err := c.authorize(fmt.Sprintf(
		"time(%s); check if not_after($e), time($t), $t <= $e;",
		now.UTC().Truncate(time.Second).Format(time.RFC3339))); err != nil {
		return denied(ReasonExpired, "token has expired")
	}
	// Scope: the tool named in this call must appear in the token.
	if err := c.authorize(fmt.Sprintf(
		"call_tool(%q); check if call_tool($t), tool($t);", tool)); err != nil {
		return denied(ReasonOutOfScope, "tool is not in the token's scope")
	}
	return nil
}

// authorize runs one concern against a fresh authorizer. Each concern gets
// its own pass so the caller learns which gate refused; the token's own
// signature was already proven in NewChecker.
//
// The authorizer contents carry the request facts plus the check that
// must hold, and an unconditional allow policy: biscuit evaluates policies
// only after every check has passed, so "allow if true" here means "the
// checks are the decision".
func (c *Checker) authorize(contents string) error {
	auth, err := c.tok.Authorizer(c.root)
	if err != nil {
		return err
	}
	parsed, err := parser.FromStringAuthorizer(contents)
	if err != nil {
		return fmt.Errorf("capability: internal authorizer %q: %w", contents, err)
	}
	auth.AddAuthorizer(parsed)
	allow, err := parser.FromStringPolicy("allow if true")
	if err != nil {
		return fmt.Errorf("capability: internal policy: %w", err)
	}
	auth.AddPolicy(allow)
	return auth.Authorize()
}
