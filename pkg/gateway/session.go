package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"
	"time"

	"github.com/hive-immune/hive-immune/pkg/taint"
)

// Session is the state one MCP connection carries: its identity, whether
// untrusted content has entered it, and the counters the swarm reputation
// feed is built from. The stdio transport gives us one process per
// connection, so the session id can also be the process start time; it is
// only ever used for correlation, never for trust.
type Session struct {
	ID    string
	Agent string
	Taint *taint.Session

	mu sync.Mutex
	c  SessionCounters
}

// SessionCounters are cumulative for the life of the session.
type SessionCounters struct {
	Calls      int `json:"calls"`
	Allowed    int `json:"allowed"`
	Denied     int `json:"denied"`
	Approvals  int `json:"approvals"`
	Approved   int `json:"approved"`
	Rejected   int `json:"rejected"`
	OutOfScope int `json:"out_of_scope"`
}

// NewSession builds a session for one connection.
func NewSession(id, agent string) *Session {
	if id == "" {
		id = time.Now().UTC().Format("20060102T150405.000000000")
	}
	return &Session{ID: id, Agent: agent, Taint: taint.New()}
}

// Count returns a snapshot of the counters.
func (s *Session) Count() SessionCounters {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.c
}

func (s *Session) count(f func(*SessionCounters)) {
	s.mu.Lock()
	f(&s.c)
	s.mu.Unlock()
}

// SessionState is what the admin endpoint serves about the session.
type SessionState struct {
	ID       string          `json:"id"`
	Agent    string          `json:"agent"`
	Taint    taint.State     `json:"taint"`
	Counters SessionCounters `json:"counters"`
	Policy   *PolicyState    `json:"policy"`
}

// PolicyState describes the loaded policy for the admin endpoint.
type PolicyState struct {
	Path     string `json:"path,omitempty"`
	Tools    int    `json:"tools"`
	Degraded bool   `json:"degraded"`
	Error    string `json:"error,omitempty"`
}

// Digest returns the hex sha256 of b. Parameter and result digests in the
// audit log and the credential chain are all produced here so that two
// deployments hash identically.
func Digest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// DigestArgs hashes a tools/call argument object. Missing arguments hash
// as an empty object so that "no arguments" is a stable value.
func DigestArgs(raw json.RawMessage) string {
	if len(raw) == 0 {
		return Digest([]byte("{}"))
	}
	return Digest(raw)
}
