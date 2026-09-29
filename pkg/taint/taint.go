// Package taint tracks whether untrusted, externally sourced content has
// entered an agent session.
//
// Indirect prompt injection (T1) works by getting hostile instructions into
// the context window through data the agent reads: web pages, email bodies,
// third-party API responses. Once that has happened, no amount of scanning
// tells the gateway which later instruction came from the user and which
// came from the attacker, so the session itself is treated as tainted.
//
// The rule is structural rather than heuristic: a session that has read
// external content may no longer perform state-changing or outward-facing
// actions without a human in the loop. That converts "detect the injection"
// (unsolved) into "gate the effect" (mechanical).
package taint

import (
	"fmt"
	"sync"
	"time"
)

// Source says where a tool's output comes from. Anything the organisation
// does not fully control - the web, a customer's mailbox, a third-party API -
// is external.
type Source string

// Classification of a tool's output.
const (
	// SourceInternal means the output originates inside the trust boundary
	// (own file system, own database, own internal services).
	SourceInternal Source = "internal"
	// SourceExternal means the output can contain instructions written by
	// someone outside the trust boundary.
	SourceExternal Source = "external"
)

// ParseSource validates a source name from configuration.
func ParseSource(s string) (Source, error) {
	switch Source(s) {
	case SourceInternal, SourceExternal:
		return Source(s), nil
	}
	return "", fmt.Errorf("taint: unknown source %q (want %q or %q)", s, SourceInternal, SourceExternal)
}

// Session is the taint state of one agent session. It is safe for
// concurrent use: MCP clients may have several tool calls in flight.
type Session struct {
	mu      sync.Mutex
	tainted bool
	// taintedAt is when the session was first tainted (zero if never).
	taintedAt time.Time
	// sources records which external tools tainted the session, in order.
	sources []string
	// marks counts taint events since the last reset, resets counts resets.
	marks, resets int
}

// New returns a clean session.
func New() *Session { return &Session{} }

// Tainted reports whether external content has entered the session.
func (s *Session) Tainted() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tainted
}

// Mark records that output from the tool named from has entered the
// session. It is a no-op (returning false) if the session is already
// tainted. The returned sources list is a copy and never nil.
func (s *Session) Mark(from string, at time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tainted {
		return false
	}
	s.tainted = true
	s.taintedAt = at
	s.sources = []string{from}
	s.marks++
	return true
}

// Reset returns the session to clean. It reports whether the session was
// tainted before, so the caller can record a reset in the audit log.
func (s *Session) Reset() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.tainted {
		return false
	}
	s.tainted = false
	s.taintedAt = time.Time{}
	s.sources = nil
	s.resets++
	return true
}

// State is a snapshot of the session's taint state, as served by the
// gateway's admin endpoint.
type State struct {
	Tainted   bool      `json:"tainted"`
	TaintedAt time.Time `json:"tainted_at,omitempty"`
	Sources   []string  `json:"sources,omitempty"`
	Marks     int       `json:"marks"`
	Resets    int       `json:"resets"`
}

// Snapshot returns the current state.
func (s *Session) Snapshot() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return State{
		Tainted:   s.tainted,
		TaintedAt: s.taintedAt,
		Sources:   append([]string(nil), s.sources...),
		Marks:     s.marks,
		Resets:    s.resets,
	}
}
