package gateway

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// Record is one line of the audit log: what was asked, what the gateway
// decided, and (for forwarded calls) a digest of what came back. Operator
// interventions that are not calls (a taint reset) appear as Action
// "reset" with an empty tool.
//
// Digests are hashes, never content: the log has to be safe to ship to a
// SIEM and to share across organisations, and it must never become a copy
// of the conversation.
type Record struct {
	Time          time.Time `json:"time"`
	Session       string    `json:"session"`
	Agent         string    `json:"agent"`
	CallID        string    `json:"call_id,omitempty"`
	Tool          string    `json:"tool"`
	Risk          Risk      `json:"risk"`
	NeedsApproval bool      `json:"needs_approval,omitempty"`
	TaintedBefore bool      `json:"tainted_before"`
	TaintedAfter  bool      `json:"tainted_after"`
	Action        Action    `json:"action"`
	Rule          string    `json:"rule"`
	Reason        string    `json:"reason"`
	ArgsDigest    string    `json:"args_digest,omitempty"`
	ResultDigest  string    `json:"result_digest,omitempty"`
	UpstreamError string    `json:"upstream_error,omitempty"`
	DurationMS    int64     `json:"duration_ms"`
}

// Audit is an append-only JSONL sink. A nil *Audit discards records, which
// is what a caller that did not configure a log gets.
type Audit struct {
	mu  sync.Mutex
	enc *json.Encoder
	f   *os.File
}

// OpenAudit opens path for appending. An empty path returns nil (discard).
func OpenAudit(path string) (*Audit, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o640)
	if err != nil {
		return nil, fmt.Errorf("gateway: opening audit log: %w", err)
	}
	return &Audit{enc: json.NewEncoder(f), f: f}, nil
}

// Append writes one record.
func (a *Audit) Append(r Record) error {
	if a == nil {
		return nil
	}
	if r.Time.IsZero() {
		r.Time = time.Now().UTC()
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.enc.Encode(r); err != nil {
		return fmt.Errorf("gateway: writing audit record: %w", err)
	}
	return nil
}

// Close flushes and closes the file.
func (a *Audit) Close() error {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.f == nil {
		return nil
	}
	err := a.f.Close()
	a.f, a.enc = nil, nil
	return err
}

// Tail returns up to n most recent records, oldest first. It is used by
// the admin endpoint and by the offline demo renderer.
func (a *Audit) Tail(n int) ([]Record, error) {
	if a == nil || a.f == nil || n <= 0 {
		return nil, nil
	}
	a.mu.Lock()
	path := a.f.Name()
	a.mu.Unlock()

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("gateway: reading audit log: %w", err)
	}
	lines := splitLines(raw)
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	out := make([]Record, 0, len(lines))
	for _, line := range lines {
		var r Record
		if err := json.Unmarshal(line, &r); err != nil {
			return nil, fmt.Errorf("gateway: corrupt audit record: %w", err)
		}
		out = append(out, r)
	}
	return out, nil
}

func splitLines(b []byte) [][]byte {
	var out [][]byte
	start := 0
	for i, c := range b {
		if c == '\n' {
			if i > start {
				out = append(out, b[start:i])
			}
			start = i + 1
		}
	}
	if start < len(b) {
		out = append(out, b[start:])
	}
	return out
}
