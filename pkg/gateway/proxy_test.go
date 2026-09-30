package gateway

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/123456342g-lang/hive-immune/pkg/quorum"
)

type nopApprover struct{ allow bool }

func (n nopApprover) Approve(context.Context, Approval) (bool, error) { return n.allow, nil }

type errApprover struct{}

func (errApprover) Approve(context.Context, Approval) (bool, error) {
	return false, fmt.Errorf("webhook down")
}

// testServer builds a server with a policy file and an audit log in a temp
// directory, so every test can assert on what was recorded.
func testServer(t *testing.T, mutate func(*Config)) (*server, *bytesBuffer) {
	t.Helper()
	dir := t.TempDir()
	cfg := Config{
		Agent:     "agent-1",
		SessionID: "sess-1",
		DenyStyle: DenyToolResult,
		AuditPath: filepath.Join(dir, "audit.jsonl"),
		Stderr:    io.Discard,
		Now:       func() time.Time { return time.Unix(1_700_000_000, 0) },
	}
	out := &bytesBuffer{}
	cfg.ClientOut = out
	if mutate != nil {
		mutate(&cfg)
	}
	s, err := newServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.audit.Close() })
	return s, out
}

// bytesBuffer is a client-side sink that is safe to read while the pumps
// write (clientMu serialises writers, but tests read after each step).
type bytesBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (w *bytesBuffer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(p)
}

func (w *bytesBuffer) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.String()
}

func (w *bytesBuffer) Reset() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.b.Reset()
}

func (w *bytesBuffer) Len() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Len()
}

func withPolicy(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tools.yaml")
	if err := os.WriteFile(path, []byte(goodPolicy), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func callLine(id int, tool string) string {
	return fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":%q,"arguments":{"x":1}}}`, id, tool)
}

// feed runs lines through the client pump into a fresh upstream buffer.
func feed(t *testing.T, s *server, lines ...string) *stringsBuilder {
	t.Helper()
	var up stringsBuilder
	in := strings.NewReader(strings.Join(lines, "\n") + "\n")
	if err := s.pumpClient(context.Background(), in, &up); err != nil {
		t.Fatalf("pumpClient: %v", err)
	}
	return &up
}

type stringsBuilder struct{ strings.Builder }

// answer pushes one upstream response through the server pump.
func answer(t *testing.T, s *server, out io.Writer, line string) {
	t.Helper()
	if err := s.pumpServer(context.Background(), strings.NewReader(line+"\n"), out); err != nil {
		t.Fatalf("pumpServer: %v", err)
	}
}

func mustTail(t *testing.T, s *server, n int) []Record {
	t.Helper()
	recs, err := s.audit.Tail(n)
	if err != nil {
		t.Fatal(err)
	}
	return recs
}

// TestDenyNeverReachesUpstream: without a policy the gateway is in failure
// mode and nothing is forwarded - the "egress 默认拒绝" contract.
func TestDenyNeverReachesUpstream(t *testing.T) {
	s, out := testServer(t, nil)

	up := feed(t, s, callLine(1, "read_file"))

	if up.Len() != 0 {
		t.Fatalf("upstream received %q, want nothing", up.String())
	}
	if !strings.Contains(out.String(), "hive-gateway denied") {
		t.Fatalf("client got %q", out.String())
	}
	if !strings.Contains(out.String(), `"isError":true`) {
		t.Fatalf("default denial must be a tool error: %q", out.String())
	}
	recs := mustTail(t, s, 10)
	if len(recs) != 1 || recs[0].Action != ActionDeny || recs[0].Rule != "degraded.deny" {
		t.Fatalf("audit = %+v", recs)
	}
	if recs[0].Agent != "agent-1" || recs[0].Session != "sess-1" {
		t.Fatalf("audit identity = %s/%s", recs[0].Agent, recs[0].Session)
	}
}

func TestDenyStyleError(t *testing.T) {
	s, out := testServer(t, func(c *Config) { c.DenyStyle = DenyError })
	feed(t, s, callLine(1, "read_file"))
	if !strings.Contains(out.String(), `"code":-32001`) {
		t.Fatalf("client got %q", out.String())
	}
}

// TestExternalReadTaintsSession: an external-source tool that succeeds
// marks the session; the next outward-facing call then needs a human.
func TestExternalReadTaintsSession(t *testing.T) {
	s, out := testServer(t, func(c *Config) { c.PolicyPath = withPolicy(t) })

	up := feed(t, s, callLine(1, "search_web"))
	if up.Len() == 0 {
		t.Fatal("read of an external tool must be forwarded")
	}
	if s.session.Taint.Tainted() {
		t.Fatal("taint must follow the result, not the request")
	}

	answer(t, s, out, `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"<html>evil</html>"}]}}`)
	if !s.session.Taint.Tainted() {
		t.Fatal("session must be tainted after a successful external read")
	}
	recs := mustTail(t, s, 10)
	if len(recs) != 1 {
		t.Fatalf("want 1 record, got %d", len(recs))
	}
	if recs[0].ResultDigest == "" || recs[0].ArgsDigest == "" {
		t.Fatal("records must carry argument and result digests")
	}
	if recs[0].TaintedBefore || !recs[0].TaintedAfter {
		t.Fatalf("record taint flags = before %v after %v (the read itself starts clean)", recs[0].TaintedBefore, recs[0].TaintedAfter)
	}

	// Now the tainted session tries to send mail: no approver -> denied.
	before := up.Len()
	feed(t, s, callLine(2, "send_email"))
	if up.Len() != before {
		t.Fatal("egress from a tainted session reached the upstream")
	}
	if !strings.Contains(out.String(), "external content") {
		t.Fatalf("client should learn why: %q", out.String())
	}
	recs = mustTail(t, s, 10)
	last := recs[len(recs)-1]
	if last.Rule != "taint.egress" || last.Action != ActionDeny || !last.NeedsApproval {
		t.Fatalf("last record = %+v", last)
	}
}

// TestFailedExternalCallDoesNotTaint: an error result carries no content,
// so it must not put the session into confirmation-everything mode.
func TestFailedExternalCallDoesNotTaint(t *testing.T) {
	s, out := testServer(t, func(c *Config) { c.PolicyPath = withPolicy(t) })
	feed(t, s, callLine(1, "search_web"))
	answer(t, s, out, `{"jsonrpc":"2.0","id":1,"result":{"content":[],"isError":true}}`)
	if s.session.Taint.Tainted() {
		t.Fatal("a failed tool result must not taint the session")
	}
	recs := mustTail(t, s, 1)
	if recs[0].TaintedAfter {
		t.Fatal("record must show the session staying clean")
	}
}

// TestUpstreamErrorRecorded: a JSON-RPC error from the server is audited
// as an upstream failure, not as content that tainted the session.
func TestUpstreamErrorRecorded(t *testing.T) {
	s, out := testServer(t, func(c *Config) { c.PolicyPath = withPolicy(t) })
	feed(t, s, callLine(1, "search_web"))
	answer(t, s, out, `{"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"boom"}}`)
	recs := mustTail(t, s, 1)
	if recs[0].UpstreamError != "boom" || recs[0].ResultDigest != "" {
		t.Fatalf("record = %+v", recs[0])
	}
	if s.session.Taint.Tainted() {
		t.Fatal("error response must not taint")
	}
}

// TestMalformedCallIsDenied: params we cannot parse cannot be classified,
// so they are answered locally instead of forwarded.
func TestMalformedCallIsDenied(t *testing.T) {
	s, out := testServer(t, func(c *Config) { c.PolicyPath = withPolicy(t) })
	up := feed(t, s, `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{}}`)
	if up.Len() != 0 {
		t.Fatal("malformed call must not be forwarded")
	}
	if !strings.Contains(out.String(), "params invalid") {
		t.Fatalf("client got %q", out.String())
	}
	recs := mustTail(t, s, 1)
	if recs[0].Rule != "malformed.call" {
		t.Fatalf("rule = %s", recs[0].Rule)
	}
}

func TestPassThroughMessages(t *testing.T) {
	s, out := testServer(t, func(c *Config) { c.PolicyPath = withPolicy(t) })
	up := feed(t, s,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	if strings.Count(up.String(), "\n") != 3 {
		t.Fatalf("upstream got %q", up.String())
	}
	if out.Len() != 0 {
		t.Fatalf("nothing should come back before the upstream answers: %q", out.String())
	}
	if len(mustTail(t, s, 10)) != 0 {
		t.Fatal("only tools/call is audited")
	}

	answer(t, s, out, `{"jsonrpc":"2.0","id":2,"result":{"tools":[]}}`)
	if !strings.Contains(out.String(), `"id":2`) {
		t.Fatalf("response lost: %q", out.String())
	}
	if len(mustTail(t, s, 10)) != 0 {
		t.Fatal("a response to an untracked request must not produce a record")
	}
}

// taintSession runs one external read plus its successful response.
func taintSession(t *testing.T, s *server, out io.Writer, startID int) {
	t.Helper()
	feed(t, s, callLine(startID, "search_web"))
	answer(t, s, out, fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"result":{"content":[]}}`, startID))
	if !s.session.Taint.Tainted() {
		t.Fatal("setup: session must be tainted")
	}
}

func TestApprovalGrantAndReject(t *testing.T) {
	for _, allow := range []bool{true, false} {
		s, out := testServer(t, func(c *Config) {
			c.PolicyPath = withPolicy(t)
			c.Approver = nopApprover{allow: allow}
		})
		taintSession(t, s, out, 1)

		up := feed(t, s, callLine(2, "send_email"))
		recs := mustTail(t, s, 10)
		last := recs[len(recs)-1]
		if allow {
			if up.Len() == 0 {
				t.Fatal("approved call must reach the upstream")
			}
			// An approved call is recorded when its response arrives,
			// like any forwarded call.
			answer(t, s, out, `{"jsonrpc":"2.0","id":2,"result":{"content":[]}}`)
			recs = mustTail(t, s, 10)
			last = recs[len(recs)-1]
			if last.Action != ActionApprove || !strings.Contains(last.Reason, "approved") {
				t.Fatalf("record = %+v", last)
			}
			if last.Tool != "send_email" {
				t.Fatalf("record tool = %s", last.Tool)
			}
		} else {
			if up.Len() != 0 {
				t.Fatal("rejected call must not reach the upstream")
			}
			if last.Action != ActionDeny || !strings.Contains(last.Reason, "refused") {
				t.Fatalf("record = %+v", last)
			}
			if !strings.Contains(out.String(), "refused") {
				t.Fatalf("client got %q", out.String())
			}
		}
	}
}

func TestApproverErrorDenies(t *testing.T) {
	s, out := testServer(t, func(c *Config) {
		c.PolicyPath = withPolicy(t)
		c.Approver = errApprover{}
	})
	taintSession(t, s, out, 1)

	up := feed(t, s, callLine(2, "send_email"))
	if up.Len() != 0 {
		t.Fatal("a failing approval channel must fail closed")
	}
	recs := mustTail(t, s, 10)
	if !strings.Contains(recs[len(recs)-1].Reason, "webhook down") {
		t.Fatalf("record = %+v", recs[len(recs)-1])
	}
}

// TestEnrichHook drives the swarm level into the decision: isolate freezes
// even reads, observe forces writes through approval.
func TestEnrichHook(t *testing.T) {
	s, out := testServer(t, func(c *Config) {
		c.PolicyPath = withPolicy(t)
		c.Approver = nopApprover{allow: false}
		c.Enrich = func(in *Input) { in.Level = quorum.LevelIsolate }
	})
	up := feed(t, s, callLine(1, "read_file"))
	if up.Len() != 0 {
		t.Fatal("isolate must stop reads too")
	}
	if recs := mustTail(t, s, 1); recs[0].Rule != "level.isolate" {
		t.Fatalf("rule = %s", recs[0].Rule)
	}
	_ = out

	s2, _ := testServer(t, func(c *Config) {
		c.PolicyPath = withPolicy(t)
		c.Approver = nopApprover{allow: false}
		c.Enrich = func(in *Input) { in.Level = quorum.LevelObserve }
	})
	up2 := feed(t, s2, callLine(1, "read_file"))
	if up2.Len() == 0 {
		t.Fatal("observe must not block reads")
	}
	up3 := feed(t, s2, callLine(2, "create_ticket"))
	if up3.Len() != 0 {
		t.Fatal("observe must route writes through approval")
	}
}

func TestSessionCounters(t *testing.T) {
	s, out := testServer(t, func(c *Config) { c.PolicyPath = withPolicy(t) })
	feed(t, s, callLine(1, "read_file"), callLine(2, "search_web"))

	c := s.session.Count()
	if c.Calls != 2 || c.Allowed != 2 || c.Denied != 0 {
		t.Fatalf("counters = %+v", c)
	}
	answer(t, s, out, `{"jsonrpc":"2.0","id":2,"result":{"content":[]}}`)
	if p := s.takePending(`"2"`); p != nil {
		t.Fatal("completed call must leave the pending map")
	}
}

// TestPendingEviction bounds the map when a client pipelines calls whose
// responses never arrive (for example cancelled requests).
func TestPendingEviction(t *testing.T) {
	s, _ := testServer(t, func(c *Config) { c.PolicyPath = withPolicy(t) })
	old := maxPendingCalls
	maxPendingCalls = 2
	defer func() { maxPendingCalls = old }()

	feed(t, s, callLine(1, "read_file"), callLine(2, "read_file"), callLine(3, "read_file"))

	s.mu.Lock()
	n, order := len(s.pending), len(s.order)
	s.mu.Unlock()
	if n != 2 || order != 2 {
		t.Fatalf("pending=%d order=%d, want 2/2", n, order)
	}
}

func TestOnDecisionHook(t *testing.T) {
	var got []Record
	var mu sync.Mutex
	s, _ := testServer(t, func(c *Config) {
		c.OnDecision = func(r Record) { mu.Lock(); got = append(got, r); mu.Unlock() }
	})
	feed(t, s, callLine(1, "read_file"))
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || got[0].Rule != "degraded.deny" {
		t.Fatalf("hook got %+v", got)
	}
}

func TestAuditDisabledIsSafe(t *testing.T) {
	var nilAudit *Audit
	if err := nilAudit.Append(Record{}); err != nil {
		t.Fatal(err)
	}
	if err := nilAudit.Close(); err != nil {
		t.Fatal(err)
	}
	if recs, err := nilAudit.Tail(5); err != nil || recs != nil {
		t.Fatalf("Tail = %v, %v", recs, err)
	}
}

func TestAuditFileRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	a, err := OpenAudit(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Append(Record{Tool: "x", Action: ActionAllow, Rule: "risk.read"}); err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	b, err := OpenAudit(path)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	recs, err := b.Tail(10)
	if err != nil || len(recs) != 1 || recs[0].Tool != "x" {
		t.Fatalf("recs = %+v, err = %v", recs, err)
	}
	if a, err := OpenAudit(""); err != nil || a != nil {
		t.Fatal(err)
	}
}

func TestTailRejectsCorruptLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := os.WriteFile(path, []byte("{\"broken\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	a, err := OpenAudit(path)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if _, err := a.Tail(5); err == nil {
		t.Fatal("corrupt line must be reported")
	}
	if recs, err := a.Tail(0); err != nil || recs != nil {
		t.Fatalf("Tail(0) = %v, %v", recs, err)
	}
}

// BenchmarkHandleCall is the week-1 latency check: the gateway adds one
// policy lookup, one digest and one audit write per call.
func BenchmarkHandleCall(b *testing.B) {
	dir := b.TempDir()
	path := filepath.Join(dir, "tools.yaml")
	if err := os.WriteFile(path, []byte(goodPolicy), 0o644); err != nil {
		b.Fatal(err)
	}
	var out bytesBuffer
	s, err := newServer(Config{
		Agent: "a", PolicyPath: path, DenyStyle: DenyToolResult,
		ClientOut: &out, Stderr: io.Discard, Now: time.Now,
	})
	if err != nil {
		b.Fatal(err)
	}
	var up stringsBuilder
	ctx := context.Background()
	line := callLine(1, "read_file") + "\n"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out.Reset()
		up.Reset()
		if err := s.pumpClient(ctx, strings.NewReader(line), &up); err != nil {
			b.Fatal(err)
		}
	}
}
