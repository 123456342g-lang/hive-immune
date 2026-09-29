package gateway

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestMain lets the test binary double as a fake MCP stdio server, so Run
// can be exercised against a real subprocess.
func TestMain(m *testing.M) {
	if os.Getenv("HIVE_GATEWAY_FAKE_MCP") == "1" {
		fakeMCPServer(os.Stdin, os.Stdout)
		return
	}
	os.Exit(m.Run())
}

// fakeMCPServer speaks just enough MCP for the end-to-end tests.
func fakeMCPServer(in io.Reader, out io.Writer) {
	br := bufio.NewReader(in)
	for {
		m, err := ReadMessage(br)
		if err != nil {
			return
		}
		switch {
		case m.IsRequest() && m.Method == "initialize":
			replyResult(m, `{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"fake","version":"0"}}`, out)
		case m.IsRequest() && m.Method == "tools/list":
			replyResult(m, `{"tools":[{"name":"read_file","description":"read","inputSchema":{"type":"object"}}]}`, out)
		case m.IsRequest() && m.Method == "tools/call":
			p, err := m.ParseCall()
			if err != nil {
				replyError(m, -32602, err.Error(), out)
				continue
			}
			replyResult(m, `{"content":[{"type":"text","text":"`+p.Name+` ok"}]}`, out)
		case m.IsRequest():
			replyResult(m, `{}`, out)
		}
	}
}

func replyResult(req Message, result string, out io.Writer) {
	_ = WriteMessage(out, Message{JSONRPC: "2.0", ID: req.ID, Result: json.RawMessage(result)})
}

func replyError(req Message, code int, msg string, out io.Writer) {
	_ = WriteMessage(out, Message{JSONRPC: "2.0", ID: req.ID, Error: &RPCError{Code: code, Message: msg}})
}

func fakeCommand() []string { return []string{os.Args[0]} }
func fakeEnv() []string     { return []string{"HIVE_GATEWAY_FAKE_MCP=1"} }

// run is one end-to-end gateway session: the test writes client lines, waits
// for output, then closes the pipe and reads the audit log.
type run struct {
	t         *testing.T
	pw        *io.PipeWriter
	out       *bytesBuffer
	auditPath string
	done      chan error
	cancel    context.CancelFunc
	exited    bool
	err       error
}

func startRun(t *testing.T, mutate func(*Config)) *run {
	t.Helper()
	dir := t.TempDir()
	out := &bytesBuffer{}
	pr, pw := io.Pipe()
	cfg := Config{
		Command: fakeCommand(), Env: fakeEnv(),
		AuditPath: filepath.Join(dir, "audit.jsonl"),
		Agent:     "agent-1",
		Stderr:    io.Discard,
		ClientIn:  pr, ClientOut: out,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	if cfg.Command == nil {
		cfg.Command = fakeCommand()
		cfg.Env = fakeEnv()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg) }()
	r := &run{t: t, pw: pw, out: out, auditPath: cfg.AuditPath, done: done, cancel: cancel}
	t.Cleanup(r.close)
	return r
}

// close is the cleanup hook: it must tolerate the gateway having already
// exited in finish().
func (r *run) close() {
	r.cancel()
	if r.exited {
		return
	}
	select {
	case <-r.done:
		r.exited = true
	case <-time.After(10 * time.Second):
		r.t.Error("gateway did not exit")
	}
}

// waitExit waits for Run to return, at most once.
func (r *run) waitExit() error {
	if r.exited {
		return r.err
	}
	select {
	case err := <-r.done:
		r.exited, r.err = true, err
	case <-time.After(20 * time.Second):
		r.t.Fatal("gateway did not exit after the client closed")
	}
	return r.err
}

func (r *run) send(lines ...string) {
	r.t.Helper()
	for _, l := range lines {
		if _, err := io.WriteString(r.pw, l+"\n"); err != nil {
			r.t.Fatalf("write client line: %v", err)
		}
	}
}

// waitOutput blocks until the client-visible output contains want.
func (r *run) waitOutput(want string) {
	r.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if s := r.out.String(); strings.Contains(s, want) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	r.t.Fatalf("client output never contained %q:\n%s", want, r.out.String())
}

// finish closes the client stream, waits for the gateway to exit and
// returns the audit log.
func (r *run) finish() []Record {
	r.t.Helper()
	_ = r.pw.Close()
	if err := r.waitExit(); err != nil {
		r.t.Fatalf("Run: %v", err)
	}
	return readAuditFile(r.t, r.auditPath)
}

func readAuditFile(t *testing.T, path string) []Record {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	var recs []Record
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var rec Record
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("audit line %q: %v", line, err)
		}
		recs = append(recs, rec)
	}
	return recs
}

// TestRunForwardsEverythingWithPolicy: the week-1 acceptance case - point an
// MCP client at the gateway and a clean session behaves exactly as before.
func TestRunForwardsEverythingWithPolicy(t *testing.T) {
	r := startRun(t, func(c *Config) { c.PolicyPath = withPolicy(t) })
	r.send(
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/hosts"}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"send_email","arguments":{"to":"a@b.c"}}}`,
	)
	r.waitOutput(`"id":3`)
	r.waitOutput(`"id":4`)
	r.waitOutput("send_email ok")

	recs := r.finish()
	if len(recs) != 2 {
		t.Fatalf("audit has %d records, want 2: %+v", len(recs), recs)
	}
	for _, rec := range recs {
		if rec.Action != ActionAllow || rec.Session == "" || rec.Agent != "agent-1" {
			t.Fatalf("record = %+v", rec)
		}
		if rec.ArgsDigest == "" || rec.ResultDigest == "" {
			t.Fatalf("record must carry both digests: %+v", rec)
		}
	}
	if !strings.Contains(r.out.String(), "read_file ok") || !strings.Contains(r.out.String(), "send_email ok") {
		t.Fatalf("clean session must be transparent:\n%s", r.out.String())
	}
}

// TestRunFailureModeDenies: no policy file, nothing reaches the upstream
// except the handshake.
func TestRunFailureModeDenies(t *testing.T) {
	r := startRun(t, nil)
	r.send(
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{}}}`,
	)
	r.waitOutput(`"id":2`)
	r.waitOutput("policy unavailable")

	recs := r.finish()
	if len(recs) != 1 || recs[0].Rule != "degraded.deny" || recs[0].Action != ActionDeny {
		t.Fatalf("audit = %+v", recs)
	}
	if strings.Contains(r.out.String(), "read_file ok") {
		t.Fatal("nothing may reach the upstream in failure mode")
	}
}

// TestRunTaintAndDenyEgress is the T1 story end to end: an external read
// taints the session, and the next outward-facing call is answered by the
// gateway without ever reaching the upstream MCP server.
func TestRunTaintAndDenyEgress(t *testing.T) {
	r := startRun(t, func(c *Config) { c.PolicyPath = withPolicy(t) })

	r.send(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search_web","arguments":{"q":"x"}}}`)
	r.waitOutput("search_web ok")

	recs := r.finish()
	if len(recs) != 1 || recs[0].Tool != "search_web" || !recs[0].TaintedAfter {
		t.Fatalf("audit = %+v", recs)
	}

	// Second session: taint it with the same read, then try egress.
	r2 := startRun(t, func(c *Config) { c.PolicyPath = withPolicy(t) })
	r2.send(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search_web","arguments":{"q":"x"}}}`)
	r2.waitOutput("search_web ok")
	// The response has been delivered, so the session is already tainted by
	// the time this line is parsed.
	r2.send(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"send_email","arguments":{"to":"eve@evil.example"}}}`)
	r2.waitOutput("external content")

	recs = r2.finish()
	last := recs[len(recs)-1]
	if last.Action != ActionDeny || last.Rule != "taint.egress" || !last.NeedsApproval {
		t.Fatalf("last record = %+v", last)
	}
	if len(recs) != 2 {
		t.Fatalf("want one forwarded read and one denial, got %+v", recs)
	}
}

func TestRunRejectsBadConfig(t *testing.T) {
	for name, cfg := range map[string]Config{
		"no command": {},
		"bad style":  {Command: []string{"x"}, DenyStyle: "loud"},
		"bad policy": {Command: []string{"x"}, PolicyPath: filepath.Join(t.TempDir(), "missing.yaml")},
	} {
		if err := Run(context.Background(), cfg); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

// TestStartAdminAndHandler covers the control plane: bind failures are
// reported, and the admin endpoints answer without touching the stdio
// data plane.
func TestStartAdminAndHandler(t *testing.T) {
	s, _ := testServer(t, func(c *Config) { c.PolicyPath = withPolicy(t) })

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	occupied := ln.Addr().String()
	s.cfg.AdminAddr = occupied
	if _, err := s.startAdmin(); err == nil {
		t.Fatal("binding an occupied admin address must fail")
	}

	s.cfg.AdminAddr = "127.0.0.1:0"
	stop, err := s.startAdmin()
	if err != nil {
		t.Fatal(err)
	}
	stop()

	ts := httptest.NewServer(s.adminHandler())
	defer ts.Close()

	if body := get(t, ts.URL+"/healthz"); body != "ok\n" {
		t.Fatalf("healthz = %q", body)
	}
	session := get(t, ts.URL+"/v1/session")
	for _, want := range []string{`"agent": "agent-1"`, `"degraded": false`, `"tools": 5`} {
		if !strings.Contains(session, want) {
			t.Fatalf("session missing %s:\n%s", want, session)
		}
	}
	reloaded := get(t, ts.URL+"/v1/audit?n=1")
	if !strings.Contains(reloaded, "[]") {
		t.Fatalf("empty audit = %q", reloaded)
	}
	if body, code := post(t, ts.URL+"/v1/reload"); code != 200 || !strings.Contains(body, `"reloaded": true`) {
		t.Fatalf("reload = %d %q", code, body)
	}
	// Bad n is a client error, not a crash.
	resp, err := http.Get(ts.URL + "/v1/audit?n=0")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("n=0 status = %d", resp.StatusCode)
	}
}

func TestAdminSessionInFailureMode(t *testing.T) {
	s, _ := testServer(t, nil)
	ts := httptest.NewServer(s.adminHandler())
	defer ts.Close()
	if body := get(t, ts.URL+"/v1/session"); !strings.Contains(body, `"degraded": true`) {
		t.Fatalf("session = %s", body)
	}
	if body, code := post(t, ts.URL+"/v1/reload"); code != 200 || !strings.Contains(body, `"reloaded": true`) {
		t.Fatalf("reload in failure mode = %d %q", code, body)
	}
}

func get(t *testing.T, url string) string {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s = %d: %s", url, resp.StatusCode, body)
	}
	return string(body)
}

func post(t *testing.T, url string) (string, int) {
	t.Helper()
	resp, err := http.Post(url, "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return string(body), resp.StatusCode
}
