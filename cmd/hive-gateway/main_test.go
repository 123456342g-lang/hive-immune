package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestMain lets the test binary double as a fake MCP stdio server so that
// serve can be tested end to end.
func TestMain(m *testing.M) {
	if os.Getenv("HIVE_GATEWAY_FAKE_MCP") == "1" {
		fakeMCPServer(os.Stdin, os.Stdout)
		return
	}
	os.Exit(m.Run())
}

func fakeMCPServer(in io.Reader, out io.Writer) {
	br := bufio.NewReader(in)
	for {
		var msg struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		line, err := br.ReadBytes('\n')
		if err != nil || json.Unmarshal(line, &msg) != nil {
			return
		}
		if msg.Method == "" || msg.ID == nil {
			continue // response or notification: nothing to answer
		}
		result := `{}`
		switch msg.Method {
		case "initialize":
			result = `{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"fake","version":"0"}}`
		case "tools/call":
			var call struct {
				Name string `json:"name"`
			}
			_ = json.Unmarshal(msg.Params, &call)
			result = `{"content":[{"type":"text","text":"` + call.Name + ` ok"}]}`
		}
		resp, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": msg.ID, "result": json.RawMessage(result)})
		if _, err := out.Write(append(resp, '\n')); err != nil {
			return
		}
	}
}

// syncBuffer lets the test read streams that the gateway's pumps, the
// logger and the upstream's stderr are all writing to.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func (s *syncBuffer) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.b.Reset()
}

func TestVersionAndUnknownCommand(t *testing.T) {
	var out syncBuffer
	if err := dispatch([]string{"version"}, nil, &out, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "hive-gateway") {
		t.Fatalf("version = %q", out.String())
	}
	for _, args := range [][]string{{}, {"nope"}} {
		if err := dispatch(args, strings.NewReader(""), &out, &out); err == nil {
			t.Errorf("%v: want error", args)
		}
	}
}

func TestServeRejectsBadUsage(t *testing.T) {
	missingPolicy := filepath.Join(t.TempDir(), "nope.yaml")
	bad := [][]string{
		{},                          // no command at all
		{"serve"},                   // no -agent, no upstream
		{"serve", "-agent", "a1"},   // no upstream command
		{"serve", "--", os.Args[0]}, // no -agent
		{"serve", "-agent", "a1", "-deny-style", "loud", "--", os.Args[0]},
		{"serve", "-agent", "a1", "-env", "novalue", "--", os.Args[0]},
		{"serve", "-agent", "a1", "-policy", missingPolicy, "--", os.Args[0]},
		{"serve", "-agent", "a1", "-admin", "not-an-address", "--", os.Args[0]},
		{"serve", "-agent", "a1", "-approve", "ftp://ops", "--", os.Args[0]},
		{"serve", "-agent", "a1", "-approve", "https://", "--", os.Args[0]},
		{"serve", "-agent", "a1", "-approve-timeout", "0s", "--", os.Args[0]},
		{"serve", "-agent", "a1", "-capability", "x.cap", "--", os.Args[0]},        // key missing
		{"serve", "-agent", "a1", "-capability-key", "root.pub", "--", os.Args[0]}, // token missing
		{"serve", "-agent", "a1", "-capability", "missing.cap", "-capability-key", "missing.pub", "--", os.Args[0]},
		{"serve", "-bogus", "--", os.Args[0]},
	}
	for _, args := range bad {
		var out syncBuffer
		if err := dispatch(args, strings.NewReader(""), &out, &out); err == nil {
			t.Errorf("%v: want error", args)
		}
	}
}

func TestServeHelp(t *testing.T) {
	var out syncBuffer
	if err := dispatch([]string{"serve", "-h"}, strings.NewReader(""), &out, &out); err != nil {
		t.Fatalf("-h must not be an error: %v", err)
	}
	if !strings.Contains(out.String(), "-deny-style") {
		t.Fatalf("help output missing flags: %q", out.String())
	}
}

// record is the subset of an audit line the command tests assert on.
type record struct {
	Agent         string `json:"agent"`
	Session       string `json:"session"`
	Tool          string `json:"tool"`
	Action        string `json:"action"`
	Rule          string `json:"rule"`
	TaintedBefore bool   `json:"tainted_before"`
	TaintedAfter  bool   `json:"tainted_after"`
}

// serveRun is one live `hive-gateway serve` process driven through pipes.
type serveRun struct {
	t         *testing.T
	pw        *io.PipeWriter
	stdout    *syncBuffer
	auditPath string
	done      chan error
	exited    bool
}

func startServe(t *testing.T, extra ...string) *serveRun {
	t.Helper()
	dir := t.TempDir()
	policy := filepath.Join(dir, "tools.yaml")
	if err := os.WriteFile(policy, []byte(`version: 1
defaults: {risk: egress, taint: external}
tools:
  read_file: {risk: read, taint: internal}
  search_web: {risk: read, taint: external}
  send_email: {risk: egress, taint: internal}
`), 0o644); err != nil {
		t.Fatal(err)
	}
	audit := filepath.Join(dir, "audit.jsonl")
	pr, pw := io.Pipe()
	stdout := &syncBuffer{}
	args := append([]string{
		"serve", "-agent", "a1", "-session", "s1",
		"-policy", policy, "-audit", audit,
		"-env", "HIVE_GATEWAY_FAKE_MCP=1",
	}, extra...)
	args = append(args, "--", os.Args[0])

	done := make(chan error, 1)
	go func() { done <- dispatch(args, pr, stdout, io.Discard) }()
	r := &serveRun{t: t, pw: pw, stdout: stdout, auditPath: audit, done: done}
	t.Cleanup(func() {
		_ = pw.Close()
		if r.exited {
			return
		}
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			t.Error("serve did not exit")
		}
	})
	return r
}

func (r *serveRun) send(lines ...string) {
	r.t.Helper()
	for _, l := range lines {
		if _, err := io.WriteString(r.pw, l+"\n"); err != nil {
			r.t.Fatalf("write client line: %v", err)
		}
	}
}

// wait blocks until the client-visible output contains want.
func (r *serveRun) wait(want string) {
	r.t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(r.stdout.String(), want) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	r.t.Fatalf("output never contained %q:\n%s", want, r.stdout.String())
}

// finish closes the client stream, waits for serve to return and returns
// the audit log.
func (r *serveRun) finish() []record {
	r.t.Helper()
	_ = r.pw.Close()
	select {
	case err := <-r.done:
		r.exited = true
		if err != nil {
			r.t.Fatalf("serve: %v\nstderr: %s", err, r.stdout.String())
		}
	case <-time.After(30 * time.Second):
		r.t.Fatal("serve did not finish")
	}
	raw, err := os.ReadFile(r.auditPath)
	if err != nil {
		r.t.Fatalf("read audit: %v", err)
	}
	var recs []record
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var rec record
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			r.t.Fatalf("audit line %q: %v", line, err)
		}
		recs = append(recs, rec)
	}
	return recs
}

// TestServeEndToEnd runs the real binary path: parse flags, spawn the
// upstream, proxy calls through the policy and write the audit log.
func TestServeEndToEnd(t *testing.T) {
	r := startServe(t)
	r.send(
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{}}}`,
	)
	r.wait("read_file ok")

	recs := r.finish()
	if len(recs) != 1 {
		t.Fatalf("audit has %d records, want 1: %+v", len(recs), recs)
	}
	if recs[0].Agent != "a1" || recs[0].Session != "s1" || recs[0].Tool != "read_file" || recs[0].Action != "allow" {
		t.Fatalf("audit = %+v", recs[0])
	}
}

// TestServeApprovalEndToEnd drives the whole P2 story: an external read
// taints the session, egress then blocks on the approval webhook, and only
// the operator's 200 lets it through.
func TestServeApprovalEndToEnd(t *testing.T) {
	var approvals int
	var mu sync.Mutex
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var a struct {
			Tool, Agent, Session, Reason string
		}
		_ = json.NewDecoder(r.Body).Decode(&a)
		mu.Lock()
		approvals++
		mu.Unlock()
		if a.Tool != "send_email" || a.Agent != "a1" || !strings.Contains(a.Reason, "external content") {
			t.Errorf("approval request = %+v", a)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	r := startServe(t, "-approve", ts.URL, "-approve-timeout", "5s")
	r.send(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search_web","arguments":{"q":"x"}}}`)
	r.wait("search_web ok")
	r.send(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"send_email","arguments":{"to":"a@b.c"}}}`)
	r.wait("send_email ok")

	recs := r.finish()
	if len(recs) != 2 {
		t.Fatalf("audit = %+v", recs)
	}
	if recs[0].Tool != "search_web" || !recs[0].TaintedAfter {
		t.Fatalf("first record = %+v", recs[0])
	}
	if recs[1].Tool != "send_email" || recs[1].Action != "approve" {
		t.Fatalf("second record = %+v", recs[1])
	}
	mu.Lock()
	defer mu.Unlock()
	if approvals != 1 {
		t.Fatalf("approvals = %d, want 1", approvals)
	}
}

// TestServeApprovalRefused: a 403 from the approver reaches the model as a
// tool error and nothing is forwarded.
func TestServeApprovalRefused(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer ts.Close()

	r := startServe(t, "-approve", ts.URL)
	r.send(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search_web","arguments":{"q":"x"}}}`)
	r.wait("search_web ok")
	r.send(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"send_email","arguments":{"to":"a@b.c"}}}`)
	r.wait("operator rejected") // model-visible refusal reason

	recs := r.finish()
	last := recs[len(recs)-1]
	if last.Tool != "send_email" || last.Action != "deny" {
		t.Fatalf("last record = %+v", last)
	}
}

// mintToken runs keygen/pubkey/issue through dispatch, the way an operator
// would, and returns the token and public key files.
func mintToken(t *testing.T, agent string, tools ...string) (tokenPath, pubPath string) {
	t.Helper()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "root.key")
	var out, logs syncBuffer
	if err := dispatch([]string{"keygen", "-out", keyPath}, nil, &out, &logs); err != nil {
		t.Fatalf("keygen: %v", err)
	}
	pub := strings.TrimSpace(out.String())
	out.Reset()
	if err := dispatch([]string{"pubkey", "-key", keyPath}, nil, &out, &logs); err != nil {
		t.Fatalf("pubkey: %v", err)
	}
	if strings.TrimSpace(out.String()) != pub {
		t.Fatal("pubkey does not match keygen output")
	}
	pubPath = filepath.Join(dir, "root.pub")
	if err := os.WriteFile(pubPath, []byte(pub+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	tokenPath = filepath.Join(dir, agent+".cap")
	args := []string{"issue", "-key", keyPath, "-agent", agent, "-ttl", "1h"}
	for _, tool := range tools {
		args = append(args, "-tool", tool)
	}
	args = append(args, "-out", tokenPath)
	out.Reset()
	if err := dispatch(args, nil, &out, &logs); err != nil {
		t.Fatalf("issue: %v", err)
	}
	return tokenPath, pubPath
}

func TestKeygenAndIssueUsage(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "root.key")
	var out, logs syncBuffer
	if err := dispatch([]string{"keygen", "-out", keyPath}, nil, &out, &logs); err != nil {
		t.Fatal(err)
	}
	if len(strings.TrimSpace(out.String())) != 64 {
		t.Fatalf("public key = %q", out.String())
	}
	if err := dispatch([]string{"keygen", "-out", keyPath}, nil, &out, &logs); err == nil {
		t.Fatal("keygen must refuse to overwrite an existing key")
	}
	for _, args := range [][]string{
		{"issue"},                                                              // no -agent, no -tool
		{"issue", "-agent", "a1"},                                              // no -tool
		{"issue", "-tool", "t"},                                                // no -agent
		{"issue", "-agent", "a1", "-tool", "t"},                                // missing key file
		{"issue", "-key", keyPath, "-agent", "a1"},                             // no -tool
		{"issue", "-key", keyPath, "-tool", "t"},                               // no -agent
		{"pubkey", "-key", filepath.Join(dir, "nope.key")},                     // missing key
		{"issue", "-key", keyPath, "-agent", "a1", "-tool", "t", "-ttl", "0s"}, // no ttl
	} {
		if err := dispatch(args, nil, &out, &logs); err == nil {
			t.Errorf("%v: want error", args)
		}
	}
}

// TestServeCapabilityEndToEnd: the token, not the policy, decides which
// tools this agent may call - and the refusal reaches the model with a
// capability rule attached.
func TestServeCapabilityEndToEnd(t *testing.T) {
	tokenPath, pubPath := mintToken(t, "a1", "read_file")
	r := startServe(t, "-capability", tokenPath, "-capability-key", pubPath)

	r.send(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search_web","arguments":{"q":"x"}}}`)
	r.wait("capability.tool-out-of-scope")

	r.send(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{}}}`)
	r.wait("read_file ok")

	recs := r.finish()
	if len(recs) != 2 {
		t.Fatalf("audit = %+v", recs)
	}
	if recs[0].Action != "deny" || recs[0].Rule != "capability.tool-out-of-scope" {
		t.Fatalf("first record = %+v", recs[0])
	}
	if recs[1].Action != "allow" || recs[1].Tool != "read_file" {
		t.Fatalf("second record = %+v", recs[1])
	}
}

// TestServeCapabilityRejectsWrongRoot: a token signed by another root key
// must not start the gateway at all.
func TestServeCapabilityRejectsWrongRoot(t *testing.T) {
	tokenPath, _ := mintToken(t, "a1", "read_file")
	_, otherPub := mintToken(t, "a1", "read_file") // different root, same shape
	var out syncBuffer
	args := []string{"serve", "-agent", "a1", "-capability", tokenPath, "-capability-key", otherPub, "--", os.Args[0]}
	err := dispatch(args, strings.NewReader(""), &out, &out)
	if err == nil {
		t.Fatal("a token from another root must be rejected at startup")
	}
	if !strings.Contains(err.Error(), "signature") {
		t.Fatalf("error = %v, want a signature failure", err)
	}
}
