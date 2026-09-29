package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
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

// syncBuffer lets the test read a stream that the gateway's pumps, the
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

// waitContains polls until want shows up in the stream.
func waitContains(t *testing.T, s *syncBuffer, want string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(s.String(), want) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("output never contained %q:\n%s", want, s.String())
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

// TestServeEndToEnd runs the real binary path: parse flags, spawn the
// upstream, proxy a call through the policy and write the audit log.
func TestServeEndToEnd(t *testing.T) {
	dir := t.TempDir()
	policy := filepath.Join(dir, "tools.yaml")
	if err := os.WriteFile(policy, []byte(`version: 1
defaults: {risk: egress, taint: external}
tools:
  read_file: {risk: read, taint: internal}
`), 0o644); err != nil {
		t.Fatal(err)
	}
	audit := filepath.Join(dir, "audit.jsonl")
	pr, pw := io.Pipe()
	var stdout, stderr syncBuffer

	errc := make(chan error, 1)
	go func() {
		errc <- dispatch([]string{
			"serve", "-agent", "a1", "-session", "s1",
			"-policy", policy, "-audit", audit,
			"-env", "HIVE_GATEWAY_FAKE_MCP=1",
			"--", os.Args[0],
		}, pr, &stdout, &stderr)
	}()
	for _, line := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{}}}`,
	} {
		if _, err := io.WriteString(pw, line+"\n"); err != nil {
			t.Fatalf("write client line: %v", err)
		}
	}
	// Wait for the tool response before half-closing: a real MCP client
	// only goes quiet once the answer is back.
	waitContains(t, &stdout, "read_file ok")
	_ = pw.Close()

	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("serve: %v\nstderr: %s", err, stderr.String())
		}
	case <-time.After(30 * time.Second):
		t.Fatal("serve did not finish")
	}
	raw, err := os.ReadFile(audit)
	if err != nil {
		t.Fatal(err)
	}
	var rec struct {
		Agent, Session, Tool, Action string
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 1 {
		t.Fatalf("audit has %d records, want 1: %s", len(lines), raw)
	}
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatalf("audit line %q: %v", lines[0], err)
	}
	if rec.Agent != "a1" || rec.Session != "s1" || rec.Tool != "read_file" || rec.Action != "allow" {
		t.Fatalf("audit = %+v", rec)
	}
}
