package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/123456342g-lang/hive-immune/pkg/cluster"
	"github.com/123456342g-lang/hive-immune/pkg/node"
	"github.com/123456342g-lang/hive-immune/pkg/quorum"
)

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *syncBuffer) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

// initTestCluster creates keys and a peers.json whose addresses point at
// free loopback ports, returning the directory and each node's address.
func initTestCluster(t *testing.T, ids ...string) (string, map[string]string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "cluster")
	var out bytes.Buffer
	if err := dispatch([]string{"init-cluster", "-nodes", strings.Join(ids, ","), "-zone", "prod", "-out", dir}, nil, &out, &out); err != nil {
		t.Fatal(err)
	}
	c, err := cluster.Load(filepath.Join(dir, "peers.json"))
	if err != nil {
		t.Fatal(err)
	}
	addrs := map[string]string{}
	for i, m := range c.Members {
		addrs[string(m.ID)] = freeAddr(t)
		c.Members[i].Addr = "http://" + addrs[string(m.ID)]
	}
	raw, _ := json.Marshal(c)
	if err := os.WriteFile(filepath.Join(dir, "peers.json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return dir, addrs
}

type runningNode struct {
	stdout, stderr *syncBuffer
	gossip, sensor string
	done           chan error
}

func startServe(t *testing.T, ctx context.Context, args ...string) *runningNode {
	t.Helper()
	rn := &runningNode{stdout: &syncBuffer{}, stderr: &syncBuffer{}, done: make(chan error, 1)}
	ready := make(chan struct{})
	go func() {
		rn.done <- serveContext(ctx, args, rn.stdout, rn.stderr, func(g, s string) {
			rn.gossip, rn.sensor = g, s
			close(ready)
		})
	}()
	select {
	case <-ready:
	case err := <-rn.done:
		t.Fatalf("serve exited early: %v\n%s", err, rn.stderr.String())
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not become ready")
	}
	return rn
}

func freshFalcoAlert() string {
	return `{"hostname":"web","priority":"Critical","rule":"Terminal shell in container","source":"syscall","time":"` +
		time.Now().UTC().Format(time.RFC3339Nano) + `","output_fields":{}}`
}

func statusOf(t *testing.T, addr string) node.StatusReport {
	t.Helper()
	resp, err := http.Get("http://" + addr + "/v1/status")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var rep node.StatusReport
	if err := json.NewDecoder(resp.Body).Decode(&rep); err != nil {
		t.Fatal(err)
	}
	return rep
}

func levelIn(rep node.StatusReport, id string) quorum.Level {
	for _, m := range rep.Members {
		if string(m.Node) == id {
			return m.Level
		}
	}
	return -1
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestServeEndToEnd runs two real nodes: a Falco alert posted to node-1's
// sensor endpoint must isolate node-1 on both nodes, put node-2 on zone
// alert, and be reported on stdout and to the webhook.
func TestServeEndToEnd(t *testing.T) {
	dir, addrs := initTestCluster(t, "node-1", "node-2")
	var hooks []node.Change
	var hookMu sync.Mutex
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var c node.Change
		_ = json.NewDecoder(r.Body).Decode(&c)
		hookMu.Lock()
		hooks = append(hooks, c)
		hookMu.Unlock()
	}))
	defer hook.Close()
	ctx, cancel := context.WithCancel(context.Background())

	n1 := startServe(t, ctx, "-node", "node-1", "-key", filepath.Join(dir, "node-1.key"), "-cluster", filepath.Join(dir, "peers.json"),
		"-listen", addrs["node-1"], "-sensor-listen", "127.0.0.1:0", "-interval", "20ms", "-webhook", hook.URL)
	n2 := startServe(t, ctx, "-node", "node-2", "-key", filepath.Join(dir, "node-2.key"), "-cluster", filepath.Join(dir, "peers.json"),
		"-listen", addrs["node-2"], "-interval", "20ms")

	resp, err := http.Post("http://"+n1.sensor+node.FalcoPath, "application/json", strings.NewReader(freshFalcoAlert()))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), `"emitted":1`) {
		t.Fatalf("sensor endpoint: %s", body)
	}

	waitFor(t, "node-2 to isolate node-1", func() bool { return levelIn(statusOf(t, n2.gossip), "node-1") == quorum.LevelIsolate })
	if lvl := levelIn(statusOf(t, n2.gossip), "node-2"); lvl != quorum.LevelObserve {
		t.Errorf("node-2 must be on zone alert, got %v", lvl)
	}
	waitFor(t, "decision on node-2 stdout", func() bool {
		return strings.Contains(n2.stdout.String(), `"node":"node-1","from":"none","to":"isolate"`)
	})
	waitFor(t, "webhook delivery", func() bool {
		hookMu.Lock()
		defer hookMu.Unlock()
		return len(hooks) >= 2
	})

	cancel()
	for _, rn := range []*runningNode{n1, n2} {
		select {
		case err := <-rn.done:
			if err != nil {
				t.Errorf("serve returned %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("serve did not shut down")
		}
	}
	if !strings.Contains(n1.stderr.String(), "hive-agent stopped") {
		t.Errorf("missing shutdown log:\n%s", n1.stderr.String())
	}
}

func TestRunPushesToNode(t *testing.T) {
	dir, addrs := initTestCluster(t, "node-1")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	n1 := startServe(t, ctx, "-node", "node-1", "-key", filepath.Join(dir, "node-1.key"), "-cluster", filepath.Join(dir, "peers.json"),
		"-listen", addrs["node-1"], "-interval", "20ms")
	var stdout, stderr bytes.Buffer

	err := dispatch([]string{"run", "-node", "node-1", "-key", filepath.Join(dir, "node-1.key"), "-source", "falco",
		"-push", "http://" + n1.gossip}, strings.NewReader(freshFalcoAlert()+"\n"), &stdout, &stderr)

	if err != nil {
		t.Fatal(err)
	}
	if stdout.Len() != 0 {
		t.Errorf("with -push nothing goes to stdout: %s", stdout.String())
	}
	if rep := statusOf(t, n1.gossip); rep.Stats.Accepted != 1 {
		t.Fatalf("pushed signal not accepted: %+v", rep.Stats)
	}
}

func TestRunPushReportsButSurvivesFailures(t *testing.T) {
	keyPath, _ := newKey(t)
	rejecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "no", http.StatusForbidden)
	}))
	defer rejecting.Close()
	for _, target := range []string{rejecting.URL, "http://" + freeAddr(t)} {
		var stdout, stderr bytes.Buffer
		err := dispatch([]string{"run", "-node", "n", "-key", keyPath, "-source", "falco", "-push", target},
			strings.NewReader(freshFalcoAlert()+"\n"), &stdout, &stderr)
		if err != nil || !strings.Contains(stderr.String(), "push") {
			t.Errorf("%s: err=%v stderr=%s", target, err, stderr.String())
		}
	}
}

func TestInitClusterSafety(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "c")
	var out bytes.Buffer
	args := []string{"init-cluster", "-nodes", "a,b", "-out", dir}
	if err := dispatch(args, nil, &out, &out); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(dir, "peers.json"))

	if err := dispatch(args, nil, &out, &out); err == nil {
		t.Error("re-initialising must fail")
	}
	if err := dispatch(append(args, "-if-missing"), nil, &out, &out); err != nil {
		t.Errorf("-if-missing must succeed: %v", err)
	}
	after, _ := os.ReadFile(filepath.Join(dir, "peers.json"))
	if !bytes.Equal(before, after) {
		t.Error("existing cluster must be untouched")
	}
	for _, bad := range []string{"../evil", `a\b`, "..", ""} {
		d := filepath.Join(t.TempDir(), "x")
		if err := dispatch([]string{"init-cluster", "-nodes", bad, "-out", d}, nil, &out, &out); err == nil {
			t.Errorf("node id %q must be refused", bad)
		}
	}
	if err := dispatch([]string{"init-cluster", "-bogus"}, nil, &out, &out); err == nil {
		t.Error("bad flag must fail")
	}
}

func TestServeRejectsBadSetup(t *testing.T) {
	dir, addrs := initTestCluster(t, "node-1", "node-2")
	peers := filepath.Join(dir, "peers.json")
	key1, key2 := filepath.Join(dir, "node-1.key"), filepath.Join(dir, "node-2.key")
	bad := [][]string{
		{"-key", key1, "-cluster", peers},
		{"-node", "node-1", "-key", key1, "-cluster", peers, "-webhook", "ftp://x"},
		{"-node", "node-1", "-key", key1, "-cluster", peers, "-interval", "0s"},
		{"-node", "node-1", "-key", key1, "-cluster", peers, "-log-level", "loud"},
		{"-node", "node-9", "-key", key1, "-cluster", peers},
		{"-node", "node-1", "-key", key2, "-cluster", peers},
		{"-node", "node-1", "-key", "missing.key", "-cluster", peers},
		{"-node", "node-1", "-key", key1, "-cluster", "missing.json"},
		{"-node", "node-1", "-key", key1, "-cluster", peers, "-min-voters", "0"},
		{"-node", "node-1", "-key", key1, "-cluster", peers, "-listen", "not-an-address"},
		{"-node", "node-1", "-key", key1, "-cluster", peers, "-listen", addrs["node-1"], "-sensor-listen", "not-an-address"},
		{"-node", "node-1", "-key", key1, "-cluster", peers, "-listen", addrs["node-1"], "-sensor-listen", "127.0.0.1:0", "-min", "2"},
		{"-bogus"},
	}
	for _, args := range bad {
		var out syncBuffer
		if err := serveContext(context.Background(), args, &out, &out, nil); err == nil {
			t.Errorf("args %v should fail", args)
		}
	}
}

func TestVersionCommand(t *testing.T) {
	var out bytes.Buffer
	if err := dispatch([]string{"version"}, nil, &out, &out); err != nil || !strings.Contains(out.String(), "hive-agent dev") {
		t.Fatalf("%q %v", out.String(), err)
	}
}
