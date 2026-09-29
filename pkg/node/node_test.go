package node

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hive-immune/hive-immune/pkg/cluster"
	"github.com/hive-immune/hive-immune/pkg/envelope"
	"github.com/hive-immune/hive-immune/pkg/pheromone"
	"github.com/hive-immune/hive-immune/pkg/quorum"
	"github.com/hive-immune/hive-immune/pkg/sensor"
)

// Time of the captured Falco alert in pkg/sensor/testdata.
var falcoAt = time.Date(2026, 9, 28, 11, 22, 27, 918448895, time.UTC)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type swarmFixture struct {
	nodes   map[pheromone.NodeID]*Node
	servers map[pheromone.NodeID]*httptest.Server
	keys    map[pheromone.NodeID]ed25519.PrivateKey
	cluster cluster.Config
	clock   *clock
}

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// newSwarm starts real HTTP nodes on loopback, all in one zone.
func newSwarm(t *testing.T, ids ...pheromone.NodeID) *swarmFixture {
	t.Helper()
	servers := make(map[pheromone.NodeID]*httptest.Server)
	var names []string
	for _, id := range ids {
		servers[id] = httptest.NewUnstartedServer(nil)
		names = append(names, string(id))
	}
	c, keys, err := cluster.Generate(names, "", "prod", rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for i := range c.Members {
		c.Members[i].Addr = "http://" + servers[c.Members[i].ID].Listener.Addr().String()
	}
	f := &swarmFixture{nodes: map[pheromone.NodeID]*Node{}, servers: servers, keys: keys, cluster: c, clock: &clock{t: falcoAt}}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	for _, id := range ids {
		cfg := DefaultConfig(id, c)
		cfg.Logger, cfg.Now = quietLogger(), f.clock.Now
		n, err := New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		f.nodes[id] = n
		servers[id].Config.Handler = n.Handler()
		servers[id].Start()
		t.Cleanup(servers[id].Close)
		go n.Run(ctx)
	}
	return f
}

func (f *swarmFixture) seal(t *testing.T, origin, subject pheromone.NodeID, strength float64) envelope.Envelope {
	t.Helper()
	s, err := envelope.NewSigner(origin, f.keys[origin])
	if err != nil {
		t.Fatal(err)
	}
	e, err := s.Seal(pheromone.Signal{Origin: origin, Subject: subject, Kind: "test", Strength: strength, At: f.clock.Now()})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func levelOf(n *Node, id pheromone.NodeID) quorum.Level {
	for _, s := range n.Evaluate() {
		if s.Node == id {
			return s.Level
		}
	}
	return -1
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestGossipSpreadsSignalAndSwarmAgrees(t *testing.T) {
	f := newSwarm(t, "node-1", "node-2", "node-3")

	if err := f.nodes["node-1"].Receive(f.seal(t, "node-1", "node-1", 0.6)); err != nil {
		t.Fatal(err)
	}

	for _, id := range []pheromone.NodeID{"node-2", "node-3"} {
		n := f.nodes[id]
		eventually(t, string(id)+" to learn about node-1", func() bool { return levelOf(n, "node-1") == quorum.LevelContain })
	}
	for id, n := range f.nodes {
		if lvl := levelOf(n, "node-2"); lvl != quorum.LevelObserve {
			t.Errorf("%s sees node-2 at %v, want zone alert (observe)", id, lvl)
		}
	}
	// node-2 and node-3 forward the signal back to each other; the echoes
	// must be recognised as duplicates, not accepted twice.
	eventually(t, "echoes to be deduplicated", func() bool {
		return f.nodes["node-2"].Stats().Duplicates+f.nodes["node-3"].Stats().Duplicates >= 1
	})
	if s := f.nodes["node-1"].Stats(); s.Accepted != 1 || s.Forwarded != 2 {
		t.Errorf("node-1 stats %+v", s)
	}
}

func TestReceiveRejects(t *testing.T) {
	f := newSwarm(t, "a", "b")
	n := f.nodes["a"]
	good := f.seal(t, "b", "b", 0.5)

	if err := n.Receive(good); err != nil {
		t.Fatal(err)
	}
	if err := n.Receive(good); !errors.Is(err, ErrDuplicate) {
		t.Errorf("replay: want ErrDuplicate, got %v", err)
	}
	tampered := good
	tampered.Signal.Strength = 1
	if err := n.Receive(tampered); !errors.Is(err, envelope.ErrBadSignature) {
		t.Errorf("tampered: got %v", err)
	}
	old := f.seal(t, "b", "b", 0.5)
	f.clock.Add(11 * time.Minute)
	if err := n.Receive(old); !errors.Is(err, ErrStale) {
		t.Errorf("stale: got %v", err)
	}
	future := f.seal(t, "b", "b", 0.5)
	future.Signal.At = f.clock.Now().Add(time.Hour)
	future = resealed(t, f, future.Signal)
	if err := n.Receive(future); !errors.Is(err, pheromone.ErrInvalidSignal) {
		t.Errorf("future: got %v", err)
	}
	if err := n.Receive(future); !errors.Is(err, pheromone.ErrInvalidSignal) {
		t.Errorf("a rejected signal must not be remembered as seen: %v", err)
	}
	if s := n.Stats(); s.Accepted != 1 || s.Duplicates != 1 || s.Rejected != 4 {
		t.Errorf("stats %+v", s)
	}
}

func resealed(t *testing.T, f *swarmFixture, s pheromone.Signal) envelope.Envelope {
	t.Helper()
	signer, _ := envelope.NewSigner(s.Origin, f.keys[s.Origin])
	e, err := signer.Seal(s)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestReplayCacheFailsClosedAndPrunes(t *testing.T) {
	f := newSwarm(t, "a")
	cfg := DefaultConfig("a", f.cluster)
	cfg.MaxSeen, cfg.Logger, cfg.Now = 1, quietLogger(), f.clock.Now
	n, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	if err := n.Receive(f.seal(t, "a", "a", 0.5)); err != nil {
		t.Fatal(err)
	}
	f.clock.Add(time.Second)
	if err := n.Receive(f.seal(t, "a", "a", 0.5)); !errors.Is(err, ErrOverloaded) {
		t.Fatalf("full cache must refuse, got %v", err)
	}
	f.clock.Add(11 * time.Minute)
	n.Prune()
	if err := n.Receive(f.seal(t, "a", "a", 0.5)); err != nil {
		t.Fatalf("after expiry the cache must have room: %v", err)
	}
}

func post(t *testing.T, url, body string) (int, string) {
	t.Helper()
	resp, err := http.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestEnvelopesEndpoint(t *testing.T) {
	f := newSwarm(t, "a", "b")
	url := f.servers["a"].URL + EnvelopesPath
	good, _ := json.Marshal([]envelope.Envelope{f.seal(t, "b", "b", 0.5), f.seal(t, "b", "a", 0.2)})

	code, body := post(t, url, string(good))
	if code != http.StatusOK || !strings.Contains(body, `"accepted":2`) {
		t.Fatalf("good batch: %d %s", code, body)
	}
	code, body = post(t, url, string(good))
	if code != http.StatusOK || !strings.Contains(body, `"duplicate":2`) {
		t.Fatalf("replayed batch: %d %s", code, body)
	}
	if code, _ := post(t, url, `{"not":"an array"}`); code != http.StatusBadRequest {
		t.Errorf("object body: %d", code)
	}
	if code, _ := post(t, url, `[`+strings.Repeat(`{},`, MaxBatch)+`{}]`); code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized batch: %d", code)
	}
	if code, _ := post(t, url, `["`+strings.Repeat("x", maxBodyBytes)+`"]`); code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized body: %d", code)
	}
	if code, body := post(t, url, `[{"signal":{"origin":"b"}}]`); code != http.StatusOK || !strings.Contains(body, `"rejected":1`) {
		t.Errorf("unsigned envelope: %d %s", code, body)
	}
}

func TestStatusAndHealth(t *testing.T) {
	f := newSwarm(t, "a", "b")
	if err := f.nodes["a"].Receive(f.seal(t, "a", "a", 1)); err != nil {
		t.Fatal(err)
	}

	resp, err := http.Get(f.servers["a"].URL + "/v1/status")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var rep StatusReport
	if err := json.NewDecoder(resp.Body).Decode(&rep); err != nil {
		t.Fatal(err)
	}
	if rep.Node != "a" || len(rep.Members) != 2 || rep.Members[0].Level != quorum.LevelIsolate || rep.Stats.Accepted != 1 {
		t.Fatalf("status %+v", rep)
	}
	raw, _ := json.Marshal(rep)
	if !bytes.Contains(raw, []byte(`"level":"isolate"`)) {
		t.Fatalf("levels must be readable names: %s", raw)
	}

	h, err := http.Get(f.servers["a"].URL + "/healthz")
	if err != nil || h.StatusCode != http.StatusOK {
		t.Fatalf("healthz: %v %v", h, err)
	}
	h.Body.Close()
}

func TestFalcoSensorEndpoint(t *testing.T) {
	f := newSwarm(t, "a", "b")
	n := f.nodes["a"]
	signer, _ := envelope.NewSigner("a", f.keys["a"])
	mapper, err := sensor.NewMapper(sensor.DefaultMapperConfig("a"))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(n.SensorHandler(sensor.Falco{}, mapper, signer))
	defer srv.Close()
	alert, err := os.ReadFile("../sensor/testdata/falco.jsonl")
	if err != nil {
		t.Fatal(err)
	}

	code, body := post(t, srv.URL+FalcoPath, string(alert))

	if code != http.StatusOK || !strings.Contains(body, `"emitted":1`) {
		t.Fatalf("%d %s", code, body)
	}
	if lvl := levelOf(n, "a"); lvl != quorum.LevelContain {
		t.Fatalf("a Falco Warning must contain the node, got %v", lvl)
	}
	eventually(t, "b to receive the gossiped alert", func() bool { return levelOf(f.nodes["b"], "a") == quorum.LevelContain })

	if code, _ := post(t, srv.URL+FalcoPath, strings.Repeat("x", maxBodyBytes+1)); code != http.StatusBadRequest {
		t.Errorf("oversized sensor body: %d", code)
	}
}

func TestWatchReportsTransitions(t *testing.T) {
	f := newSwarm(t, "a", "b")
	n := f.nodes["a"]
	prev := map[pheromone.NodeID]quorum.Level{}
	if got := n.changes(prev); len(got) != 0 {
		t.Fatalf("quiet swarm must not change: %+v", got)
	}

	if err := n.Receive(f.seal(t, "a", "a", 0.6)); err != nil {
		t.Fatal(err)
	}
	got := n.changes(prev)

	if len(got) != 2 || got[0].Node != "a" || got[0].To != quorum.LevelContain || got[1].To != quorum.LevelObserve {
		t.Fatalf("changes %+v", got)
	}
	f.clock.Add(time.Hour) // evidence decays away
	if back := n.changes(prev); len(back) != 2 || back[0].To != quorum.LevelNone {
		t.Fatalf("decay must be reported: %+v", back)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	n.Watch(ctx, time.Millisecond, func(Change) {})
}

func TestUnreachablePeerCountsSendErrors(t *testing.T) {
	f := newSwarm(t, "a", "b")
	f.servers["b"].Close()

	if err := f.nodes["a"].Receive(f.seal(t, "a", "a", 0.5)); err != nil {
		t.Fatal(err)
	}

	eventually(t, "send error", func() bool { return f.nodes["a"].Stats().SendErrors == 1 })
}

func TestPeerErrorStatusCountsSendErrors(t *testing.T) {
	f := newSwarm(t, "a")
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer failing.Close()
	c := f.cluster
	c.Members = append(c.Members, cluster.Member{ID: "b", PublicKey: c.Members[0].PublicKey, Addr: failing.URL})
	cfg := DefaultConfig("a", c)
	cfg.Logger, cfg.Now = quietLogger(), f.clock.Now
	n, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go n.Run(ctx)

	if err := n.Receive(f.seal(t, "a", "a", 0.5)); err != nil {
		t.Fatal(err)
	}

	eventually(t, "send error", func() bool { return n.Stats().SendErrors == 1 })
}

func TestFullQueueDrops(t *testing.T) {
	f := newSwarm(t, "a")
	c := f.cluster
	c.Members = append(c.Members, cluster.Member{ID: "b", PublicKey: c.Members[0].PublicKey, Addr: "http://127.0.0.1:1"})
	cfg := DefaultConfig("a", c)
	cfg.QueueSize, cfg.Logger, cfg.Now = 1, quietLogger(), f.clock.Now
	n, err := New(cfg) // Run is never started, so nothing drains the queue
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 3; i++ {
		f.clock.Add(time.Millisecond)
		if err := n.Receive(f.seal(t, "a", "a", 0.5)); err != nil {
			t.Fatal(err)
		}
	}

	if s := n.Stats(); s.Forwarded != 1 || s.Dropped != 2 {
		t.Fatalf("stats %+v", s)
	}
}

func TestNewValidation(t *testing.T) {
	c, _, err := cluster.Generate([]string{"a"}, "", "", rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bad := []func(*Config){
		func(cfg *Config) { cfg.Self = "stranger" },
		func(cfg *Config) { cfg.Cluster = cluster.Config{} },
		func(cfg *Config) { cfg.Params.Scale = 0 },
		func(cfg *Config) { cfg.MaxAge = 0 },
		func(cfg *Config) { cfg.Client = nil },
		func(cfg *Config) { cfg.Field.HalfLife = 0 },
	}
	for i, mutate := range bad {
		cfg := DefaultConfig("a", c)
		mutate(&cfg)
		if _, err := New(cfg); err == nil {
			t.Errorf("case %d should fail", i)
		}
	}
	if n, err := New(DefaultConfig("a", c)); err != nil || n.Self() != "a" || len(n.Peers()) != 0 {
		t.Fatalf("valid config: %v", err)
	}
}
