package gateway

import (
	"crypto/ed25519"
	"crypto/rand"
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

	"github.com/hive-immune/hive-immune/pkg/envelope"
	"github.com/hive-immune/hive-immune/pkg/pheromone"
)

func policyFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tools.yaml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// levelServer reports one agent's response level on /v1/status.
func levelServer(t *testing.T, agent, level string) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"members":[{"node":"`+agent+`","level":"`+level+`"}]}`)
	}))
	t.Cleanup(ts.Close)
	return ts
}

// TestServerRateLimit: the second attempt inside the window never reaches
// the upstream, and the model is told which limit stopped it.
func TestServerRateLimit(t *testing.T) {
	s, out := testServer(t, func(c *Config) {
		c.PolicyPath = withPolicy(t)
		c.RateLimit = 1
	})

	up := feed(t, s, callLine(1, "read_file"))
	if up.Len() == 0 {
		t.Fatal("the first call must go through")
	}
	answer(t, s, out, `{"jsonrpc":"2.0","id":1,"result":{"content":[]}}`)

	up2 := feed(t, s, callLine(2, "read_file"))
	if up2.Len() != 0 {
		t.Fatal("the second call exceeded the rate but reached the upstream")
	}
	if !strings.Contains(out.String(), "rate limit exceeded") {
		t.Fatalf("client got %q", out.String())
	}
	recs := mustTail(t, s, 10)
	last := recs[len(recs)-1]
	if last.Action != ActionDeny || last.Rule != "limits.rate" {
		t.Fatalf("last record = %+v", last)
	}
}

// TestServerBudget: tool cost comes from the policy; once the window's
// budget is spent, the next paid tool stops.
func TestServerBudget(t *testing.T) {
	path := policyFile(t, `version: 1
defaults: {risk: egress, taint: external}
tools:
  read_file: {risk: read, taint: internal, cost: 6}
  query_db: {risk: read, taint: internal, cost: 6}
`)
	s, out := testServer(t, func(c *Config) {
		c.PolicyPath = path
		c.Budget = 10
	})

	up := feed(t, s, callLine(1, "read_file"))
	if up.Len() == 0 {
		t.Fatal("6 of 10 budget units must fit")
	}
	answer(t, s, out, `{"jsonrpc":"2.0","id":1,"result":{"content":[]}}`)

	up2 := feed(t, s, callLine(2, "query_db"))
	if up2.Len() != 0 {
		t.Fatal("6+6 exceeds the budget but reached the upstream")
	}
	recs := mustTail(t, s, 10)
	last := recs[len(recs)-1]
	if last.Action != ActionDeny || last.Rule != "limits.budget" {
		t.Fatalf("last record = %+v", last)
	}
	// A free tool still fits: budget is about cost, not call count.
	up3 := feed(t, s, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"free_tool","arguments":{}}}`)
	if up3.Len() == 0 {
		t.Fatal("a zero-cost tool must not be blocked by the budget")
	}
}

// TestServerSwarmLevelStopsReads: what the node says about this agent is
// applied before the policy engine - isolate freezes even reads.
func TestServerSwarmLevelStopsReads(t *testing.T) {
	ts := levelServer(t, "agent-1", "isolate")
	s, out := testServer(t, func(c *Config) {
		c.PolicyPath = withPolicy(t)
		c.NodeURL = ts.URL
	})

	up := feed(t, s, callLine(1, "read_file"))
	if up.Len() != 0 {
		t.Fatal("isolate must stop reads")
	}
	if !strings.Contains(out.String(), "swarm level") {
		t.Fatalf("client got %q", out.String())
	}
	recs := mustTail(t, s, 1)
	if recs[0].Rule != "level.isolate" || recs[0].Action != ActionDeny {
		t.Fatalf("record = %+v", recs[0])
	}
}

// TestServerEmitsDenialSignals: a refusal the swarm cares about is
// deposited as a signed self-report; the same report is not repeated
// inside the cooldown.
func TestServerEmitsDenialSignals(t *testing.T) {
	var mu sync.Mutex
	var posted []envelope.Envelope
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet: // the feed reads levels from the same node
			_, _ = io.WriteString(w, `{"members":[{"node":"agent-1","level":"none"}]}`)
		default:
			var batch []envelope.Envelope
			_ = json.NewDecoder(r.Body).Decode(&batch)
			mu.Lock()
			posted = append(posted, batch...)
			mu.Unlock()
			_, _ = io.WriteString(w, `{"accepted":1}`)
		}
	}))
	t.Cleanup(ts.Close)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, out := testServer(t, func(c *Config) {
		c.PolicyPath = withPolicy(t)
		c.RateLimit = 1
		c.NodeURL = ts.URL
		c.NodeKey = priv
	})

	up := feed(t, s, callLine(1, "read_file"))
	if up.Len() == 0 {
		t.Fatal("first call must go through")
	}
	answer(t, s, out, `{"jsonrpc":"2.0","id":1,"result":{"content":[]}}`)

	feed(t, s, callLine(2, "read_file")) // rate-limited → signal
	feed(t, s, callLine(3, "read_file")) // still limited, same rule → cooldown

	mu.Lock()
	defer mu.Unlock()
	if len(posted) != 1 {
		t.Fatalf("got %d signals, want 1 (cooldown on the same rule)", len(posted))
	}
	ring, err := envelope.NewKeyring(map[pheromone.NodeID]ed25519.PublicKey{"agent-1": pub})
	if err != nil {
		t.Fatal(err)
	}
	sig, err := ring.Open(posted[0])
	if err != nil {
		t.Fatalf("signal must verify for the node: %v", err)
	}
	if sig.Kind != "gateway.limits.rate" || sig.Strength != 0.3 || sig.Subject != "agent-1" {
		t.Fatalf("signal = %+v", sig)
	}
}

// TestServerNoSignalForLevelVerdict: level.* is the swarm's own verdict -
// depositing it again would let the field amplify itself.
func TestServerNoSignalForLevelVerdict(t *testing.T) {
	var mu sync.Mutex
	var posted []envelope.Envelope
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			_, _ = io.WriteString(w, `{"members":[{"node":"agent-1","level":"observe"}]}`)
		default:
			var batch []envelope.Envelope
			_ = json.NewDecoder(r.Body).Decode(&batch)
			mu.Lock()
			posted = append(posted, batch...)
			mu.Unlock()
			_, _ = io.WriteString(w, `{"accepted":1}`)
		}
	}))
	t.Cleanup(ts.Close)

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := testServer(t, func(c *Config) {
		c.PolicyPath = withPolicy(t)
		c.NodeURL = ts.URL
		c.NodeKey = priv
	})

	// A clean egress call under observe needs a human; with no approval
	// channel it is refused as level.observe.
	feed(t, s, callLine(1, "send_email"))
	recs := mustTail(t, s, 1)
	if recs[0].Rule != "level.observe" || recs[0].Action != ActionDeny {
		t.Fatalf("record = %+v", recs[0])
	}
	mu.Lock()
	defer mu.Unlock()
	if len(posted) != 0 {
		t.Fatalf("level verdicts must not be re-deposited, got %d signals", len(posted))
	}
}

// TestNewServerRejectsSwarmMisconfig: broken swarm wiring fails at
// startup, not on the first call.
func TestNewServerRejectsSwarmMisconfig(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	base := func() Config {
		return Config{Stderr: io.Discard, Now: time.Now}
	}

	for name, mutate := range map[string]func(*Config){
		"signal key without node": func(c *Config) { c.NodeKey = priv },
		"node without agent":      func(c *Config) { c.NodeURL = "http://127.0.0.1:7946" },
		"negative rate":           func(c *Config) { c.RateLimit = -1 },
		"negative budget":         func(c *Config) { c.Budget = -1 },
	} {
		c := base()
		mutate(&c)
		if _, err := newServer(c); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}

	c := base()
	c.NodeURL, c.Agent, c.NodeKey = "http://127.0.0.1:7946", "a1", priv
	if _, err := newServer(c); err != nil {
		t.Fatalf("valid swarm wiring rejected: %v", err)
	}
}
