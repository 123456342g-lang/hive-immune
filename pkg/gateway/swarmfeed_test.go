package gateway

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/123456342g-lang/hive-immune/pkg/node"
	"github.com/123456342g-lang/hive-immune/pkg/quorum"
)

// statusServer answers /v1/status with the given level for agent a1 and
// counts hits. level "fail" turns into a 500, "unknown" omits a1.
func statusServer(t *testing.T, level string) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path != node.StatusPath {
			t.Errorf("path = %q, want %q", r.URL.Path, node.StatusPath)
		}
		switch level {
		case "fail":
			http.Error(w, "boom", http.StatusInternalServerError)
		case "unknown":
			_, _ = io.WriteString(w, `{"node":"n1","members":[{"node":"other","level":"none"}]}`)
		default:
			_, _ = io.WriteString(w, `{"node":"n1","members":[{"node":"a1","level":"`+level+`"}]}`)
		}
	}))
	t.Cleanup(ts.Close)
	return ts, &hits
}

func testFeed(url string, now func() time.Time) *swarmFeed {
	return newSwarmFeed(url, "a1", http.DefaultClient, now,
		slog.New(slog.NewTextHandler(io.Discard, nil)), time.Second, 30*time.Second)
}

func TestSwarmFeedReadsAndCachesLevel(t *testing.T) {
	ts, hits := statusServer(t, "isolate")
	now := time.Unix(1_700_000_000, 0)
	f := testFeed(ts.URL, func() time.Time { return now })

	if lvl := f.Level(); lvl != quorum.LevelIsolate {
		t.Fatalf("level = %v, want isolate", lvl)
	}
	// Inside the TTL the cache answers, not the node.
	now = now.Add(500 * time.Millisecond)
	if lvl := f.Level(); lvl != quorum.LevelIsolate {
		t.Fatalf("cached level = %v", lvl)
	}
	if hits.Load() != 1 {
		t.Fatalf("node was hit %d times, want 1", hits.Load())
	}
	// Past the TTL it refreshes.
	now = now.Add(2 * time.Second)
	if lvl := f.Level(); lvl != quorum.LevelIsolate {
		t.Fatalf("refreshed level = %v", lvl)
	}
	if hits.Load() != 2 {
		t.Fatalf("node was hit %d times, want 2", hits.Load())
	}
}

// TestSwarmFeedStickyThenForgets: a flapping node must not reset a contain
// decision to all-clear, but it must not freeze the agent forever either.
func TestSwarmFeedStickyThenForgets(t *testing.T) {
	var failing atomic.Bool
	var hits atomic.Int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		if failing.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, `{"members":[{"node":"a1","level":"contain"}]}`)
	}))
	t.Cleanup(ts.Close)

	now := time.Unix(1_700_000_000, 0)
	f := testFeed(ts.URL, func() time.Time { return now })
	if lvl := f.Level(); lvl != quorum.LevelContain {
		t.Fatalf("level = %v, want contain", lvl)
	}

	failing.Store(true)
	// Past the TTL the refresh fails; the last good level stands...
	now = now.Add(2 * time.Second)
	if lvl := f.Level(); lvl != quorum.LevelContain {
		t.Fatalf("during the outage the level must stick, got %v", lvl)
	}
	// ...and failed attempts still consume the TTL, so the dead node is
	// not polled on every call.
	first := hits.Load()
	now = now.Add(500 * time.Millisecond)
	_ = f.Level()
	if hits.Load() != first {
		t.Fatal("a failed refresh must throttle retries to the TTL")
	}

	// Once the level is too stale it is forgotten rather than replayed.
	now = now.Add(31 * time.Second)
	if lvl := f.Level(); lvl != quorum.LevelNone {
		t.Fatalf("stale level = %v, want none", lvl)
	}
}

func TestSwarmFeedUnknownAgentAndBadBody(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)

	ts, _ := statusServer(t, "unknown")
	f := testFeed(ts.URL, func() time.Time { return now })
	if lvl := f.Level(); lvl != quorum.LevelNone {
		t.Fatalf("unknown agent must read as none, got %v", lvl)
	}
	// The failure is cached too: no hot loop against a node that does not
	// know this agent.
	now = now.Add(500 * time.Millisecond)
	f.Level()

	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "not json")
	}))
	t.Cleanup(bad.Close)
	f2 := testFeed(bad.URL, func() time.Time { return now })
	if lvl := f2.Level(); lvl != quorum.LevelNone {
		t.Fatalf("unreadable status must read as none, got %v", lvl)
	}

	// Unreachable node.
	dead := testFeed("http://127.0.0.1:1", func() time.Time { return now })
	if lvl := dead.Level(); lvl != quorum.LevelNone {
		t.Fatalf("unreachable node must read as none, got %v", lvl)
	}
}
