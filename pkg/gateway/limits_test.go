package gateway

import (
	"testing"
	"time"
)

func TestLimiterRateWindow(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := newLimiter(3, 0, time.Minute, func() time.Time { return now })

	for i := 1; i <= 3; i++ {
		rate, budget := l.observe(0)
		if rate || budget {
			t.Fatalf("call %d inside the limit: rate=%v budget=%v", i, rate, budget)
		}
	}
	if rate, _ := l.observe(0); !rate {
		t.Fatal("the fourth attempt in the window must exceed the rate")
	}
	// A denied attempt still counts: that is the point of the limit.
	if rate, _ := l.observe(0); !rate {
		t.Fatal("the storm must keep counting")
	}

	now = now.Add(time.Minute)
	if rate, _ := l.observe(0); rate {
		t.Fatal("a new window must reset the rate")
	}
}

func TestLimiterBudget(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := newLimiter(0, 10, time.Minute, func() time.Time { return now })

	if _, budget := l.observe(6); budget {
		t.Fatal("6 of 10 must fit")
	}
	if _, budget := l.observe(5); !budget {
		t.Fatal("6+5 exceeds the budget")
	}
	// The refused attempt added nothing, so the remaining 4 still fit.
	if _, budget := l.observe(4); budget {
		t.Fatal("the refused attempt must not have spent budget")
	}
	if _, budget := l.observe(1); !budget {
		t.Fatal("the budget is now exactly full")
	}

	now = now.Add(time.Minute)
	if _, budget := l.observe(10); budget {
		t.Fatal("a new window must reset the budget")
	}
}

func TestLimiterDisabledAndDefaults(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := newLimiter(0, 0, 0, func() time.Time { return now })
	if l.window != DefaultLimitWindow {
		t.Fatalf("window = %v, want the default", l.window)
	}
	for i := 0; i < 100; i++ {
		if rate, budget := l.observe(1000); rate || budget {
			t.Fatalf("disabled limits flagged on call %d", i)
		}
	}
}

// TestLimiterConcurrency: the pumps and the admin endpoint may observe at
// the same time; the counters must stay consistent under -race.
func TestLimiterConcurrency(t *testing.T) {
	l := newLimiter(1000, 1000, time.Minute, time.Now)
	done := make(chan struct{})
	for i := 0; i < 4; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 100; j++ {
				l.observe(1)
			}
		}()
	}
	for i := 0; i < 4; i++ {
		<-done
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.calls != 400 || l.cost != 400 {
		t.Fatalf("calls=%d cost=%d, want 400/400", l.calls, l.cost)
	}
}
