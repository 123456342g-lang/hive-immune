package gateway

import (
	"sync"
	"time"
)

// DefaultLimitWindow is the accounting window for the rate and budget
// limiters when Config.LimitWindow is zero.
const DefaultLimitWindow = time.Minute

// limiter caps how much one agent's session may do per window: how many
// tools/call attempts it may make (rate) and how much planned tool cost it
// may consume (budget). Denied calls still count against the rate, because
// the point of a rate limit is to stop a storm - including a storm of
// refusals - while budget is what the operator is willing to spend.
//
// Windows are fixed: simple to reason about, simple to test with an
// injected clock, and generous enough that no agent is meaningfully
// punished for a boundary it cannot see.
type limiter struct {
	mu     sync.Mutex
	now    func() time.Time
	rate   int // max attempts per window, 0 disables
	budget int // max cost units per window, 0 disables
	window time.Duration

	start time.Time // beginning of the current window
	calls int
	cost  int
}

func newLimiter(rate, budget int, window time.Duration, now func() time.Time) *limiter {
	if window <= 0 {
		window = DefaultLimitWindow
	}
	return &limiter{now: now, rate: rate, budget: budget, window: window}
}

// observe records one tools/call attempt costing cost units and reports
// whether either limit is already exhausted. Attempts always count against
// the rate; the cost is added unless it would push the window over budget.
func (l *limiter) observe(cost int) (rateExceeded, budgetExceeded bool) {
	l.mu.Lock()
	defer l.mu.Unlock()

	t := l.now()
	if l.start.IsZero() {
		l.start = t
	} else if t.Sub(l.start) >= l.window {
		l.start, l.calls, l.cost = t, 0, 0
	}

	rateHit := l.rate > 0 && l.calls >= l.rate
	budgetHit := l.budget > 0 && l.cost+cost > l.budget
	l.calls++
	if !budgetHit {
		l.cost += cost
	}
	return rateHit, budgetHit
}
