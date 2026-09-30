package gateway

import (
	"testing"

	"github.com/123456342g-lang/hive-immune/pkg/quorum"
)

func testPolicy(t *testing.T) *Policy {
	t.Helper()
	p, err := ParsePolicy([]byte(goodPolicy))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// TestDecideMatrix walks the whole decision table: every risk class x
// clean/tainted session x swarm level x approval availability. It is the
// executable version of the policy documentation.
func TestDecideMatrix(t *testing.T) {
	p := testPolicy(t)
	cases := []struct {
		tool       string
		tainted    bool
		level      quorum.Level
		noApprover bool
		wantAction Action
		wantRule   string
	}{
		// clean session, no swarm level
		{"read_file", false, quorum.LevelNone, false, ActionAllow, "risk.read"},
		{"create_ticket", false, quorum.LevelNone, false, ActionAllow, "risk.write-internal"},
		{"send_email", false, quorum.LevelNone, false, ActionAllow, "risk.egress"},
		{"unregistered_tool", false, quorum.LevelNone, false, ActionAllow, "risk.egress"},

		// tainted session: reads still pass, everything else needs a human
		{"read_file", true, quorum.LevelNone, false, ActionAllow, "risk.read"},
		{"search_web", true, quorum.LevelNone, false, ActionAllow, "risk.read"},
		{"create_ticket", true, quorum.LevelNone, false, ActionApprove, "taint.write-internal"},
		{"send_email", true, quorum.LevelNone, false, ActionApprove, "taint.egress"},

		// tainted, no approval channel: deny, but the rule still names the
		// cause so the reputation feed can tell "taint" from "rate limit"
		{"create_ticket", true, quorum.LevelNone, true, ActionDeny, "taint.write-internal"},
		{"send_email", true, quorum.LevelNone, true, ActionDeny, "taint.egress"},
		{"read_file", true, quorum.LevelNone, true, ActionAllow, "risk.read"},

		// observe: every write needs a human, even in a clean session
		{"read_file", false, quorum.LevelObserve, false, ActionAllow, "risk.read"},
		{"create_ticket", false, quorum.LevelObserve, false, ActionApprove, "level.observe"},
		{"send_email", false, quorum.LevelObserve, false, ActionApprove, "level.observe"},
		{"create_ticket", false, quorum.LevelObserve, true, ActionDeny, "level.observe"},

		// contain: read-only
		{"read_file", false, quorum.LevelContain, false, ActionAllow, "risk.read"},
		{"create_ticket", false, quorum.LevelContain, false, ActionDeny, "level.contain"},
		{"send_email", true, quorum.LevelContain, false, ActionDeny, "level.contain"},

		// isolate: frozen
		{"read_file", false, quorum.LevelIsolate, false, ActionDeny, "level.isolate"},
		{"send_email", false, quorum.LevelIsolate, false, ActionDeny, "level.isolate"},
	}
	for _, tc := range cases {
		got := Decide(p, Input{
			Tool: tc.tool, Tainted: tc.tainted, Level: tc.level,
			ApprovalUnavailable: tc.noApprover,
		})
		if got.Action != tc.wantAction || got.Rule != tc.wantRule {
			t.Errorf("tool=%q tainted=%v level=%s noApprover=%v: got %s/%s, want %s/%s",
				tc.tool, tc.tainted, tc.level, tc.noApprover, got.Action, got.Rule, tc.wantAction, tc.wantRule)
		}
	}
}

func TestDecideFailureMode(t *testing.T) {
	d := Decide(nil, Input{Tool: "read_file"})
	if d.Action != ActionDeny || d.Rule != "degraded.deny" {
		t.Fatalf("no policy: got %s/%s, want deny/degraded.deny", d.Action, d.Rule)
	}
}

// TestDecideCapabilityBeatsEverything: an out-of-scope or expired token is
// refused before any other consideration, even for a read tool in a clean
// session - that is what makes T2 (over-privileged tool use) structural.
func TestDecideCapabilityBeatsEverything(t *testing.T) {
	p := testPolicy(t)
	for _, denied := range []string{"expired", "tool-out-of-scope", "wrong-audience", "forged"} {
		got := Decide(p, Input{Tool: "read_file", CapabilityDenied: denied})
		if got.Action != ActionDeny || got.Rule != "capability."+denied {
			t.Errorf("denied=%q: got %s/%s", denied, got.Action, got.Rule)
		}
	}
}

func TestDecideLimits(t *testing.T) {
	p := testPolicy(t)
	if d := Decide(p, Input{Tool: "read_file", RateExceeded: true}); d.Rule != "limits.rate" || d.Action != ActionDeny {
		t.Errorf("rate: %s/%s", d.Action, d.Rule)
	}
	if d := Decide(p, Input{Tool: "read_file", BudgetExceeded: true}); d.Rule != "limits.budget" || d.Action != ActionDeny {
		t.Errorf("budget: %s/%s", d.Action, d.Rule)
	}
	// Rate limit fires before the taint rule.
	if d := Decide(p, Input{Tool: "send_email", Tainted: true, RateExceeded: true}); d.Rule != "limits.rate" {
		t.Errorf("priority: %s", d.Rule)
	}
}

func TestLevelGateReads(t *testing.T) {
	for lvl, want := range map[quorum.Level]Action{
		quorum.LevelNone:    ActionAllow,
		quorum.LevelObserve: ActionAllow,
		quorum.LevelContain: ActionAllow,
		quorum.LevelIsolate: ActionDeny,
	} {
		a, rule, _ := levelGate(lvl, RiskRead)
		if a != want {
			t.Errorf("read at %s: %s (rule %q), want %s", lvl, a, rule, want)
		}
	}
}
