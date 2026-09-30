package gateway

import (
	"fmt"

	"github.com/123456342g-lang/hive-immune/pkg/quorum"
	"github.com/123456342g-lang/hive-immune/pkg/taint"
)

// Action is what the gateway does with a tools/call.
type Action string

// The three outcomes. "approve" means the call is legitimate but needs a
// human; if no approval channel answers in time it becomes a deny.
const (
	// ActionAllow forwards the call to the upstream MCP server.
	ActionAllow Action = "allow"
	// ActionDeny never reaches the upstream server; the caller gets a
	// tool error describing the rule that fired.
	ActionDeny Action = "deny"
	// ActionApprove blocks until an operator answers the approval request.
	ActionApprove Action = "approve"
	// ActionReset records an operator intervention (a taint reset) in the
	// audit log. It is not a call outcome: no tools/call ever has it.
	ActionReset Action = "reset"
)

// Input is everything the decision engine knows about one call. The zero
// value means: clean session, no swarm level, no capability token in play,
// no rate or budget pressure - i.e. the pre-0.2 baseline.
type Input struct {
	Tool    string
	Tainted bool
	Level   quorum.Level

	// CapabilityDenied is empty when the capability check passed (or is
	// not required); otherwise it names the failed check, e.g.
	// "expired" or "tool-out-of-scope".
	CapabilityDenied string
	// RateExceeded and BudgetExceeded are set by the limiters.
	RateExceeded   bool
	BudgetExceeded bool
	// ApprovalUnavailable is set when the call would need a human but no
	// approval channel is configured.
	ApprovalUnavailable bool
}

// Decision is the outcome for one call. Rule is a stable, machine-readable
// identifier ("taint.egress") for tests, dashboards and reputation
// signals; Reason is the human sentence that goes to the model and the
// audit log. NeedsApproval says the call was legitimate but waiting for a
// human - it distinguishes "the operator said no" from "nobody could be
// asked".
type Decision struct {
	Action        Action
	Rule          string
	Risk          Risk
	Taint         taint.Source
	NeedsApproval bool
	Reason        string
}

func (d Decision) String() string {
	return fmt.Sprintf("%s (%s)", d.Action, d.Rule)
}

// Decide applies the structural rules, in order:
//
//  1. failure mode: no usable policy. Without a classification no tool can
//     prove it is a read, so every call is denied ("egress 默认拒绝" - an
//     unclassified tool is treated as outward-facing). Reads pass as soon
//     as any policy is loaded, and reload failures keep the last good
//     policy for exactly this reason;
//  2. capability token (T2/T5): an out-of-scope, expired or forged token
//     denies regardless of how benign the tool looks;
//  3. rate and budget (T6);
//  4. swarm level: isolate freezes the agent, contain keeps it read-only,
//     observe forces every write through a human;
//  5. risk x taint: reads always pass; a tainted session must have a human
//     for internal writes and for anything leaving the organisation.
//
// Nothing here inspects prompt or argument content: the outcome is a pure
// function of policy, session state and identity, which is what makes it
// testable exhaustively.
func Decide(p *Policy, in Input) Decision {
	if p == nil {
		return Decision{Action: ActionDeny, Rule: "degraded.deny", Risk: RiskEgress, Taint: taint.SourceExternal,
			Reason: "policy unavailable; no tool can be shown to be read-only, so all calls are denied"}
	}
	cls := p.Classify(in.Tool)

	if in.CapabilityDenied != "" {
		return Decision{Action: ActionDeny, Rule: "capability." + in.CapabilityDenied, Risk: cls.Risk, Taint: cls.Taint,
			Reason: "capability token does not permit this call: " + in.CapabilityDenied}
	}
	if in.RateExceeded {
		return Decision{Action: ActionDeny, Rule: "limits.rate", Risk: cls.Risk, Taint: cls.Taint,
			Reason: "rate limit exceeded for this agent"}
	}
	if in.BudgetExceeded {
		return Decision{Action: ActionDeny, Rule: "limits.budget", Risk: cls.Risk, Taint: cls.Taint,
			Reason: "cost budget exhausted for this agent"}
	}

	if lvl, rule, needsApproval := levelGate(in.Level, cls.Risk); lvl != ActionAllow {
		if lvl == ActionApprove && in.ApprovalUnavailable {
			return Decision{Action: ActionDeny, Rule: rule, Risk: cls.Risk, Taint: cls.Taint, NeedsApproval: true,
				Reason: "swarm level requires approval for writes, but no approval channel is configured"}
		}
		return Decision{Action: lvl, Rule: rule, Risk: cls.Risk, Taint: cls.Taint, NeedsApproval: needsApproval,
			Reason: fmt.Sprintf("swarm level %q: %s", in.Level, rule)}
	}

	switch {
	case cls.Risk == RiskRead:
		return Decision{Action: ActionAllow, Rule: "risk.read", Risk: cls.Risk, Taint: cls.Taint,
			Reason: "read-only tool"}
	case in.Tainted && cls.Risk == RiskWriteInternal:
		return approvalOrDeny(in, Decision{Risk: cls.Risk, Taint: cls.Taint, Rule: "taint.write-internal",
			Reason: "session has read external content; internal writes need a human"})
	case in.Tainted && cls.Risk == RiskEgress:
		return approvalOrDeny(in, Decision{Risk: cls.Risk, Taint: cls.Taint, Rule: "taint.egress",
			Reason: "session has read external content; sending data out needs a human"})
	}
	return Decision{Action: ActionAllow, Rule: "risk." + string(cls.Risk), Risk: cls.Risk, Taint: cls.Taint,
		Reason: "clean session, tool within policy"}
}

func approvalOrDeny(in Input, d Decision) Decision {
	d.NeedsApproval = true
	if in.ApprovalUnavailable {
		d.Action = ActionDeny
		d.Reason += "; no approval channel is configured"
		return d
	}
	d.Action = ActionApprove
	return d
}

// levelGate maps a swarm response level onto an action for one risk class.
// Reads survive observe and contain; only isolate stops everything.
func levelGate(lvl quorum.Level, r Risk) (Action, string, bool) {
	switch lvl {
	case quorum.LevelIsolate:
		return ActionDeny, "level.isolate", false
	case quorum.LevelContain:
		if r == RiskRead {
			return ActionAllow, "", false
		}
		return ActionDeny, "level.contain", false
	case quorum.LevelObserve:
		if r == RiskRead {
			return ActionAllow, "", false
		}
		return ActionApprove, "level.observe", true
	}
	return ActionAllow, "", false
}
