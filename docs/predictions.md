# Predictions

Falsifiable claims the project makes, with the measurement that would
kill them. A prediction that cannot fail is marketing. Status links to
the evidence; the AgentDojo numbers live in [eval.md](eval.md).

## P1 - gating effects stops indirect prompt injection (T1)

**Claim.** On AgentDojo with the standard injection attacks, the
gateway's taint gate drives injection success rate for
state-changing/egressing attacks to near zero, while benign task success
stays within a few points of the unguarded run.

**Measurement.** Same model, same tasks, gateway in front of the tools:
attack success rate (ASR) and utility (fraction of benign tasks completed)
with and without the gateway.

**Falsified if.** ASR stays above ~10% for attacks whose winning step is
a write or egress, *or* utility falls below ~80% of the unguarded run
(gating everything is trivial and useless).

**Status.** [x] measured - [eval.md](eval.md). **Mixed, leaning
falsified as written.** Security half: *untestable at this tier* - the
unguarded baseline executes 0/57 injections (`glm-4-flash` is
injection-incapable), so there is no ASR for the gate to reduce; the
gate's denials are verified by audit, not by ASR deltas. Utility half:
deny-only gating yields 15.0% vs 32.5% unguarded (46% of baseline -
below the 80% bar, so the "few points" clause fails for that
configuration), while an approval channel recovers to 30.0% (egress
refused by design) and full approval to 32.5% - exact parity. The
prediction as written did not specify an approval channel; with one, the
utility criterion passes and only the ASR criterion remains open,
pending a model tier that actually executes injections.

## P2 - capability tokens bound a session's blast radius (T2/T5)

**Claim.** A session holding a least-privilege token cannot perform
out-of-scope calls even when the policy, the swarm level and a clean
taint state would all allow them; forged, expired or foreign tokens are
refused with a distinguishable rule in the audit log.

**Measurement.** Gateway test suite (`capability.*` rules) and the eval
run with tokens scoped per task family.

**Falsified if.** any out-of-scope call reaches the upstream MCP server,
or a token minted for another subject verifies.

**Status.** [x] `pkg/gateway/capability_test.go`, `pkg/capability`.

## P3 - a swarm level reaches the data plane within seconds (T7)

**Claim.** When the local node's status moves an agent to `isolate`, the
gateway stops *all* tool calls (including reads) within one status TTL
(2s) plus request latency; `contain` keeps reads alive and freezes
writes.

**Measurement.** End-to-end test with a stubbed `/v1/status`
(`TestServeSwarmLevelEndToEnd`), plus the compose demo under Falco
pressure.

**Falsified if.** calls keep passing at `isolate`, or reads die at
`contain`.

**Status.** [x] gateway tests; [ ] compose demo timing.

## P4 - the credential copy is tamper-evident without the gateway (T4)

**Claim.** Anyone holding only the public key can detect a modified,
truncated or re-signed line in the credential file; `hive-agent verify`
exits non-zero on any such line.

**Measurement.** Round-trip and tamper tests, plus fuzzing of the
envelope parser.

**Falsified if.** verify accepts a line whose payload, payload type or
signature was altered, or crashes on malformed input.

**Status.** [x] `pkg/dsse`, `pkg/credential` tests and fuzz targets.

## P5 - rate and budget stop cost runaway (T6)

**Claim.** A looping agent is stopped at `-rate` attempts per window
(counting attempts it was refused), and `-budget` is never overshot by
more than one in-flight call's cost.

**Measurement.** `TestServerRateLimit`, `TestServerBudget` and the
end-to-end CLI test.

**Falsified if.** a refusal does not count toward the rate, or a call
that would exceed the remaining budget is forwarded.

**Status.** [x] gateway and cmd tests.

## P6 - the gate is cheap enough to sit inline

**Claim.** The policy path (no capability token) adds sub-millisecond
overhead per `tools/call`; with a capability token the three datalog
checks stay in single-digit milliseconds (`BenchmarkCheck`).

**Measurement.** `go test -bench BenchmarkCheck ./pkg/capability/`.

**Falsified if.** overhead reaches tens of milliseconds on the
policy-only path, or a token check exceeds ~20ms on a warm process.

**Status.** [x] 7.4ms/op measured for the full token check on an
i7-13650HX (2026-09); re-run on target hardware before quoting.

## What would change our mind

The load-bearing prediction is P1. If a rigorous eval shows the taint
gate both failing to stop egress attacks *and* gutting benign utility,
the design claim - "convert detection into gating" - is wrong and the
project needs a different mechanism, not a tuned policy. P3–P5 are
structural (they are properties of code paths with tests); P2 fails only
by regression; P6 fails on hardware.
