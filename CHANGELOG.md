# Changelog

All notable changes are documented here. The project follows
[Semantic Versioning](https://semver.org/); before 1.0, minor versions may
contain breaking changes.

## 0.2.0 — Agent 行为防线 (agent behavior defense line)

The swarm now reaches the tool boundary: every MCP call an agent makes is
gated inline, and the decisions are auditable, token-bound and scoreable.

### Added

- `hive-gateway`: a hand-written MCP stdio proxy (newline-delimited
  JSON-RPC, spec 2025-06-18) that decides per `tools/call` -
  degraded mode, capability token, rate/budget, swarm level, then
  risk x taint - and forwards or refuses. Unknown tools default to
  `egress`/`external`; refusals return as tool errors so the upstream
  server is never called; every decision lands in a JSONL audit log.
- Session taint: reads classified `external` taint the session; a tainted
  session may not perform `write-internal` or `egress` operations without
  an approval channel (HTTP webhook: 2xx grant, 403 refuse, anything
  else/timeout deny - the body is never parsed). Policy files are YAML
  (`version: 1`, per-tool `risk`/`taint`/`cost`).
- Capability tokens (biscuit-go/v2, Apache-2.0): least-privilege,
  time-bounded tokens checked on the hot path; forged/expired/foreign
  tokens refused with distinguishable audit rules. 50ms eval budget
  fails closed.
- DSSE-signed credential distribution: `hive-agent credential` files are
  tamper-evident (`hive-agent verify` exits non-zero on any modified
  line); the gateway consumes the public-key side.
- Swarm level -> data plane: node status (`isolate` stops all tool calls
  within one status TTL, `contain` keeps reads and freezes writes)
  reaches the gateway; self-reports can only escalate the reporter.
- Rate and budget limits (`-rate`, `-budget`): refused attempts count.
- Eval harness (`eval/`): AgentDojo 0.1.35 benchmark with the gateway
  in the loop - baseline vs gated modes, per-task gateway sessions,
  environment roundtrip over MCP, automated approval channels, GLM
  dialect adapter. Results and caveats in [docs/eval.md](docs/eval.md):
  deny-only gating 15.0% vs 32.5% unguarded utility, approval channel
  recovers to 30.0%, full approval to exact parity; injection success
  0/24 gated, but also 0/57 unguarded (model tier), so ASR reduction is
  untested at this tier.
- Documentation: `docs/gateway.md`, `docs/threat-model.md` (T1-T8),
  `docs/eval.md`, `docs/predictions.md` (P1-P6), example
  `deploy/k8s/network-policy.yaml`.
- CI test workflow and release workflow building versioned Linux/macOS/
  Windows binaries plus the container image.

### Known limitations

- Gossip and the MCP stdio data plane are unencrypted; signatures give
  integrity, not confidentiality. The admin listener (`-admin`) can reset
  taint and must stay on localhost or behind a network policy.
- One upstream MCP server per gateway process; stdio framing only.
- The eval covers the `workspace` suite on one free-tier model; the
  security half of P1 needs a model tier that actually executes
  injections (see docs/eval.md).

## 0.1.0 — first public preview

First end-to-end release: real eBPF sensor events flow through signed gossip
to a swarm decision on every node.

### Added

- `hive-agent serve`: swarm node with HTTP gossip (flooding with
  de-duplication), replay protection (acceptance window plus digest cache
  that fails closed), `/v1/status`, `/healthz`, level-change decisions as
  JSON lines on stdout and optional webhook delivery.
- Falco integration via `http_output` (`-sensor-listen`) or pipe
  (`hive-agent run`); Tetragon integration via `tetra getevents -o json`
  with operator-defined policy strengths.
- Swarm decisions: self-reports may escalate a node itself; other nodes need
  a quorum of at least `-min-voters` peers; zone-wide alert posture.
- `hive-agent init-cluster`, `keygen`, `pubkey`, `version`.
- Docker image (`scratch`, static binary, non-root) and a Compose demo with
  three nodes and Falco.
- Core libraries: pheromone field, Ed25519 envelopes, quorum and
  reputation ledger, deterministic swarm simulator (`hive-sim`).

### Known limitations

- Gossip is plain HTTP without transport encryption or peer
  authentication; integrity comes from per-signal signatures. Run it on a
  trusted network segment until mTLS lands.
- All-to-all gossip is intended for swarms of up to a few dozen nodes.
- Decisions are advisory: no enforcement adapters yet (use the webhook).
- Sensor signals describe the local node only.
