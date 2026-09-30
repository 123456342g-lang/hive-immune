# hive-immune

**Swarm-intelligence defense for enterprise networks.** Instead of one central
brain behind one wall, every node runs a small agent that senses locally,
leaves signed, decaying "threat pheromones" for its neighbours, and joins a
reputation-weighted quorum before the swarm acts.

中文说明见 [README.zh-CN.md](README.zh-CN.md)。

> Status: **0.2.0.** Real Falco and Tetragon eBPF events flow as signed
> signals over gossip to a swarm decision on every node, and the new
> `hive-gateway` gates every MCP tool call an agent makes (policy,
> taint, approval channel, capability tokens, swarm level) with a full
> audit trail. Network decisions remain advisory; the tool boundary is
> enforced. Gossip is plain HTTP with signed payloads. See
> [Known limitations](#known-limitations) before deploying.

```
tick 15   active=0   isolated=2   contained=2   false=0
....m.m...#...oo+...      #  intruder cut off by the swarm
....oo....#..mo.m..m      m  lying agent (10% of the swarm)
                          o  neighbours on alert, + contained
```

## Why

| Traditional perimeter | hive-immune |
|---|---|
| Central SIEM decides | Local agents decide collectively |
| One compromised sensor lies unnoticed | Liars lose reputation and are muted |
| Signals can be spoofed on the wire | Every signal is Ed25519-signed |
| Alerts are binary | Response is graded: observe → contain → isolate |
| A prompt-injected agent acts freely | Every MCP tool call passes the gateway's risk × taint policy first |

## Try it

### End-to-end demo (Docker, Linux kernel with BTF)

Three swarm nodes and a real Falco sensor:

```sh
docker compose -f deploy/compose/docker-compose.yml up -d --build
docker run --rm alpine cat /etc/shadow           # trips a Falco rule on "node-1"
curl -s localhost:7956/v1/status                 # node-2's view: node-1 contained, zone on alert
docker compose -f deploy/compose/docker-compose.yml logs node-3   # decisions as JSON lines
docker compose -f deploy/compose/docker-compose.yml down -v
```

Full walkthrough and production setup: [docs/quickstart.md](docs/quickstart.md).

### Gateway (gate an MCP server)

```sh
go build -o hive-gateway ./cmd/hive-gateway
hive-gateway keygen -out root.key
hive-gateway issue -agent agent-1 -key root.key -tool search_emails -out agent-1.tok
hive-gateway serve -agent agent-1 -policy tools.yaml -audit audit.jsonl -- ./my-mcp-server
```

Refusals come back to the model as ordinary tool errors; the upstream
server is never called. Full flags, policy schema and the approval
webhook: [docs/gateway.md](docs/gateway.md). Evaluated on AgentDojo in
[docs/eval.md](docs/eval.md).

### Simulator

Requires Go 1.22+.

```sh
go run ./cmd/hive-sim                     # reference scenario, maps every 10 ticks
go run ./cmd/hive-sim -every 0 -seed 7    # summary only, different seed
go run ./cmd/hive-sim -h                  # all flags
```

Every run is deterministic: the same flags always produce the same result.

### Connect a real sensor

```sh
hive-agent keygen -out node.key
falco -o json_output=true | hive-agent run -node web-1 -key node.key -source falco
```

Tetragon, safety flags and deployment notes: [docs/sensors.md](docs/sensors.md).

## Architecture

| Package | Layer | What it does |
|---|---|---|
| `pkg/pheromone` | Stigmergy | Time-decaying, spatially weighted signal field. Per-origin intensity cap stops a single agent from flooding it; future-dated signals are rejected. |
| `pkg/envelope` | Integrity | Ed25519 signing over an unambiguous, domain-separated canonical encoding. Forged or tampered signals never reach the field. |
| `pkg/quorum` | Decision | Reputation-weighted quorum with graded response levels and a minimum-voter rule. Immutable reputation ledger. |
| `pkg/sim` | Simulation | Grid network, spreading intruder, false-alarm noise and Byzantine agents that frame neighbours and forge signals. |
| `pkg/sensor` | Sensing | Parses Falco and Tetragon JSON events (untrusted input: bounded, validated, fuzzed) into signals about the local node, with host binding, time window and cooldown. |
| `pkg/keyfile` | Identity | Node key generation and storage (0600, never overwritten). |
| `pkg/cluster` | Membership | `peers.json`: members, public keys, gossip addresses, zones. |
| `pkg/swarm` | Decision | Turns the field into a level per node: self-reports, peer quorum, zone alert. |
| `pkg/node` | Runtime | Gossip over HTTP, replay protection, status API, Falco `http_output` endpoint. |
| `pkg/gateway` | Enforcement | Inline MCP `tools/call` gate: degraded → capability → rate/budget → swarm level → risk × taint, with JSONL audit and approval webhook. |
| `pkg/capability` | Least privilege | Biscuit-based session tokens bound to agent, tools and expiry. |
| `pkg/dsse`, `pkg/credential` | Distribution | Tamper-evident signed credential files (`hive-agent verify`). |
| `cmd/hive-sim` | CLI | Runs the simulator and renders the network. |
| `cmd/hive-agent` | CLI | `serve` a node, `run` a sensor pipe, `init-cluster`, `keygen`. |
| `cmd/hive-gateway` | CLI | `serve` the MCP gate, `keygen`/`issue` capability tokens. |
| `eval/` | Evidence | AgentDojo benchmark harness with the gateway in the loop ([docs/eval.md](docs/eval.md)). |

### Security properties (tested)

- **Byzantine bound:** with the default policy, attackers holding less than
  1/3 of voting weight cannot force containment of a healthy node while honest
  voters score it at or below 0.1 (property test over 5 000 random swarms).
- **No forgery:** a signal is accepted only if it verifies against the
  registered key of its claimed origin (unit tests + fuzzing).
- **Flood resistance:** one origin contributes at most `OriginCap` to any node.
- **Clock abuse:** signals more than `MaxSkew` in the future are rejected.
- **Tool-call gating (measured):** on AgentDojo's workspace suite the
  gateway refuses exactly the calls its policy targets (every utility loss
  in deny mode maps to a logged denial) and adds zero overhead under an
  approve-everything channel (32.5% = unguarded parity); injection success
  is 0/24 gated - but also 0/57 unguarded at this model tier, so ASR
  reduction awaits a model that executes injections
  ([docs/eval.md](docs/eval.md)).

## Known limitations

- **Transport:** gossip is plain HTTP. Payloads are signed and replay-checked,
  but not encrypted, and any host that can reach a node can send it (signed)
  traffic or read `/v1/status`. Keep it on a trusted segment until mTLS lands.
- **Scale:** gossip is all-to-all; intended for up to a few dozen nodes.
- **Network decisions are advisory:** they are emitted as JSON and webhooks.
  The *tool boundary* is enforced (hive-gateway refuses inline), but there is
  no Cilium/security-group adapter yet.
- **Gateway:** stdio framing only, one upstream MCP server per process, no
  transport encryption on the stdio hop; the `-admin` control plane can reset
  taint - bind it to localhost or see `deploy/k8s/network-policy.yaml`.
- Sensor signals describe the local node only; attributing activity to peers
  is planned. With only self-reports, the peer quorum path stays idle.
- In the simulator, reputation is updated from ground truth. A real deployment
  needs post-incident confirmation (analyst verdicts, canary attacks) instead.
- Detection quality degrades as the malicious share approaches 1/3 and as the
  intruder spreads faster than neighbours can detect it; tune `-field-scale`
  and `-vote-radius` and measure false isolations for your topology.
- The eval's security half is inconclusive at the tested model tier
  (unguarded ASR 0/57); re-run with a model tier that executes injections
  before quoting ASR numbers.

## Roadmap

1. ~~eBPF sensor agent (Tetragon/Falco integration)~~ — done, see [docs/sensors.md](docs/sensors.md)
2. ~~Gossip transport, replay protection and key distribution~~ — HTTP gossip and replay protection done in 0.1.0; mTLS / SPIFFE next
3. ~~Agent 行为防线: MCP gateway, taint, capability tokens, swarm level → data plane~~ — done in 0.2.0, see [docs/gateway.md](docs/gateway.md) and [docs/eval.md](docs/eval.md)
4. Human-in-the-loop approval UX (queue, digest, mobile) beyond the raw webhook
5. ASR eval on a model tier that executes injections; multi-suite policy files (travel/banking/slack)
6. Enforcement adapters (Cilium network policy, cloud security groups)
7. Deception layer (honeypot redirection on isolation)
8. TLA+ model of the quorum protocol; continuous red-team evolution

## Contributing & security

See [CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities privately as
described in [SECURITY.md](SECURITY.md), never in public issues.

## License

[Apache License 2.0](LICENSE).
