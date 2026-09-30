# The MCP gateway

`hive-gateway` sits between an agent and one MCP server. Every
`tools/call` is classified by a policy file, checked against the session's
state (taint, capability token, limits, swarm level), audited, and either
forwarded or refused. Everything else - `tools/list`, notifications, pings
- passes through untouched.

```
agent (MCP client) ──stdio──▶ hive-gateway ──stdio──▶ MCP server
                                │
                                ├─ tools.yaml      what each tool may do
                                ├─ audit.jsonl     what happened
                                ├─ credentials     signed copy of every decision
                                └─ admin :8787     reset taint, reload policy, tail audit
```

## Quick start

```sh
hive-gateway serve -agent a1 -policy tools.yaml -- npx -y @modelcontextprotocol/server-everything
```

Point your MCP client at the gateway instead of the server; nothing else
changes. A minimal `tools.yaml`:

```yaml
version: 1
defaults: {risk: egress, taint: external}
tools:
  read_file:    {risk: read, taint: internal}
  fetch_url:    {risk: read, taint: external}
  create_issue: {risk: write-internal, taint: internal}
  send_email:   {risk: egress, taint: internal, cost: 5}
```

## How a call is decided

The order is fixed and each step has a stable rule name that shows up in
the audit log and (optionally) as a swarm signal:

| # | Rule | What it means |
|---|------|---------------|
| 1 | `degraded.deny` | No usable policy: nothing can prove it is a read, so everything is denied. A reload failure keeps the last good policy instead. |
| 2 | `capability.*` | The session's token does not permit this call (`subject`, `expired`, `tool-out-of-scope`, `malformed`, `unauthorized`). |
| 3 | `limits.rate`, `limits.budget` | The per-agent window says stop. Denied attempts count against the rate. |
| 4 | `level.*` | Swarm verdict on this agent: `isolate` stops everything, `contain` freezes writes, `observe` pushes writes through a human. |
| 5 | `taint.egress`, `taint.write-internal` | The session has read external content; anything outward needs a human. |
| 6 | `risk.read`, `risk.write-internal`, `risk.egress` | Clean session: reads always pass, writes pass, egress passes. |

The decision is a pure function of policy, session state and identity -
the gateway never reads prompt or argument content.

## tools.yaml

```yaml
version: 1                    # required; only version 1 exists
defaults: {risk: egress, taint: external}   # optional, fail-closed if absent
tools:
  <name>: {risk: <class>, taint: <internal|external>, cost: <int>}
```

- **risk** - `read`, `write-internal` (changes state inside the
  organisation) or `egress` (data or effects leave it).
- **taint** - whether this tool's *output* can carry instructions from
  outside. A tool that does not say defaults to `external`: unread output
  taints the session rather than staying quiet.
- **cost** - what one attempt charges the session budget (`0` = free,
  negatives are rejected).

Unknown fields and unknown enum values are rejected: a typo must not
silently downgrade a tool. The file is re-read automatically when it
changes (throttled to once per second), and `POST /v1/reload` forces it.
An edit that fails to parse keeps the previous policy in effect.

## Sessions and taint

A successful call to a `taint: external` tool marks the session as having
read untrusted content. From then on `egress` and `write-internal` tools
need approval (see below). Reads are never blocked by taint.

Inspect and clear it:

```sh
curl -s localhost:8787/v1/session
curl -sX POST localhost:8787/v1/taint/reset
```

The reset is written to the audit log as `admin.taint-reset`, so a later
review can see who re-enabled egress.

## Approval webhook

Calls the decision engine marks `approve` are POSTed to `-approve` and
the client waits:

```json
POST /approve
{"session": "…", "agent": "a1", "call_id": "1", "tool": "send_email",
 "risk": "egress", "args_digest": "…",
 "reason": "session has read external content; sending data out needs a human",
 "requested_at": "2026-09-29T12:00:00Z"}
```

- any `2xx` → the call proceeds;
- `403` → refused;
- anything else, including a timeout (`-approve-timeout`, default 60s)
  → refused.

The response body is not parsed: the status code is the whole answer, so
anything that can receive a POST can be the approver (a chat bot, a
ticket bot, a `curl` one-liner).

No `-approve` means every `approve` decision becomes a deny: nobody to
ask is the same as nobody said yes.

## Capability tokens

The policy says what a tool may do; a capability token says what *this
session* may do. Only the holder of the root key can widen scope, and
anyone holding a token can narrow it further (biscuit attenuation).

```sh
hive-gateway keygen -out root.key                 # prints the public key
hive-gateway pubkey -key root.key > root.pub
hive-gateway issue -key root.key -agent a1 \
  -tool read_file -tool fetch_url -ttl 24h -out a1.cap

hive-gateway serve -agent a1 -capability a1.cap -capability-key root.pub -- …
```

The gateway verifies the token's signature chain at startup; per call it
asks three questions - is it ours, is it live, is the tool in scope - and
records which one failed as `capability.<reason>`. Without `-capability`
there is no token gate.

## Signed decision credentials

With `-credential` and `-credential-key` (another `keygen` key), every
decision is also appended to a JSONL file as a DSSE envelope signed by
the gateway. Anyone with the public key can check the file was not edited:

```sh
hive-gateway pubkey -key cred.key                      # hex public key
hive-agent verify -in credentials.jsonl -pub <hex>
ok   line 1 2026-09-29T12:00:00Z agent=a1 tool=send_email action=deny rule=taint.egress
fail line 2: credential: schema "…", want "hive-immune/gateway-decision/v1"
```

Verification needs nothing but the file and the public key, so a reviewer
or a customer can audit the trail you hand them. Arguments and results
are hashed, never stored.

## Rate and budget

```sh
hive-gateway serve -agent a1 -rate 60 -budget 500 -limit-window 1m -- …
```

- `-rate` counts *attempts* per window - a refused call still counts, so
  a looping agent cannot retry its way past the limit.
- `-budget` sums the `cost` of successful charges; a call that would
  overshoot the remaining budget is denied instead of partially paid.
- Windows are fixed and in-process: they reset on restart. Each session
  (one gateway process) has its own counters.

## Swarm feedback

Given `-node` (a local `hive-agent serve` URL), the gateway reads this
agent's response level from `/v1/status` and applies the level gate from
the table above. Levels are cached for 2s; if the node is unreachable the
last known level stays in force for up to 60s, then the gate opens
(the gateway fails *open* on stale swarm state, but keeps denying while
the cached level says so).

With `-node-key` (the gateway's own key, whose public half is listed in
`peers.json` under `-agent`), every refusal is also deposited into the
swarm as a signed self-report (`gateway.limits.rate`,
`gateway.taint.egress`, ...). Signals are posted after the reply is
written, so the client never waits for the node, and they are rate-limited
to one per rule per 30s.

## Audit log

One JSON line per decision (plus operator interventions):

```json
{"time":"…","session":"…","agent":"a1","call_id":"1","tool":"send_email",
 "risk":"egress","needs_approval":true,"tainted_before":true,"tainted_after":true,
 "action":"deny","rule":"taint.egress",
 "reason":"session has read external content; sending data out needs a human",
 "args_digest":"…","duration_ms":0}
```

`args_digest` and `result_digest` are SHA-256 of the raw JSON - enough to
prove two records refer to the same call without storing what was sent.

## Admin endpoints (`-admin 127.0.0.1:8787`)

| Method & path | Effect |
|---|---|
| `GET /healthz` | `ok` |
| `GET /v1/session` | session id, agent, taint snapshot, counters, policy state |
| `POST /v1/taint/reset` | clear the session taint (audited) |
| `POST /v1/reload` | re-read tools.yaml now |
| `GET /v1/audit?n=100` | last n audit records (1–1000) |

The admin listener is separate from the stdio data plane. Bind it to
localhost or protect it with a network policy: it can reset taint.

## Failure modes

| Situation | Behaviour |
|---|---|
| `tools.yaml` missing or invalid at startup | the gateway will not start |
| policy edit fails to reload | last good policy stays in effect, error in `/v1/session` |
| `-policy ""` | failure mode: every call denied (`degraded.deny`) |
| approval webhook down or slow | deny |
| upstream MCP server dies | its stdout reaches EOF, the gateway shuts down cleanly; in-flight calls get no response |
| swarm node unreachable | cached level for 60s, then no level gate |
| credential file unwritable | decision still made and audited; a log line notes the loss |

## Security properties

- Unclassified tools are egress and external: silence is not consent.
- Nothing in the decision path parses model output; the outcome is a
  function of configuration and session state, so it is exhaustively
  testable.
- The capability root key and the credential signing key are separate
  files; compromise of one does not forge the other.
- Signals are self-reports: they say "this gateway refused", never
  "that agent is malicious" - only the swarm's quorum rules level peers.

## Limitations (0.2)

- One upstream MCP server per gateway process; stdio framing only
  (newline-delimited JSON-RPC, no HTTP/SSE transports).
- Rate and budget windows are per process and reset on restart.
- The approval webhook is synchronous: the agent waits while a human
  answers.
- Gossip between the gateway and the node is plain HTTP; keep both on
  localhost or a trusted segment (see [quickstart](quickstart.md)).
- Arguments are hashed, not encrypted: digests leak equality of calls
  across the log.
