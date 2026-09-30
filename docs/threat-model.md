# Threat model

What hive-immune defends, from whom, and what it deliberately does not
attempt. Threats are numbered (T1…) and referenced from code comments and
[predictions.md](predictions.md).

## Assets

1. **The agent session** - the integrity of what the agent does with its
   tools: which records it writes, which mail it sends, what it runs.
2. **The organisation's egress** - nothing leaves (network, mail,
   ticketing, shell) without either a clean session or a human.
3. **The evidence** - the audit trail must survive as proof of what was
   decided, and keep saying so after the fact.
4. **The swarm's judgement** - response levels about nodes must reflect
   real signals, not attacker-chosen ones.

## Trust boundaries

```
 untrusted                     │ gateway (trusted)            │ operator
───────────────────────────────┼──────────────────────────────┼──────────
 web pages, e-mail, API        │ tools.yaml                   │ root keys
 responses, tool output ─────▶ │ capability/credential keys   │ approval webhook
 model / MCP client            │ session state, audit log ───▶│ peers.json
      │                        │         │                    │
      └── stdio ──▶ hive-gateway ◀── stdio ──▶ MCP server ◀───┘ tools
```

- **Model and MCP client**: assumed honest *in structure* (they speak
  correct JSON-RPC) but free to call any tool at any time. The gateway
  never trusts them to ask permission first.
- **Tool output**: fully untrusted. It may carry hostile instructions
  (T1); reading it changes the session's state (taint), never the
  policy.
- **Policy, keys, peers.json**: operator-controlled. Whoever can edit
  them owns the gateway - that is a boundary, not a threat we mitigate.
- **Swarm nodes**: trusted for their *signature* (peers.json), not for
  their *content*: a signed signal is evidence, and levelling a peer
  still requires the quorum rules.

## Threats

| ID | Threat | Control | Enforced in |
|----|--------|---------|-------------|
| T1 | **Indirect prompt injection**: hostile instructions enter through data the agent reads | Reading external content taints the *session*; internal writes and egress then need a human. The injection is never detected - its effect is gated | `pkg/taint`, rules `taint.*` |
| T2 | **Over-privileged tool use**: the agent calls tools outside its task | Classification (`tools.yaml`) plus, per session, a capability token naming the exact tools, subject and expiry | `pkg/gateway`, `pkg/capability` |
| T3 | **Exfiltration through legitimate tools**: a clean-looking tool ships data out | Egress is its own risk class; a tainted session cannot reach it without approval; `-budget` bounds how much can go | rule `taint.egress`, `limits.*` |
| T4 | **Audit tampering**: editing or truncating the evidence after the fact | Append-only JSONL plus an independent DSSE-signed copy per decision; verification needs only the public key | `pkg/credential`, `hive-agent verify` |
| T5 | **Forged or stolen capability tokens / credentials** | Ed25519 signature chains verified at startup; tokens carry subject and TTL; keys are separate files with 0600 permissions | `pkg/capability`, `pkg/dsse`, `pkg/keyfile` |
| T6 | **Resource exhaustion**: loops or expensive tools burn money | Per-agent rate (counting attempts) and budget windows | `pkg/gateway` limits |
| T7 | **Byzantine swarm peers**: a compromised node lies about others | Signal signatures + replay window, self-reports can only escalate the reporter, containment needs a quorum of distinct peers | `pkg/envelope`, `pkg/quorum` |
| T8 | **Sensor spoofing / replay**: forged or repeated eBPF events | Sensor endpoints are localhost-only, signals are signed and checked against acceptance window + digest cache (fails closed) | `pkg/sensor`, `pkg/node` |

The gateway covers T1–T6 at the session level; the swarm (0.1) covers
T7–T8 at the node level. They compose: a gateway refusal can become a
signed self-report (T1 evidence) that raises its node's level, which then
gates the same agent harder via `-node`.

## Non-goals

- **Detecting** prompt injection in content. Unsolvable in general; the
  design converts detection into gating (see taint's package comment).
- **Containing a hostile model with no tools.** Without a tool, the model
  can only talk to its user.
- **An insider with the root keys or shell on the gateway host.** Keys
  are 0600 and the container is non-root, but file-system compromise
  equals policy compromise.
- **Encryption of gossip or stdio.** Signatures give integrity, not
  confidentiality; run both on a trusted segment (0.1 limitation, mTLS
  planned).
- **Multi-tenant isolation.** One gateway process serves one session;
  tenants need separate processes.

## Residual risks

- Taint is per session: a new session starts clean by definition. An
  attacker who can restart the agent clears taint (audit shows the new
  session id).
- Approval fatigue: every gated call blocks a human; operators under
  pressure grant everything. Rate/budget still hold (T6), but T1/T3 then
  depend on the human.
- The swarm fails *open* if it is silent for over 60s: the gateway
  prefers letting a clean session work over freezing it when the node is
  down. Cached levels keep enforcing while fresh.
- Cost windows are in-process: a restart resets them.
- Digests in the audit log leak equality of repeated calls (not content).
