# Sensor integration (Falco, Tetragon)

hive-immune does not ship its own kernel probes. It consumes the JSON event
streams of two mature eBPF runtime sensors and turns them into signed
pheromone signals about the local node:

```
Falco / Tetragon ──JSON lines──▶ hive-agent run ──signed envelopes (JSON lines)──▶ transport (roadmap)
```

Verified against **Falco 0.45.0** (modern_ebpf driver) and **Tetragon v1.7.1**
on Linux 6.18. The files in `pkg/sensor/testdata/` are real captured output.

## 1. Create a node identity

```sh
hive-agent keygen -out /etc/hive-immune/node.key   # prints the public key
hive-agent pubkey -key /etc/hive-immune/node.key   # print it again later
```

The key file is created with mode `0600` and is never overwritten. Distribute
the printed public key to the other nodes' keyrings; keep the private key on
the node.

## 2a. Falco

Run Falco with JSON output and pipe it into the agent:

```sh
falco -o json_output=true \
  | hive-agent run -node web-1 -key /etc/hive-immune/node.key -source falco -host web-1
```

Severity comes from the Falco priority:

| Priority | Strength |
|---|---|
| Emergency, Alert, Critical | 1.0 |
| Error | 0.8 |
| Warning | 0.6 |
| Notice | 0.4 |
| Informational | 0.2 |
| Debug | 0.1 |

With the default `-min 0.5`, Warning and above become signals.

The signal kind is `falco.<rule>`, e.g. `falco.Read sensitive file untrusted`.

## 2b. Tetragon

Tetragon emits telemetry, not alerts, so you decide which TracingPolicies
matter and how strongly. Example policies are in `deploy/tetragon/`:

| Policy | What it watches | Suggested strength |
|---|---|---|
| `hive-sensitive-files` | opens of `/etc/shadow`, `/etc/sudoers`, `/root/.ssh` | 0.8 |
| `hive-tcp-connect` | every outbound TCP connection | 0.1 (telemetry only) |

```sh
tetra getevents -o json \
  | hive-agent run -node db-1 -key /etc/hive-immune/node.key -source tetragon \
      -policy hive-sensitive-files=0.8 -policy hive-tcp-connect=0.1
```

Events from policies not listed with `-policy`, and `process_exec` /
`process_exit` events, are skipped. The agent can also read Tetragon's JSON
export file with `-in <path>`.

## Output

One JSON envelope per line on stdout:

```json
{"signal":{"origin":"web-1","subject":"web-1","kind":"falco.Read sensitive file untrusted","strength":0.6,"at":"2026-09-28T11:41:30.689722198Z"},"signature":"DA89lAQY...AA=="}
```

When input ends, a summary goes to stderr:

```
hive-agent: lines=8 emitted=1 skipped=3 throttled=4 rejected=0 malformed=0
```

## Safety controls

| Flag | Default | Purpose |
|---|---|---|
| `-host` | (any) | Only accept events reported for this host name, so a misrouted stream cannot make one node report on another |
| `-min` | 0.5 | Drop weaker events |
| `-cooldown` | 10s | At most one signal per kind per cooldown, unless stronger |
| `-max-age` | 5m | Drop old events, e.g. when replaying logs |

Also enforced, and not configurable: lines longer than 1 MiB are discarded,
rule names are limited to 128 bytes of printable UTF-8, events more than 5 s
in the future are rejected, and cooldown state is capped at 4096 kinds.

## Operational notes (found during verification)

- **Falco in a container reports the container ID as `hostname`.** Set the
  container's hostname to the node name (Kubernetes does this for
  `hostNetwork` pods), or omit `-host`.
- **Tetragon on Docker Desktop / WSL2** cannot see the host procfs, so
  process details (binary, arguments) may be missing. The agent does not rely
  on them.
- **`tetra getevents` buffers when writing to a file.** Stop it with SIGINT,
  not SIGTERM, or the last events are lost.
- **Windows PowerShell 5.1 prepends a UTF-8 BOM** when piping into a native
  program; the agent strips it.
- **Tetragon v1.7** rejects `returnArgAction: Post` in TracingPolicies that
  older examples still use.

## Not yet covered

Signals currently describe the local node only. Attributing activity to
peers (e.g. inbound connections from another node) needs an IP-to-node
inventory and is planned together with the gossip transport.
