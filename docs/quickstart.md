# Quickstart

## 1. End-to-end demo with Docker

Requirements: Docker with a Linux kernel that exposes BTF
(`/sys/kernel/btf/vmlinux`; any recent distribution, Docker Desktop on WSL2
works). The demo runs three swarm nodes and a real Falco sensor on "node-1".

```sh
docker compose -f deploy/compose/docker-compose.yml up -d --build
```

> If the repository path contains non-ASCII characters, Docker Compose's
> build may fail with `header key "x-docker-expose-session-sharedkey"
> contains value with non-printable ASCII characters`. Build the image first
> and start without `--build`:
>
> ```sh
> docker build -t hive-immune:0.1.0 --build-arg VERSION=0.1.0 .
> docker compose -f deploy/compose/docker-compose.yml up -d
> ```

> If a host port is taken (`failed to bind host port ... address already in
> use`), pick others: `HIVE_PORT_1=27946 HIVE_PORT_2=27956 HIVE_PORT_3=27966
> docker compose ... up -d`. On Windows, check
> `netsh int ipv4 show dynamicport tcp`: if the dynamic range starts low,
> outbound connections can briefly occupy the default ports.

Trigger a Falco rule (Falco watches every container on the host). Give
Falco 20–30 seconds after start-up to attach its eBPF probes first; events
before that are not seen:

```sh
docker compose -f deploy/compose/docker-compose.yml logs falco | grep -m1 "TOCTOU\|Starting"   # probes loading
docker run --rm alpine cat /etc/shadow
```

Within a few seconds every node agrees:

```sh
curl -s localhost:7946/v1/status   # node-1
curl -s localhost:7956/v1/status   # node-2
curl -s localhost:7966/v1/status   # node-3
```

```json
{"node":"node-2","members":[
  {"node":"node-1","level":"contain","self_score":0.45,"reason":"self-report"},
  {"node":"node-2","level":"observe","reason":"zone alert: node-1"},
  {"node":"node-3","level":"observe","reason":"zone alert: node-1"}], ...}
```

Each node also prints level changes as JSON lines:

```sh
docker compose -f deploy/compose/docker-compose.yml logs node-3
```

Repeated alerts escalate node-1 to `isolate`; when the evidence decays
(half-life 2 minutes) the levels fall back to `none`. Clean up with:

```sh
docker compose -f deploy/compose/docker-compose.yml down -v
```

## 2. Production setup

### Identities

On **each** node, create its key; the private key never leaves the node:

```sh
hive-agent keygen -out /etc/hive-immune/node.key     # prints the public key
```

Collect the public keys into one `peers.json` and distribute it to every
node (configuration management, a ConfigMap, ...):

```json
{"members": [
  {"id": "web-1", "public_key": "<hex>", "addr": "http://10.0.1.11:7946", "zone": "prod-web"},
  {"id": "web-2", "public_key": "<hex>", "addr": "http://10.0.1.12:7946", "zone": "prod-web"},
  {"id": "db-1",  "public_key": "<hex>", "addr": "http://10.0.2.21:7946", "zone": "prod-db"}
]}
```

Unknown fields are rejected, so typos fail loudly. Only members listed here
can sign signals that others accept.

### Run a node

```sh
hive-agent serve -node web-1 -key /etc/hive-immune/node.key -cluster /etc/hive-immune/peers.json \
  -listen 10.0.1.11:7946 -sensor-listen 127.0.0.1:7947 -webhook https://soar.example.com/hive
```

Point Falco at the local sensor listener (in `falco.yaml` or with `-o`):

```yaml
json_output: true
http_output:
  enabled: true
  url: http://127.0.0.1:7947/v1/sensor/falco
```

For Tetragon, pipe its events into the node instead:

```sh
tetra getevents -o json | hive-agent run -node web-1 -key /etc/hive-immune/node.key \
  -source tetragon -policy hive-sensitive-files=0.8 -push http://127.0.0.1:7946
```

### Decisions

Every level change is written to stdout and, with `-webhook`, POSTed as:

```json
{"time":"...","node":"web-1","from":"none","to":"contain",
 "status":{"node":"web-1","level":"contain","self_score":0.45,"peer_score":0,"voters":0,"reason":"self-report"}}
```

| Level | Suggested action |
|---|---|
| `observe` | raise logging and sampling, notify on-call |
| `contain` | restrict network access (micro-segmentation), force re-authentication |
| `isolate` | cut the node off, preserve evidence |

hive-immune 0.1 does not enforce these itself; wire the webhook to your
SOAR, firewall or orchestration tooling.

### Key flags

| Flag | Default | Meaning |
|---|---|---|
| `-min-voters` | 3 | distinct peers needed to contain *another* node (collusion threshold) |
| `-field-scale` | 1 | evidence for a ~63% score; raise it to require more evidence |
| `-half-life` | 2m | how fast evidence fades |
| `-max-age` | 10m | replay window: older signals are rejected |
| `-interval` | 2s | evaluation period |

### Network security

Gossip is plain HTTP in 0.1. Every signal is signed and replay-checked, but
traffic is not encrypted and `/v1/status` is readable by anyone who can
reach the port. Restrict port 7946 to cluster members with a firewall or
network policy, and never expose the sensor listener beyond `127.0.0.1`.
