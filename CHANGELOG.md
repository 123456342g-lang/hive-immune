# Changelog

All notable changes are documented here. The project follows
[Semantic Versioning](https://semver.org/); before 1.0, minor versions may
contain breaking changes.

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
