# Contributing to hive-immune

Thanks for helping build a better swarm defense.

## Ground rules

- Security issues go through [SECURITY.md](SECURITY.md), never public issues.
- Be respectful; see the [Code of Conduct](CODE_OF_CONDUCT.md).
- By contributing you agree your work is licensed under Apache-2.0.

## Development

Requires Go 1.22+.

```sh
gofmt -l .                  # must print nothing
go vet ./...
go test -race ./...
go test ./pkg/envelope -run '^$' -fuzz FuzzOpen -fuzztime 30s
```

CI runs the same checks on Linux, Windows and macOS and enforces **80% total
test coverage**.

## Pull requests

1. Open an issue first for anything larger than a small fix.
2. Write the test first; each bug fix must add a regression test.
3. Keep functions small and packages focused; prefer immutable values.
4. Use [Conventional Commits](https://www.conventionalcommits.org/):
   `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`, `perf:`, `ci:`.
5. Changes to thresholds or scoring must include simulation results across
   several seeds (contained runs, compromised nodes, false isolations), since
   small changes can trade detection for false isolations.

## Design principles

- **No single point of trust.** Nothing one agent says can trigger strong
  action alone.
- **Verify before use.** Unsigned or malformed input never reaches the field.
- **Bounded everything.** Memory, time skew and per-origin influence all have
  limits.
- **Deterministic simulation.** Same config, same result, so regressions are
  reproducible.
