# vetlock

**Behavioral diffing for npm dependency updates.** Answers the question no updater answers:
*"What does this dependency update DO now that it didn't do before?"*

vetlock reads two lockfiles (before and after an update), fetches every changed package —
including the full transitive closure — extracts the tarballs safely, and reports **capability
deltas**: new install scripts, new network endpoints, new filesystem writes, environment-token
harvesting, obfuscation jumps, integrity tampering. With provenance chains so you know exactly
which direct dependency pulled the risk in.

**Never runs any code from analyzed packages.** Static analysis over extracted tarballs only.
Zero telemetry. Your lockfiles never leave your machine.

## Quick start

```
npx vetlock diff package-lock.before.json package-lock.after.json
npx vetlock diff pkg@1.2.0 pkg@1.2.1        # resolves both trees itself
npx vetlock scan package-lock.json          # baseline mode
```

Exit codes: `0` clean · `1` ≥ WARN · `2` ≥ BLOCK. Machine formats: `--json`, `--sarif`, `--md`.

## Why

Advisory databases (npm audit, Dependabot) match against **known** CVE/GHSA entries — they lag
attacks by days. Renovate/Dependabot **open** the update PRs but tell you nothing about what
the diff actually contains. vetlock is the review step they lack: it detects **unknown/novel**
malice via behavior change, framed as a diff so the false-positive floor is low.

We don't say *"axios uses the network"* (of course it does). We say *"axios STARTED contacting a
new domain in this update."*

## Positioning

| Tool | What it does | vetlock differentiator |
|---|---|---|
| `npm audit` / Dependabot | Match versions against known CVE/advisory DBs | Detects **unknown/novel** malice via behavior change |
| Socket.dev | Commercial SaaS behavioral analysis | Open source, self-hosted, diff-framed, zero exfil |
| `npq` | Install-time heuristics on one package | Recursive over full lockfile graph, PR-native |
| `lockfile-lint` | Lockfile hygiene | We analyze **tarball contents**, not lockfile text |
| Dependabot/Renovate | Open the update PRs | We're their missing review step |

## Documentation

- [THREAT-MODEL.md](docs/THREAT-MODEL.md) — attackers we defend against, and what we don't catch
- [DETECTIONS.md](docs/DETECTIONS.md) — replay results against historical npm attacks
- [ARCHITECTURE.md](docs/ARCHITECTURE.md) — pipeline, invariants, tests
- [docs/adr/](docs/adr) — Architecture Decision Records

## Status

Early alpha. Detector coverage is deliberately narrow-and-tested rather than broad-and-hopeful;
[DETECTIONS.md](docs/DETECTIONS.md) publishes catches AND misses honestly.

## License

Apache-2.0
