# vetlock

**Behavioral diff for npm dependency updates.** Answers the question no updater answers:
*"What does this dependency update DO now that it didn't do before?"*

vetlock reads two lockfiles (before and after an update), fetches every changed package —
including the full transitive closure — extracts the tarballs safely, and reports **capability
deltas**: new install scripts, new network endpoints, new filesystem writes, environment-token
harvesting, obfuscation jumps, integrity tampering. With provenance chains so you know exactly
which direct dependency pulled the risk in.

**Never runs any code from analyzed packages.** Static analysis over extracted tarballs only.
Zero telemetry. Your lockfiles never leave your machine.

## What it looks like

Real captured output against a defanged Shai-Hulud 2025 worm fixture in this repo:

```
vetlock diff summary
  BLOCK · 13 findings · 1 changed package · 6ms

BLOCK  11
  chalk 5.3.0 → 5.3.1
    via: my-app → chalk
    · install.script-added — Lifecycle script "postinstall" was added.
      package.json:1  postinstall: node postinstall.js
    · env.token-harvest — Package started reading sensitive env: NPM_TOKEN
      index.js:14  const token = process.env.NPM_TOKEN;
    · env.token-harvest — Package started reading sensitive env: GITHUB_TOKEN
      index.js:15  const ghToken = process.env.GITHUB_TOKEN;
    · env.token-harvest — Package started reading sensitive env: AWS_ACCESS_KEY_ID
      index.js:16  const aws = process.env.AWS_ACCESS_KEY_ID;
    · env.token-harvest — Package started reading sensitive env: whole-object process.env enumeration
      index.js:18  const envDump = Object.keys(process.env);
    · exec.new-module — Package started using process/execution module "child_process".
      index.js:1  imports child_process
    · net.new-endpoint — New network endpoint appeared: https://exfil.example.invalid/collect
      index.js:1  https://exfil.example.invalid/collect
    · net.new-endpoint — New network endpoint appeared: https://exfil.example.invalid/webhook
      postinstall.js:1  https://exfil.example.invalid/webhook

WARN  2
    · net.new-module — Package started using network module "https".
    · meta.maintainer-change — Publisher/maintainer set changed between versions.

Impact by direct dependency:
  chalk: BLOCK (13 findings in subtree)
```

Exit code `2`. See [DETECTIONS.md](docs/DETECTIONS.md) for the full replay against the corpus.

## Quick start

```bash
npx vetlock diff package-lock.before.json package-lock.after.json
```

Machine formats: `--json`, `--sarif` (upload to GitHub code-scanning), `--md` (paste as PR
comment). Exit codes: `0` clean · `1` ≥ WARN · `2` ≥ BLOCK. `--fail-on=<detector-list>` for
per-detector CI gating.

## GitHub Action

Runs vetlock on every PR that touches `package-lock.json`. Sticky PR comment + SARIF upload
to the Security tab.

```yaml
- uses: OJ-Uday/vetlock/action@v0
  with:
    fail-on: install.script-added,env.token-harvest,net.new-endpoint
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: vetlock.sarif }
```

Full recipe: [action/README.md](action/README.md).

## Why

Advisory databases (`npm audit`, Dependabot) match against **known** CVE/GHSA entries — they lag
attacks by days. Renovate/Dependabot **open** the update PRs but tell you nothing about what
the diff contains. vetlock is the review step they lack: it detects **unknown/novel** malice
via behavior change, framed as a diff so the false-positive floor is low.

We don't say *"axios uses the network"* (of course it does). We say *"axios STARTED contacting
a new domain in this update."*

## Positioning

| Tool | What it does | vetlock differentiator |
|---|---|---|
| `npm audit` / Dependabot | Match versions against known CVE/advisory DBs | Detects **unknown/novel** malice via behavior change |
| Socket.dev | Commercial SaaS behavioral analysis | Open source, self-hosted, diff-framed, zero exfil |
| `npq` | Install-time heuristics on one package | Recursive over full lockfile graph, PR-native |
| `lockfile-lint` | Lockfile hygiene (URLs, integrity) | We analyze **tarball contents**, not lockfile text |
| Dependabot/Renovate | Open the update PRs | We're their missing review step |

## Detector catalog

| Category | Detector | Severity | What it catches |
|---|---|---|---|
| INSTALL | `install.script-added` | BLOCK | Lifecycle script (pre/post/install/prepare) added |
| INSTALL | `install.script-changed` | BLOCK | Existing lifecycle script body changed |
| ENV | `env.token-harvest` | BLOCK | New reads of `NPM_TOKEN`, `GITHUB_TOKEN`, `AWS_*`, etc; or whole-object `process.env` enumeration |
| NET | `net.new-endpoint` | BLOCK | New URL literal appeared in source |
| NET | `net.new-module` | WARN | New http/https/net/fetch/websocket module imported |
| EXEC | `exec.new-module` | BLOCK | New `child_process`/`worker_threads`/`vm` import |
| FS | `fs.new-hotpath-write` | BLOCK | New fs.write targeting `.ssh`, `.npmrc`, `.git/config`, wallet paths, `/etc/*`, etc |
| INTEG | `integrity.hash-mismatch` | BLOCK | Same version, different tarball hash (registry tamper / MITM) |
| CODE | `code.dynamic-loading-added` | WARN | New `eval`, `new Function`, dynamic `require`/`import`, `vm` sink |
| OBF | `obf.entropy-jump` | WARN → BLOCK\* | Entropy jump, minification regression, or new high-entropy literals |
| META | `meta.maintainer-change` | WARN | Publisher/maintainer emails changed between versions |
| DEPS | `deps.new-direct-dep` | INFO | New direct dependency added |

\* OBF escalates to BLOCK when co-occurring with NET or INSTALL findings in the same package
(the classic worm co-occurrence).

## Design invariants (each a named test)

- **NEVER-EXECUTE canary** (`never-execute-canary.test.ts`). The soul test. Hostile fixture
  whose every file writes a sentinel if executed; analyzer runs → sentinel must not exist.
- **Closure completeness** — every changed node analyzed, no default depth limit.
- **New-node full-scan** — added transitive package analyzed absolutely (event-stream case).
- **Provenance correctness** — shortest paths root → node.
- **Diff-framing** — capabilities in both versions never fire; only deltas escalate.
- **Determinism** — same inputs → byte-identical findings JSON.
- **Integrity tripwire** — same version + different hash → BLOCK unconditionally.
- **Fail-soft parse** — unparseable source → WARN, never crash.
- **Safe extract** — zip-slip, symlinks, tarbombs rejected.

## Documentation

- [THREAT-MODEL.md](docs/THREAT-MODEL.md) — attackers we defend against; explicit non-catches
- [DETECTIONS.md](docs/DETECTIONS.md) — replay results against historical npm attacks
- [ARCHITECTURE.md](docs/ARCHITECTURE.md) — pipeline, invariants, ADRs
- [docs/adr/](docs/adr) — Architecture Decision Records (name, language, parser, fetch, NEVER-EXECUTE)
- [SECURITY.md](SECURITY.md) — how to report vulnerabilities in vetlock itself

## Status

**v0.0.0 — early alpha.** Detector coverage is deliberately narrow-and-tested rather than
broad-and-hopeful. 76 tests currently green across the workspace, including a corpus-acceptance
test that catches the defanged Shai-Hulud 2025 worm with 13 findings across 5 detector
categories. FP smoke on 3 realistic benign version bumps: 0 findings, verdict CLEAN.

Known limitations, published honestly (also in DETECTIONS.md):

- Logic bombs using capabilities the package already had are our hardest case.
- Fully dynamic loading chains where every string is computed at runtime are flagged, not
  followed.
- Baseline-scan mode (single lockfile, no diff frame) is not yet implemented.
- npm lockfiles v2/v3 only; pnpm and yarn lockfiles are on the roadmap.

## License

Apache-2.0.

## Author

Uday Ojha ([@OJ-Uday](https://github.com/OJ-Uday)). Feedback, PRs, and false-positive reports
welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).
