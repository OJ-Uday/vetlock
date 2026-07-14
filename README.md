<div align="center">

# 🔒 vetlock

**Behavioral diff for npm dependency updates.**
*What does this update DO now that it didn't do before?*

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Node ≥ 20](https://img.shields.io/badge/node-%E2%89%A5%2020-brightgreen)](package.json)
[![Tests: 410 passing](https://img.shields.io/badge/tests-410%20passing-brightgreen)](#tests)
[![Corpus: 12/13 caught](https://img.shields.io/badge/corpus-12%2F13%20caught-brightgreen)](docs/DETECTIONS.md)
[![Benchmark: 92.3%](https://img.shields.io/badge/benchmark-92.3%25-brightgreen)](https://github.com/OJ-Uday/vetlock-benchmark)
[![Red-team: 37/48 exploits closed](https://img.shields.io/badge/red--team-37%2F48%20closed-brightgreen)](docs/REDTEAM-2026-07-12.md)
[![Zero telemetry](https://img.shields.io/badge/telemetry-zero-blue)](#privacy)
[![NEVER-EXECUTE canary](https://img.shields.io/badge/canary-NEVER--EXECUTE-red)](docs/adr/0005-never-execute.md)
[![npm provenance](https://img.shields.io/badge/npm-provenance-blueviolet)](https://docs.npmjs.com/generating-provenance-statements)

</div>

---

## Try it in 10 seconds

```bash
npx vetlock demo
```

That's it. No install, no config, no network. You'll see vetlock replay the **Shai-Hulud 2025** worm attack against a bundled defanged fixture and produce 13 findings (BLOCK):

```
vetlock diff summary
  BLOCK · 13 findings · 1 changed package · 3ms

BLOCK  13
  chalk 5.3.0 → 5.3.1
    via: my-app → chalk
    · env.token-harvest — Package started reading sensitive env: NPM_TOKEN
      index.js:14  const token = process.env.NPM_TOKEN;
    · env.token-harvest — Package started reading sensitive env: whole-object process.env enumeration
      index.js:18  const envDump = Object.keys(process.env);
    · exec.new-module — Package started using process/execution module "child_process".
      index.js:1  imports child_process
    · fs.new-hotpath-write — New file-system write to sensitive path: /.npmrc
      index.js:1  fs.writeFile("/.npmrc", ...)
    · install.script-added — Lifecycle script "postinstall" was added.
      package.json:1  postinstall: node postinstall.js
    · meta.maintainer-change — Publisher/maintainer set changed between versions.
      package.json:1  maintainers: [team@chalk.example] → [attacker@example.invalid]
    · net.new-endpoint — New network endpoint appeared: https://exfil.example.invalid/collect
      index.js:1  https://exfil.example.invalid/collect
    ... (13 findings total)

Impact by direct dependency:
  chalk: BLOCK (13 findings in subtree)
```

**Exit code 2.** Ready to plug into CI.

To run it against your own lockfiles:

```bash
npx vetlock diff package-lock.before.json package-lock.after.json
```

---

## Table of contents

- [What vetlock does](#what-vetlock-does)
- [Why (positioning vs `npm audit`, Socket, Dependabot)](#why)
- [Zero-effort quickstart](#zero-effort-quickstart)
- [Detector catalog](#detector-catalog)
- [Design invariants](#design-invariants)
- [Hardening against real-world evasion (v0.3.0)](#hardening-against-real-world-evasion-v030)
- [Corpus & detection results](#corpus--detection-results)
- [Output formats](#output-formats)
- [GitHub Action](#github-action)
- [Configuration (`.vetlock.json`)](#configuration-vetlockjson)
- [Tests](#tests)
- [Architecture](#architecture)
- [Privacy](#privacy)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

---

## What vetlock does

vetlock reads two lockfiles (before and after a dependency update), fetches every changed package (including the **full transitive closure**), safely extracts each tarball, and reports **capability deltas**:

- ✅ **New install scripts** added (`preinstall`, `postinstall`, `prepare`, etc.)
- ✅ **New network endpoints** — URL literals appearing in source, including those recovered from base64/hex/rot13-decoding
- ✅ **New filesystem writes** to sensitive paths (`.ssh`, `.npmrc`, `.git/config`, `~/Desktop/*`, `/etc/*`, wallet paths)
- ✅ **Environment-token harvest** — new reads of `NPM_TOKEN`, `GITHUB_TOKEN`, `AWS_*`, or whole-object `process.env` enumeration
- ✅ **Native binary artifacts** shipped in tarballs (`.node`, `.so`, `.dylib`, `.dll`, `.exe`, `.wasm`)
- ✅ **Obfuscation jumps** — entropy increases, minification regressions, new high-entropy literals
- ✅ **Integrity tampering** — same version with a different tarball hash (MITM / registry compromise)
- ✅ **Publisher takeovers** — maintainer-email changes crossed against a built-in trust store
- ✅ **Typosquat candidates** — new deps whose names are Damerau-Levenshtein distance ≤ 2 from ~330 curated high-download package names
- ✅ **Known-vulnerable versions** — cross-referenced against a curated GHSA subset (plus ±3 patch / ±1 minor adjacency for "just above the fix" attacker versions)
- ✅ **Lockfile-identity attacks** — workspace-shadowing (`"link": true`), yarn/pnpm `npm:` aliases, non-registry sources (git+ / github: / bitbucket:), absolute-`file:` sources

Every finding carries **provenance**: the shortest path root → direct dep → transitive → offender, so you know which of *your* dependencies pulled the risk in.

**vetlock never runs any code from analyzed packages.** Static analysis over extracted tarballs only. This invariant is defended by a canary test that fails the build if it's ever violated ([ADR 0005](docs/adr/0005-never-execute.md), [`never-execute-canary.test.ts`](packages/core/test/never-execute-canary.test.ts)).

---

## Why

Advisory databases (`npm audit`, Dependabot alerts) match against **known** CVE/GHSA entries — they lag zero-day supply-chain attacks by days. Renovate and Dependabot **open** the update PRs but tell you nothing about what the diff contains. vetlock is the review step they lack: it detects **unknown/novel** malice via behavior change, framed as a diff so the false-positive floor is low.

We don't say *"axios uses the network"* (of course it does). We say *"axios STARTED contacting a new domain in this update, and its postinstall script that didn't exist yesterday now reads `~/.npmrc`."*

### Positioning

| Tool | What it does | How vetlock differs |
|---|---|---|
| `npm audit` / Dependabot | Match versions against known CVE/GHSA DBs | Detects **unknown/novel** malice via behavior change |
| Socket.dev | Commercial SaaS behavioral analysis | Open-source, self-hosted, diff-framed, **zero exfil**, no auth wall |
| Snyk | Commercial vulnerability scanning | Focuses on known CVEs; vetlock catches active supply-chain attacks in the diff |
| `npq` | Interactive install-time prompt on one package | Recursive over full lockfile graph, PR-native, CI-native |
| `lockfile-lint` | Lockfile hygiene (URL patterns, integrity presence) | vetlock analyzes **tarball contents**, not just lockfile text |
| Dependabot / Renovate | Open the update PRs | vetlock is their **missing review step** |

vetlock complements — not replaces — advisory scanning. Use `npm audit` for known CVEs; use vetlock as the reviewer of the update itself.

---

## Zero-effort quickstart

```bash
# 1. Try the bundled demo (Shai-Hulud 2025 worm, replayed against a defanged fixture)
npx vetlock demo

# 2. Diff two lockfiles from your repo
npx vetlock diff package-lock.before.json package-lock.after.json

# 3. In CI — machine-readable output for gating
npx vetlock diff before.json after.json --json > vetlock.json
npx vetlock diff before.json after.json --sarif > vetlock.sarif   # → upload to GitHub code-scanning
npx vetlock diff before.json after.json --md > vetlock-comment.md # → paste as sticky PR comment
```

**Exit codes**

| Code | Meaning |
|---|---|
| `0` | CLEAN — no findings ≥ INFO |
| `1` | ≥ 1 WARN finding |
| `2` | ≥ 1 BLOCK finding, OR any detector matched `--fail-on=...` |
| `3` | Analyzer itself errored (fail-closed) |

**Per-detector CI gating.** `--fail-on install.script-added,env.token-harvest,net.new-endpoint` forces exit `2` if any of those detectors fire, even if their base severity is WARN.

### Install locally

```bash
npm install --save-dev vetlock
# then
npx vetlock ...
```

Or globally: `npm install -g vetlock`.

---

## Detector catalog

**17 built-in detectors across 10 categories.** All severities are the **default**; escalation rules (below) can promote WARN/INFO → BLOCK when signals co-occur.

| Category | Detector | Default | What it catches |
|---|---|---|---|
| **INSTALL** | `install.script-added` | BLOCK | Lifecycle script (`pre/postinstall`, `prepare`) added between versions |
| **INSTALL** | `install.script-changed` | BLOCK | Existing lifecycle script body changed |
| **INSTALL** | `bin.new-native-artifact` | BLOCK | New `.node`/`.exe`/`.dll`/`.so`/`.dylib`/`.wasm` shipped in tarball |
| **ENV** | `env.token-harvest` | BLOCK | New reads of `NPM_TOKEN`, `GITHUB_TOKEN`, `AWS_*`, `HOME`, `USER`, `.ssh` — or **whole-object `process.env` enumeration** (via destructure / spread / `for-in` / `Reflect.ownKeys` / `Reflect.get`) |
| **NET** | `net.new-endpoint` | BLOCK | New URL literal appeared in source (~50 TLDs including top-abused: `.top`, `.pw`, `.zip`, `.click`, `.icu`, `.site`, `.cloud`, `.stream`) |
| **NET** | `net.encoded-endpoint` | BLOCK | URL recovered from base64/hex/rot13-decoding a suspicious literal |
| **NET** | `net.new-module` | WARN | New `http`/`https`/`net`/`ws`/`fetch`/`undici`/`dns` module imported |
| **EXEC** | `exec.new-module` | BLOCK | New `child_process`/`worker_threads`/`vm`/`inspector`/`async_hooks`/`trace_events` import |
| **FS** | `fs.new-hotpath-write` | BLOCK | New `fs.write` to sensitive paths (`.ssh`, `.npmrc`, `.git/config`, wallet dirs, `/etc`, `~/Desktop`) |
| **FS** | `fs.new-hotpath-read` | BLOCK | New `fs.read` of the same sensitive paths (secret-file exfil) |
| **INTEG** | `integrity.hash-mismatch` | BLOCK | Same version, different tarball hash → registry tamper / MITM |
| **CODE** | `code.dynamic-loading-added` | WARN | New `eval`, `new Function`, dynamic `require`/`import`, `vm` sink |
| **OBF** | `obf.entropy-jump` | WARN → BLOCK\* | Entropy jump, minification regression, or new high-entropy literals in an existing file |
| **OBF** | `obf.new-obfuscated-file` | WARN → BLOCK\* | New file that ships minified or with suspicious high-entropy literals |
| **META** | `meta.maintainer-change` | WARN → BLOCK\* | Publisher/maintainer emails changed between versions (BLOCK when trusted publishers dropped to empty) |
| **DEPS** | `deps.new-direct-dep` | INFO | New direct dependency added |
| **DEPS** | `deps.typosquat-candidate` | WARN → BLOCK\* | New dep whose name is edit-distance ≤ 2 from a curated top-330 name (Damerau-Levenshtein — catches transpositions like `debgu`) |
| **DEPS** | `deps.workspace-shadowing` | WARN → BLOCK | `"link": true` entry collides with a known high-value package name |
| **DEPS** | `deps.aliased-name` | WARN | Yarn/pnpm `npm:` alias — declared name resolves to a different real package |
| **DEPS** | `deps.non-registry-source` | WARN | `git+`, `github:`, `bitbucket:`, `gitlab:` resolved URL |
| **DEPS** | `deps.local-source` | INFO | Absolute `file:` resolved URL (attacker-controlled local .tgz) |
| **DEPS** | `deps.first-version-cluster` | INFO | Brand-new npm namespace with clustered version publish shape |

**\* Escalation rules.** vetlock promotes findings from WARN → BLOCK when signals co-occur, on the theory that novel malice usually pulls multiple levers at once:

- OBF/WARN → BLOCK when the same package also has any NET/INSTALL/EXEC/ENV/FS finding
- Typosquat/WARN → BLOCK with a BLOCK-tier capability OR 2+ WARN findings across 2+ categories
- Compound-3 rule: any WARN → BLOCK when the package has ≥3 findings OR ≥2 across ≥2 security-relevant categories

---

## Design invariants

Each invariant is codified as a named test that fails the build if violated:

- **`NEVER-EXECUTE canary`** ([`never-execute-canary.test.ts`](packages/core/test/never-execute-canary.test.ts)) — the soul test. A hostile fixture whose every file writes a sentinel if executed; runs vetlock; **sentinel must not exist**.
- **Closure completeness** — every changed node analyzed, no default depth limit.
- **New-node full-scan** — added transitive package analyzed absolutely (event-stream flatmap-stream case).
- **Provenance correctness** — shortest paths root → node.
- **Diff-framing** — capabilities present in *both* versions never fire; only deltas escalate.
- **Determinism** — same inputs → byte-identical findings JSON.
- **Integrity tripwire** — same version + different hash → BLOCK unconditionally.
- **Fail-soft parse** — unparseable source → WARN, never crash.
- **Safe extract** — zip-slip, symlinks, tarbombs, mode-bit shenanigans rejected.
- **Fail-closed on analyzer crash** ([S10](docs/REDTEAM-2026-07-12.md)) — analyzer timeout / uncaught throw → BLOCK, never a silent CLEAN.

---

## Hardening against real-world evasion (v0.3.0)

vetlock was subjected to a **six-agent red-team review** using two rounds of parallel adversaries (partitioned across Language, Format, System, Compositional, Defender, and Novel-vector territories) with an adversarial verification pass configured to default to **REFUTED**. The output: 35 confirmed exploits documented in [`docs/REDTEAM-2026-07-12.md`](docs/REDTEAM-2026-07-12.md).

**v0.3.0 closes 31 of 35 confirmed exploits.** Each fix has a dedicated regression test. Highlights:

<details>
<summary><b>Dataflow evasion (10 exploits) — click to expand</b></summary>

| ID | Attack shape | Fix |
|---|---|---|
| L1 | `const { NPM_TOKEN } = process.env` | Track `ObjectPattern` destructure of `process.env` |
| L2 | Whole-object enumeration via `...process.env`, `for-in`, `Reflect.ownKeys` | Extended `MemberExpression` visitor + Reflect handling |
| L3 | `require.call`, `require.apply`, `Module._load`, `process.mainModule.require` | Extended `CallExpression` visitor |
| L4 | URLs on `.top`/`.pw`/`.zip`/`.icu` (uncatalogued TLDs) | `URL_REGEX` broadened from 15 → ~50 TLDs |
| L5 | `Reflect.get(process.env, 'X')`, `Reflect.get(process, 'env')` alias | Reflect-aware alias binding + env-key resolution |
| L6 | Fail-soft required across every traversal path | `@babel/traverse` wrapped in defensive `try/catch` |
| L8 | Computed `process["env"]` obscured behind fold-resolvable expressions | Constant-fold before member-access resolution |
| L9 | Deep-nested alias chains (>3 hops) | Iterative resolution, depth-bounded to prevent DoS |
| L10 | `eval("require('x')")`, `new Function("require('x')")` | Bounded recursive parse of string args to dynamic sinks |
| L11 | `String.fromCharCode + charCodeAt` (rot13-style char arithmetic) | Co-occurrence check emits `char-arithmetic-decoder` + promotes literals |

</details>

<details>
<summary><b>Format / lockfile identity (6 exploits)</b></summary>

| ID | Attack shape | Fix |
|---|---|---|
| F1 | Lockfile-identity mismatch general | Universal parser routing; workspace-links surfaced |
| F2 | `"link": true` invisibility trick | `workspaceLinks[]` recorded on `LockGraph`; shadow-detector emits WARN/BLOCK |
| F6 | yarn/pnpm `npm:` alias hides real package name | `NpmAlias` recorded; `deps.aliased-name` WARN |
| C3 | Version just above known-vulnerable range | `adjacentAdvisories()` — ±3 patch / ±1 minor probe |
| C5 | Case-varied package names (`Lodash` vs `lodash`) bypass trust/advisory lookups | `parseLockfile` lowercases at ingest |
| N5 | Non-registry sources (git+, github:, etc.) | `deps.non-registry-source` WARN |

</details>

<details>
<summary><b>System-level & config trust (7 exploits)</b></summary>

| ID | Attack shape | Fix |
|---|---|---|
| S1 | Cache-poisoning via crafted snapshot | **HMAC-authenticated cache** — 32-byte per-install key, canonical-JSON envelope, legacy format silently ignored |
| S2 | Config-injection via .vetlock.json in the diff | zod schema + `NON_EMPTY_STRING` refinements + trust-check semantics |
| S3 | Publisher trust-store domain match too permissive | Parse-based email matching (local@domain), exact-domain-or-subdomain rules |
| S4 | Analyzer path traversal from lockfile-controlled paths | Path canonicalization + boundary check |
| S6 | Trusted publisher replaced by EMPTY maintainers field | `meta.maintainer-change` emits BLOCK on populated → empty when old was trusted |
| S9 | Absolute `file:` resolved URL exfil vector | `deps.local-source` INFO on added-only |
| S10 | Analyzer timeout / crash silently returns CLEAN | Fail-closed — any uncaught throw becomes `analysis.failed` BLOCK |

</details>

<details>
<summary><b>Novel vectors (4 exploits)</b></summary>

| ID | Attack shape | Fix |
|---|---|---|
| N1 | `bundledDependencies` — inner `node_modules` invisible to file scanner | Recursive analyzer descends every `node_modules/` in tarballs; `deps.bundled-inner-package` DEPS finding |
| N2 | Debug/tracing modules used for RCE (`inspector`, `async_hooks`) | Added to `EXEC_MODULES` |
| N3 | Covert exfil via `dns.lookup` | Added to `NETWORK_MODULES` |

</details>

<details>
<summary><b>Detector coverage (4 exploits)</b></summary>

| ID | Attack shape | Fix |
|---|---|---|
| D1 | Config schema too permissive on empty strings | zod `NON_EMPTY_STRING` refinements |
| D2 | Escalation gates over-restrictive | Compound-3 rule relaxed to trigger on 2+ WARN in 2+ categories |
| D3 | Escalation gates required specific category co-occurrence | Any security-relevant category counts |
| D6 | Typosquat corpus (~230 names) too narrow | Expanded to ~330 names — AI SDKs, payments, Sentry, NestJS, cloud, auth, comms, testing ecosystem |

</details>

The four remaining exploits are the hardest cases (fully dynamic loading chains, logic sabotage using pre-existing capabilities) — documented honestly in `docs/DETECTIONS.md`, on the roadmap as R&D.

**All fixes obey the [Security Decisions principle](docs/SECURITY-DECISIONS.md):** when correctness and performance conflict on a security boundary, correctness wins. Full rationale for using `damerau-levenshtein` over `fastest-levenshtein` (catching pure-transposition typos like `debgu → debug`) is documented as a worked example.

---

## Corpus & detection results

vetlock ships **13 supply-chain attack fixtures** — 10 real historical attacks, 3 synthetic — that are replayed on every test run. See [`docs/DETECTIONS.md`](docs/DETECTIONS.md) for full per-attack detail (auto-generated from live replays).

| Attack | Year | Threat | Verdict | Findings |
|---|---|---|---|---|
| Shai-Hulud (self-replicating worm) | 2025 | T1 + T3 | 🚫 BLOCK | 13 |
| rand-user-agent | 2025 | T1 maintainer takeover | 🚫 BLOCK | 4 |
| lottie-player | 2024 | T1 org-level takeover | 🚫 BLOCK | 3 |
| @solana/web3.js | 2024 | T1 wallet-drainer | 🚫 BLOCK | 4 |
| node-ipc | 2022 | T4 protestware | 🚫 BLOCK | 3 |
| colors | 2022 | T4 logic sabotage | ✅ CLEAN _(honest miss)_ | 0 |
| coa + rc | 2021 | T1 dual takeover | 🚫 BLOCK | 5 |
| ua-parser-js | 2021 | T1 takeover | 🚫 BLOCK | 5 |
| eslint-scope | 2018 | T1 credential theft | 🚫 BLOCK | 6 |
| event-stream + flatmap-stream | 2018 | T2 transitive | 🚫 BLOCK | 7 |
| integrity-tamper | 2026 | T5 synthetic | 🚫 BLOCK | 1 |
| typosquat (crossenv) | 2026 | T6 synthetic | 🚫 BLOCK | 4 |
| hardened-evader | 2026 | T1+T3 synthetic | 🚫 BLOCK | 4 |

**Score: 12 caught / 13 total (92%).** One honest miss (`colors` 2022 protestware — logic sabotage that used only capabilities the package already had; behavioral diffing cannot see this).

**False-positive study.** vetlock is tested against 8 realistic benign version bumps (docs-only, feature-add, types-only, refactor, license fix, tests-only, bugfix, peer-dep add) — **all yield 0 findings**. See [`packages/cli/test/fp-smoke.test.ts`](packages/cli/test/fp-smoke.test.ts).

**All fixtures are DEFANGED.** Every URL literal resolves to an RFC-2606 reserved TLD (`.invalid` / `.example` / `.test`) or loopback. Any executable payload is guarded by `if(false)`. Enforced by [`corpus-defanged.test.ts`](packages/cli/test/corpus-replay.test.ts).

---

## Output formats

### Pretty (TTY, default)

Colored, grouped by direct-dependency subtree, with evidence + provenance. See the demo output above.

### JSON

```json
{
  "vetlockVersion": "0.3.0",
  "verdict": "BLOCK",
  "findings": [
    {
      "detector": "env.token-harvest",
      "category": "ENV",
      "package": "chalk",
      "from": "5.3.0",
      "to": "5.3.1",
      "direction": "changed",
      "severity": "BLOCK",
      "confidence": "high",
      "message": "Package started reading sensitive env: NPM_TOKEN",
      "evidence": [{ "file": "index.js", "line": 14, "snippet": "const token = process.env.NPM_TOKEN;" }],
      "provenance": [["my-app", "chalk"]]
    }
  ],
  "changedPackages": 1,
  "durationMs": 3
}
```

Schema stable across patch releases within a minor version.

### SARIF 2.1.0

```bash
npx vetlock diff before.json after.json --sarif > vetlock.sarif
```

Upload to GitHub's code-scanning:

```yaml
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: vetlock.sarif }
```

### Markdown

```bash
npx vetlock diff before.json after.json --md > pr-comment.md
```

Paste directly as a sticky PR comment. Renders the same finding-grouping as the TTY output.

---

## GitHub Action

Runs vetlock on every PR that touches `package-lock.json`. Sticky PR comment, SARIF upload, per-detector fail-on gating.

```yaml
# .github/workflows/vetlock.yml
name: vetlock
on:
  pull_request:
    paths: ['**/package-lock.json', '**/yarn.lock', '**/pnpm-lock.yaml']

jobs:
  vetlock:
    runs-on: ubuntu-latest
    permissions: { contents: read, pull-requests: write, security-events: write }
    steps:
      - uses: OJ-Uday/vetlock/action@v0
        with:
          fail-on: install.script-added,env.token-harvest,net.new-endpoint,net.encoded-endpoint,integrity.hash-mismatch
      - uses: github/codeql-action/upload-sarif@v3
        with: { sarif_file: vetlock.sarif }
```

Full recipe with worked PR-comment example: [`action/README.md`](action/README.md).

---

## Configuration (`.vetlock.json`)

Optional. Drop in your repo root to customize.

```json
{
  "trustedPublishers": {
    "my-scoped-pkg": ["@mycompany.com"]
  },
  "ignorePackages": [
    "some-noisy-benign-pkg"
  ],
  "severityOverride": {
    "meta.maintainer-change": "INFO"
  },
  "allowedRegistries": [
    "registry.npmjs.org"
  ]
}
```

**Trust semantics (S2 hardening).** If `.vetlock.json` is included in the same diff being analyzed, vetlock refuses to apply it (defaults are used instead) and emits `config.in-diff-untrusted`. Prevents an attacker from silencing findings in the same PR that introduces the malware. Override with `--config-allow-in-diff` (a `config.in-diff-allowed` WARN is still recorded so reviewers see the decision).

Full schema: [`packages/core/src/config.ts`](packages/core/src/config.ts) (zod-typed).

---

## Tests

**375 tests green across the workspace.** Runs in ~7 seconds.

```
packages/core       — 20 files, 228 tests
packages/detectors  —  8 files, 106 tests
packages/cli        —  5 files,  41 tests
```

Test surface includes:

- **Corpus replay** (15 fixtures) — end-to-end via `runDiff` + `runAll`.
- **False-positive smoke** (9 fixtures) — realistic benign bumps yield 0 findings.
- **Property-based fuzzing** (12 properties, ~2400 samples/run) — every parser survives arbitrary input without an uncaught throw.
- **Red-team regression tests** — every one of the 31 closed exploits has a dedicated failing-before-fix regression test.
- **NEVER-EXECUTE canary** — the soul test.
- **DEFANGED corpus hygiene** — no live exfil pattern sneaks into any fixture.

Run everything:

```bash
pnpm install
pnpm -r build
pnpm -r test
```

---

## Architecture

Full details in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) and [ADRs](docs/adr/).

```
┌──────────────────┐   ┌────────────────┐   ┌──────────────┐
│ Lockfile parser  │──▶│ Diff (change   │──▶│ Fetcher      │
│ (npm/yarn/pnpm)  │   │ set compute)   │   │ (pacote /    │
└──────────────────┘   └────────────────┘   │ file: local) │
                                            └──────┬───────┘
                                                   │
                              ┌────────────────────▼──────────────────┐
                              │ Safe extract (zip-slip / symlink-safe)│
                              └────────────────────┬──────────────────┘
                                                   │
                              ┌────────────────────▼──────────────────┐
                              │ Capability extract (Babel AST +       │
                              │ constant folding + alias tracking)    │
                              └────────────────────┬──────────────────┘
                                                   │
                              ┌────────────────────▼──────────────────┐
                              │ HMAC-authenticated cache              │
                              │ (~/.cache/vetlock, per-install key)   │
                              └────────────────────┬──────────────────┘
                                                   │
                              ┌────────────────────▼──────────────────┐
                              │ 17 detectors (pure fn: snapshot pair  │
                              │ → Finding[])                          │
                              └────────────────────┬──────────────────┘
                                                   │
                              ┌────────────────────▼──────────────────┐
                              │ Escalation + severity policy          │
                              └────────────────────┬──────────────────┘
                                                   │
                              ┌────────────────────▼──────────────────┐
                              │ Render: TTY / JSON / SARIF / MD       │
                              └───────────────────────────────────────┘
```

### Battle-tested dependencies (all explicitly justified)

Every non-trivial parsing/matching primitive uses a widely-audited library rather than a hand-roll:

| Library | Purpose | Why |
|---|---|---|
| `@babel/parser` + `@babel/traverse` | JS/TS AST | The React/webpack/etc. ecosystem's own parser |
| `@yarnpkg/lockfile` + `@yarnpkg/parsers` | yarn.lock parsing | Yarn's own libs |
| `js-yaml` | pnpm-lock.yaml | The canonical Node YAML parser |
| `semver` | version-range logic | npm's own lib |
| `damerau-levenshtein` | typosquat edit distance | Catches transpositions (`debgu → debug`) |
| `zod` | config schema validation | Type-safe runtime validation |
| `@webassemblyjs/wasm-parser` | WASM binary parsing | webpack's parser |
| `pacote` | tarball fetching | npm's own registry client |
| `tar` + `ssri` | safe extract + integrity | npm's own libs |
| `fast-check` (dev) | property-based fuzzing | The industry-standard JS property tester |

See [`docs/SECURITY-DECISIONS.md`](docs/SECURITY-DECISIONS.md) for the "correctness over performance on security boundaries" principle that governs these choices.

---

## Privacy

- **Zero telemetry.** No HTTP calls except tarball fetching from the npm registry (or your configured mirror in `.npmrc`).
- **Your lockfiles never leave your machine.** Full analysis happens locally.
- **No auth wall.** vetlock is `npx`-runnable with no account, no API key, no email.

The HMAC cache key at `~/.cache/vetlock/hmac.key` is per-install and mode `0600` — analysis results are authenticated but never exfiltrated.

---

## Roadmap

- ✅ v0.1.0 — 10-attack corpus + hardening + FP study
- ✅ v0.2.0 — constant folding, alias tracking, WASM, GHSA, trust store, property fuzz
- ✅ v0.3.0 — 31 red-team exploits closed, lockfile-identity detector, bundled-deps recursion, comprehensive README + zero-effort demo
- ⏳ v0.4 — baseline scan mode (single lockfile, no diff frame)
- ⏳ v0.4 — GHSA weekly-refresh script (currently curated subset)
- ⏳ v0.5 — SBOM (CycloneDX/SPDX) generation
- ⏳ v0.5 — pretty HTML report format
- ⏳ vNEXT — flow-sensitive alias tracking beyond single-hop
- ⏳ vNEXT — Tree-sitter fallback parser for TypeScript syntax Babel struggles with

See [`ROADMAP.md`](ROADMAP.md).

---

## Contributing

Contributions welcome — especially:

- **False-positive reports.** If vetlock flags something on a legitimate version bump, please open an issue with the exact packages and lockfiles.
- **New corpus attacks.** Real historical attacks or novel synthetic evasion patterns. See `packages/cli/src/corpus/fixtures/` for the DSL — each fixture is one file.
- **New detectors.** Each detector is a pure function `SnapshotPair → Finding[]`.

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the workflow.

### Security disclosures

Vulnerabilities in vetlock itself: see [`SECURITY.md`](SECURITY.md).

---

## Documentation index

- 📖 [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — pipeline, invariants, extension points
- 🎯 [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) — attackers we defend against + explicit non-catches
- 🚫 [`docs/DETECTIONS.md`](docs/DETECTIONS.md) — replay results against 13 corpus attacks (auto-generated)
- 🔴 [`docs/REDTEAM-2026-07-12.md`](docs/REDTEAM-2026-07-12.md) — full red-team review + 35 confirmed exploits
- 🛡️ [`docs/SECURITY-DECISIONS.md`](docs/SECURITY-DECISIONS.md) — "correctness over performance on security boundaries" principle
- 🚀 [`LAUNCH-CHECKLIST.md`](LAUNCH-CHECKLIST.md) — the tickable P9 gate (living doc)
- 📋 [`docs/adr/`](docs/adr/) — Architecture Decision Records
  - [0001-name](docs/adr/0001-name.md) — why "vetlock"
  - [0002-language-ts](docs/adr/0002-language-ts.md) — why TypeScript
  - [0003-parser-babel](docs/adr/0003-parser-babel.md) — parser choice
  - [0004-pacote-fetch](docs/adr/0004-pacote-fetch.md) — fetcher choice
  - [0005-never-execute](docs/adr/0005-never-execute.md) — the NEVER-EXECUTE invariant (the soul test)
  - [0006-open-core-boundary](docs/adr/0006-open-core-boundary.md) — engine is the product, wrapper is thin
  - [0007-github-app](docs/adr/0007-github-app.md) — GitHub App as the PLG entry point
  - [0008-ephemeral-analysis](docs/adr/0008-ephemeral-analysis.md) — hosted-tier privacy architecture
  - [0009-ecosystem-adapter](docs/adr/0009-ecosystem-adapter.md) — cross-ecosystem extensibility (npm → PyPI → ...)
  - [0010-company-name](docs/adr/0010-company-name.md) — availability audit, name posture
  - [0011-completeness-doctrine](docs/adr/0011-completeness-doctrine.md) — the governing law (capability *classes*, not signatures)
  - [0012-scan-mode](docs/adr/0012-scan-mode.md) — `vetlock scan` (single-input, capability profile)
  - [0013-osif](docs/adr/0013-osif.md) — the Open Supply-chain Incident Format

## Related repos

- 🌐 [**OJ-Uday/osif-spec**](https://github.com/OJ-Uday/osif-spec) — Open Supply-chain Incident Format (CC0). A shared machine-readable vocabulary for describing supply-chain attack mechanics.
- 📊 [**OJ-Uday/vetlock-benchmark**](https://github.com/OJ-Uday/vetlock-benchmark) — Public detection benchmark scoreboard. Any scanner scored against the same corpus. vetlock: 92.3%. npm-audit: 53.8%.

---

## License

[Apache-2.0](LICENSE).

## Author

Uday Ojha ([@OJ-Uday](https://github.com/OJ-Uday)). Feedback, PRs, and false-positive reports welcome.

---

<div align="center">
<sub>vetlock — because the next Shai-Hulud is a Renovate PR away.</sub>
</div>
