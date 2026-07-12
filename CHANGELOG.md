# CHANGELOG

All notable changes to this project are documented here.

The format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project uses [semantic versioning](https://semver.org/).

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
