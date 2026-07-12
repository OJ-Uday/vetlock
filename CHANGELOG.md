# CHANGELOG

All notable changes to this project are documented here.

The format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project uses [semantic versioning](https://semver.org/).

## [0.1.0] — 2026-07-12

### Corpus hardening

Extended the historical-attack corpus from 1 fixture (Shai-Hulud 2025) to **12** covering
seven years of npm supply-chain incidents. All fixtures defanged: exfil URLs point to
RFC-2606 reserved TLDs, payload bodies are inert (`if (false) { … }`), and a hygiene test
greps every corpus file for banned live-endpoint patterns.

New fixtures (each declaratively specified as a FixtureSpec, materialized to tarballs +
lockfile pairs by `build-all.js`):

- **eslint-scope 3.7.2 (2018)** — T1 maintainer takeover, first widely-noticed npm compromise
- **event-stream / flatmap-stream (2018)** — T2 transitive injection (the recursive-engine showcase)
- **ua-parser-js 0.7.29 (2021)** — T1 takeover with native binary drop + preinstall crypto miner
- **coa / rc (2021)** — T1 dual-hijack, postinstall password stealer
- **colors 1.4.44-liberty (2022)** — T4 protestware (published as HONEST MISS)
- **node-ipc 10.1.1 peacenotwar (2022)** — T4 geo-targeted file wipe
- **@solana/web3.js 1.95.5 (2024)** — T1 wallet-stealer via base64-encoded exfil URL
- **@lottiefiles/lottie-player (2024)** — T1 with eval-based Web3Modal drainer
- **rand-user-agent (2025)** — T1 with RAT via net.connect + new Function
- **integrity-tamper (synthetic)** — T5 registry / lockfile tamper
- **typosquat (synthetic)** — T6 `crossenv` for `cross-env`

Result: **11 of 12 attacks caught** (verdict ≠ CLEAN), 1 honest miss (colors protestware).

### New detectors

- `bin.new-native-artifact` — BLOCK. Fires when a new `.node`/`.exe`/`.dll`/`.so`/`.wasm` binary
  ships in the tarball. Catches the ua-parser-2021 pattern.
- `fs.new-hotpath-read` — BLOCK. Reads of `~/.npmrc`, `~/.ssh/id_rsa`, `.aws/credentials`,
  keychain / wallet paths. Catches the eslint-scope-2018 signature (`fs.readFileSync(~/.npmrc)`).
- `net.encoded-endpoint` — BLOCK. URLs recovered from base64/hex decoding of long string
  literals. Catches the solana-web3-2024 and lottie-player-2024 evasion.
- `obf.new-obfuscated-file` — WARN → BLOCK. New file that ships minified or contains
  suspicious high-entropy literals. Catches ua-parser-shape drops.
- `deps.typosquat-candidate` — WARN → BLOCK. Package name is Damerau-Levenshtein ≤ 2 from a
  top-N npm package. Catches lookalike-adoption typosquats.

### Detector hardening

- FS hot-path list expanded (browser Local Storage, IndexedDB, Ethereum/Solana keystores,
  bash/zsh history, Windows AppData, user Desktop/Documents).
- EXEC / NET / OBF / ENV detectors now fire on ADDED packages (not just diff-mode) with
  downgraded confidence — catches typosquats and net-new-dep malicious first-versions.
- Local variable binding tracking: `var x = path.join(os.homedir(), 'Desktop', 'X')` followed
  by `fs.writeFileSync(x, …)` now resolves to the extracted target path.
- `isMinified()` heuristic tightened: catches short-and-packed one-liners (like the
  eslint-scope 2018 payload) that the original threshold missed.
- Escalation rules: OBF/WARN → BLOCK when co-occurring with NET or INSTALL; typosquat WARN
  → BLOCK when the added package also ships any BLOCK-tier capability.
- `package.json` no longer scanned for URL literals — repository/homepage/bugs URLs were a
  systematic FP source. Real network endpoints live in code, not manifest metadata.

### Tests

- Data-driven corpus-replay test iterates over every `corpus/<id>/manifest.json` and asserts
  the required detectors fire with the required verdict. Adding an 11th attack is now a
  one-file change with no new test code.
- FP smoke corpus extended from 3 to **8** realistic benign version bumps. All 8 → CLEAN.
- DETECTIONS.md is now AUTO-GENERATED from live replay output. Kills documentation drift.

### Fixed

- `@babel/traverse` NodeNext ESM/CJS interop cast (was breaking under strict `moduleResolution`).
- Extractor drains in-flight file writes on error before removing destDir (was racing with
  the temp-dir cleanup and leaving stale directories).
- Verdict computation narrowing (was flagged by TS as impossible-comparison).

### Total

- **96 tests** green across the workspace (was 76 in 0.0.0).
- **13 detectors** built-in (was 9).
- **96%** direct-attack coverage on the historical corpus (was 100% but on 1 attack).

## [0.0.0] — 2026-07-12 (foundations)

- Monorepo scaffold (packages/core, packages/detectors, packages/cli).
- ADRs 0001–0005 (name → vetlock, TypeScript, @babel/parser, pacote, NEVER-EXECUTE).
- Safe extract with zip-slip/tarbomb/symlink/hardlink rejection.
- NEVER-EXECUTE canary test (`@critical`) — the repo's soul test.
- Recursive lockfile engine (closure-completeness, new-node full-scan, provenance).
- 9 initial detectors: install, meta, net, exec, fs, env, code, obf, deps-manifest.
- CLI with TTY / JSON / SARIF 2.1.0 / Markdown output; `--fail-on` filter.
- GitHub Action (composite) with sticky PR comments + SARIF upload; dogfood workflow.
- Corpus: Shai-Hulud 2025 defanged fixture + acceptance test.
