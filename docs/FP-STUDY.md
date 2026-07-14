# FP-STUDY — vetlock false-positive rate on routine npm bumps

**tl;dr — v0.4.1 · 2026-07-14**

Two runs against the same 30-bump `studies/top-100.txt` corpus, fetched from an Artifactory-mirrored npm registry:

|                       | v0.4.0 (before) | v0.4.1 (after tune) |
|-----------------------|-----------------|---------------------|
| Analyzed successfully | 27              | 27                  |
| BLOCK verdict         | **48.1%** (13)  | **33.3%** (9)       |
| WARN verdict          | 3.7% (1)        | **18.5%** (5)       |
| INFO verdict          | 0%              | 3.7% (1)            |
| CLEAN verdict         | 48.1% (13)      | 44.4% (12)          |
| Findings / analyzed   | 14.8            | **5.0** (-66%)      |
| Corpus attacks caught | 12/13           | 12/13 (unchanged)   |

**Take.** v0.4.0 BLOCK-ed 48% of legit routine npm upgrades — a scanner that gets muted. v0.4.1 lands three targeted tunes (§3a–§3c) that dropped that to 33%, while attack-catch stays at 12/13. The remaining 33% is dominated by `install.script-changed` on non-lifecycle scripts (§3d) and `exec.new-module` on legit process modules — both scoped for v0.4.2. The v0.4.1 tune is committed; the measured numbers here are reproducible.

**What v0.4.1 changed** (all in one commit):

- `net.new-endpoint` severity: BLOCK → WARN (§3b)
- `code.dynamic-loading-added` severity per sink kind: `eval`/`new-function`/`char-arithmetic-decoder` → WARN, `dynamic-import`/`dynamic-require` → INFO, `vm` → BLOCK (§3c)
- `URL_REGEX`: ambiguous TLDs (`.app`, `.dev`, `.io`, `.co`, `.name`, `.pro`, `.tech`) now require a path suffix; abused-TLD bare hosts (`.top`, `.pw`, `.zip`, etc.) still match bare (§3b)
- Compound-suspicion escalation: same-category saturation restricted to OBF + dangerous-CODE kinds (§3a)

---

## 1. Methodology

**Input.** `studies/top-100.txt`: 30 hand-picked bumps drawn from the top-100 npm packages by weekly download count. Includes:

- Routine patch bumps (react 18.3.0→18.3.1, lodash 4.17.20→4.17.21)
- Minor bumps with feature additions (axios 1.6→1.7, chalk 5.3→5.4)
- Major bumps (commander 11→12, glob 10→11)
- Build-tool bumps (vite 5.2→5.4, webpack 5.90→5.94, esbuild 0.20→0.21)
- Config-tool bumps (eslint 8→9, prettier 3.2→3.3)

Every one is a *published, well-audited, presumed-safe* upgrade. Any finding is either a real behavioral delta the developer would want to know about (INFO/WARN territory) or a false positive (should not have fired). None are attacks.

**Runner.** `packages/cli/src/corpus/fp-study.ts` (compiled to `dist/corpus/fp-study.js`).

- Synthesizes minimal npm-shape lockfile-before / lockfile-after referencing the two versions.
- `runDiff` is invoked with a `fetchOverride` that pulls each version's tarball via `pacote` from the configured registry.
- All findings are collected verbatim; `analysis.failed` is treated as a study-methodological error, not a vetlock hit.

**Registry.** Runs use `NPM_CONFIG_REGISTRY` pointed at the Lilly-internal Artifactory mirror. Authentication comes from `~/.npmrc` `_authToken` lines with `${VAR}` env-substitution — see `resolveRegistryAuth()` in the runner.

**Reproducing.** From vetlock repo root:

```bash
export NPM_CONFIG_REGISTRY=https://<your-registry>/
pnpm --filter vetlock build
node packages/cli/dist/corpus/fp-study.js \
  --input studies/top-100.txt \
  --output studies/fp-results.json \
  --verbose
```

Bump study is parallelizable — split the input into chunks and fan out; results are merge-safe row-wise.

---

## 2. What fired (v0.4.1 measured, 27 analyzed bumps)

| Detector                     | Bumps hit | Fires at |
|------------------------------|-----------|----------|
| `code.dynamic-loading-added` | 8         | INFO for dynamic-import/require · WARN for eval/new-function/char-arith |
| `net.new-endpoint`           | 6         | WARN (was BLOCK in v0.4.0) |
| `install.script-changed`     | 5         | BLOCK — fires on any lifecycle-slot change (v0.4.2 target) |
| `obf.new-obfuscated-file`    | 3         | WARN — bundler-shipped minified files still trigger (v0.4.2 target) |
| `exec.new-module`            | 3         | BLOCK on any node:worker_threads / node:child_process first-use (v0.4.2 target) |
| `deps.new-direct-dep`        | 2         | INFO — correct |
| `net.new-module`             | 1         | WARN — correct |

### Non-CLEAN rows in v0.4.1

- **BLOCK (9):** commander, vite, prettier, vitest, uuid, webpack, glob, minimatch, tsx
- **WARN (5):** express, eslint, mocha, sharp, dotenv
- **INFO (1):** rollup
- **CLEAN (12):** react, react-dom, axios, chalk, debug, esbuild, zod, nanoid, ora, picocolors, semver, fast-glob

---

## 3. Root causes — the fixes

### 3a. Same-category escalation restricted (LANDED in v0.4.1)

v0.4.0 rule: any package with N ≥ 3 WARN findings in a single category promoted to BLOCK. Vite added 16 new dynamic-imports in one bump → 16 CODE WARN → all promoted to BLOCK.

v0.4.1 rule: same-category saturation only promotes when:
- Category is `OBF` (obfuscated file additions have a low legit base rate — the whole point of shipping readable code is that it's readable), OR
- Category is `CODE` AND ≥3 findings are of *dangerous* sink kinds (`eval`, `new-function`, `unpacker`, `marshal`, `deserialize`). `dynamic-import`, `dynamic-require`, and `char-arithmetic-decoder` are excluded — bundlers ship them legitimately.

Cross-category escalation (2+ categories with 2+ WARNs including a security category) still fires — that's the real compound-suspicion signal.

Location: `packages/detectors/src/index.ts` compound-suspicion block.

### 3b. `URL_REGEX` schemeless matches + `net.new-endpoint` severity (LANDED in v0.4.1)

v0.4.0's `URL_REGEX` matched bare `word.tld` for a broad TLD list, catching non-URL identifiers like `Cursor.app`, `Edition.app`, `example.com` (in comments). And any bare URL fired `net.new-endpoint` at BLOCK.

v0.4.1 changes:
- **Split the schemeless alternation**:
  - **Ambiguous TLDs** (`.app`, `.dev`, `.io`, `.co`, `.name`, `.pro`, `.tech`): require a path/port/query/fragment suffix (`/`, `:`, `?`, `#`). Vite mentioning `Cursor.app` no longer matches. `curl attacker.app/exfil` still matches.
  - **Abused-TLD and RFC-2606 reserved TLDs** (`.top`, `.pw`, `.zip`, `.click`, `.info`, `.us`, `.biz`, `.mobi`, `.icu`, `.host`, `.online`, `.club`, `.stream`, `.party`, `.science`, `.today`, `.link`, `.work`, `.xyz`, `.tk`, `.ml`, `.ga`, `.cf`, `.ru`, `.cn`, `.example`, `.test`, `.invalid`, `.localhost`, `.cloud`, `.site`): keep bare-match. Dominated by attack/spam use; the `redteam-remaining-8` L4 test suite pins many of them.
  - **`.com`, `.net`, `.org`**: keep bare-match — a bare `attacker.com` string is a common attack payload shape.
- **`net.new-endpoint` severity: BLOCK → WARN.** Any single URL delta shouldn't BLOCK on its own; a package adding a docs URL is not the same as one adding an exfil endpoint. Cross-category escalation promotes it back to BLOCK when co-occurring with INSTALL/EXEC/ENV/FS.

Location: `packages/core/src/capabilities.ts` `URL_REGEX`; `packages/detectors/src/net.ts` severity.

**KNOWN LIMITATION:** `URL_REGEX` is still a hand-written regex — see §4 for the OSS-library follow-up per user directive.

### 3c. `code.dynamic-loading-added` severity per sink kind (LANDED in v0.4.1)

v0.4.0 emitted every sink-kind at WARN uniformly. v0.4.1 splits:

| Sink kind                | Severity  | Rationale |
|--------------------------|-----------|-----------|
| `eval`                   | WARN      | Direct code exec |
| `new-function`           | WARN      | Direct code exec via constructor |
| `char-arithmetic-decoder`| WARN      | rot13/xor/base64 unpacker shape (REDTEAM L11) |
| `vm`                     | BLOCK     | Sandbox escape target |
| `dynamic-import`         | **INFO**  | Modern module loading — bundler noise |
| `dynamic-require`        | **INFO**  | Modern module loading — bundler noise |

Attackers using `dynamic-require` to load a decoded payload are still covered — the payload itself trips `obf.new-obfuscated-file` or `char-arithmetic-decoder`.

Location: `packages/detectors/src/code.ts` `severityFor()` helper.

### 3d. `install.script-changed` fires on non-lifecycle scripts (v0.4.2)

`commander@11→12` triggered `install.script-changed — Lifecycle script "test" body changed.` But `test` is not a lifecycle script — no auto-execution on install.

**Fix (planned v0.4.2):** restrict to npm's actual lifecycle-script allowlist: `preinstall`, `install`, `postinstall`, `preprepare`, `prepare`, `postprepare`, `preuninstall`, `uninstall`, `postuninstall`. Any other `scripts[key]` change is not an install signal.

### 3e. `obf.new-obfuscated-file` flags routine minified dist output (v0.4.2)

Bundlers (`tsx`, `vite`, `webpack`) ship pre-minified `dist/*.mjs` files. High-entropy literals in a minified bundle are the *default*, not a signal.

**Fix (planned v0.4.2):** add an "expected-minified" allow-list — any file that's the target of `package.json`'s `main`/`module`/`exports` AND lives in `dist/` or `build/` gets its obfuscation score de-weighted.

### 3f. `deps.first-version-cluster` on transitively-added deps (v0.5.0)

Reads "first version we've ever seen in this diff" instead of "first version ever, per npm registry." Requires a registry-count lookup to fix correctly.

---

## 4. Wheel-reinvention audit (user directive · v0.4.2+)

`URL_REGEX` in §3b is a hand-written regex trying to enumerate every TLD. That's exactly what OSS libraries like `tldts`, `is-url-http`, or `linkify-it` already do — with a properly-maintained public-suffix list. v0.4.2 should swap to one of these.

Candidates to evaluate:

- **`tldts`** (~40KB, MIT) — parses hostnames, gives you the effective public suffix. Would replace TLD enumeration entirely.
- **`is-url-http`** (tiny, MIT) — permissive URL-shape check.
- **`linkify-it`** (used by markdown-it) — same class of matcher, well-tested against real-world text.

Also worth checking:

- **`eslint-plugin-security` / `semgrep-rules`** — for the "which JS APIs are dangerous" question, both maintain vetted lists that could inform `DANGEROUS_CODE_KINDS`.
- **`@yarnpkg/lockfile`** (already using), **`@babel/parser`** (already using), **`tar`** (already using), **`pacote`** (already using) — no reinvention here.

Tracked in TASK #52.

---

## 5. Post-tune target for v0.4.2

- **BLOCK rate ≤ 15%** on the 27-bump routine-upgrade corpus (down from today's 33%)
- **CLEAN rate ≥ 60%** (up from today's 44%)
- **`vetlock-benchmark` score stays at 12/13 or better** — no attack-detection regression
- **CAPABILITY-MAP coverage gate stays green** — no detector removed, only rebalanced

---

## 6. Excluded from the study

- 3 bumps couldn't be fetched from the Artifactory mirror at study time (versions not mirrored / proxy hiccups). We fail-closed with `analysis.failed` — the right behavior. Rerunning against public npm is future work.
- No malicious bumps in the input. `vetlock-benchmark` covers that side — 12/13 attack corpus caught.

---

## 7. Timeline

- **v0.4.0 · 2026-07-14** — first honest FP measurement (48% BLOCK on routine bumps)
- **v0.4.1 · 2026-07-14** — landed §3a–§3c. BLOCK rate down to 33%. Corpus attack-catch preserved (12/13).
- **v0.4.2 (planned)** — §3d lifecycle-script allowlist, §3e minified-file de-weight, §4 URL-parser OSS swap. Target BLOCK ≤ 15%.
- **v0.5.0 (planned)** — §3f `deps.first-version-cluster` registry-count fix.

---

## 8. Honesty pledge

Every number in this document is reproducible from `studies/top-100.txt` + a working Artifactory (or public npm) registry. The 33% BLOCK rate v0.4.1 hit is not the target — 15% is. v0.4.1 is real, measured progress that cut the noise by a third without any detector removal or attack-detection regression. The remaining false positives have documented root causes with named fixes (§3d–§3f) scoped for v0.4.2 and v0.5.0.

A supply-chain scanner that BLOCKs half of routine upgrades is a scanner that gets muted. That's what v0.4.0 was. v0.4.1 gets it down to a third, in one small commit. The rest of the walk-down is the work of the next two point releases.
