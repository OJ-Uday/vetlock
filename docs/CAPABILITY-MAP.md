# CAPABILITY-MAP

**Version:** 0.1 · **Source of truth:** `packages/detectors/src/capability-map.json` · **This doc is auto-generated** — do not edit by hand; run `pnpm corpus:capmap` after editing the JSON.

> The machine-readable enumeration of every capability *class* vetlock claims to cover, plus each class's sinks (runtime primitives) and entry-points (attack surfaces). ADR 0011 (completeness doctrine) is the governing law. Coverage is CI-enforced: any entry with a missing detector, missing test, or missing corpus ref (unless flagged `soft_warn_no_corpus`) fails `capability-map-coverage.test`.

## Summary

- **Total enumerated primitives:** 48
- **With corpus fixture(s):** 25 (52%)
- **Soft-warn (no corpus yet):** 23

| Class | Sink count | Entry-point count | Total |
|---|---:|---:|---:|
| `advisory-known-vuln` | 2 | 0 | 2 |
| `code-execution` | 11 | 0 | 11 |
| `dep-graph-anomaly` | 1 | 0 | 1 |
| `fs-read` | 1 | 0 | 1 |
| `fs-write` | 1 | 0 | 1 |
| `graph-entry-point` | 0 | 9 | 9 |
| `install-hook` | 0 | 5 | 5 |
| `integrity` | 1 | 0 | 1 |
| `net-egress` | 8 | 0 | 8 |
| `obfuscation-decode` | 2 | 0 | 2 |
| `publisher-trust` | 0 | 1 | 1 |
| `secret-read` | 5 | 0 | 5 |
| `typosquat` | 0 | 1 | 1 |

## `advisory-known-vuln`

| ID | Kind | Detector(s) | Corpus | Chokepoint |
|---|---|---|---|---|
| `ghsa-adjacent-version` | sink | `deps.new-direct-dep` | _(soft-warn)_ | — |
| `ghsa-affected-version` | sink | `deps.new-direct-dep` | `ua-parser-2021`, `coa-rc-2021`, `solana-web3-2024`, `lottie-player-2024`, `event-stream-2018`, `eslint-scope-2018`, `node-ipc-2022` | — |

**Notes:**
- `ghsa-adjacent-version`: C3 FIX — adjacentAdvisories helper flags versions just outside a vulnerable range

## `code-execution`

| ID | Kind | Detector(s) | Corpus | Chokepoint |
|---|---|---|---|---|
| `async_hooks` | sink | `exec.new-module` | _(soft-warn)_ | `capabilities.execModules` |
| `child_process` | sink | `exec.new-module` | `shai-hulud-2025`, `ua-parser-2021`, `coa-rc-2021`, `hardened-evader-2026` | `capabilities.execModules` |
| `dynamic-import` | sink | `code.dynamic-loading-added` | _(soft-warn)_ | `capabilities.dynamicCode` |
| `dynamic-require` | sink | `code.dynamic-loading-added` | _(soft-warn)_ | `capabilities.dynamicCode` |
| `eval` | sink | `code.dynamic-loading-added` | `hardened-evader-2026` | `capabilities.dynamicCode` |
| `inspector` | sink | `exec.new-module` | _(soft-warn)_ | `capabilities.execModules` |
| `native-node-artifact` | sink | `bin.new-native-artifact` | `ua-parser-2021` | — |
| `new Function` | sink | `code.dynamic-loading-added` | `hardened-evader-2026` | `capabilities.dynamicCode` |
| `vm` | sink | `exec.new-module`, `code.dynamic-loading-added` | `lottie-player-2024`, `rand-user-agent-2025` | `capabilities.execModules + capabilities.dynamicCode` |
| `wasm-instantiate` | sink | `wasm.suspicious-import`, `wasm.unparseable` | _(soft-warn)_ | — |
| `worker_threads` | sink | `exec.new-module` | _(soft-warn)_ | `capabilities.execModules` |

**Notes:**
- `async_hooks`: N2 FIX — monkey-patches every Promise/timer callback
- `dynamic-require`: L3 + L10 FIX — extended CallExpression visitor to catch alias forms
- `inspector`: N2 FIX — V8 debug protocol is an RCE primitive

## `dep-graph-anomaly`

| ID | Kind | Detector(s) | Corpus | Chokepoint |
|---|---|---|---|---|
| `first-version-cluster` | sink | `deps.first-version-cluster` | `typosquat-synthetic`, `hardened-evader-2026` | — |

## `fs-read`

| ID | Kind | Detector(s) | Corpus | Chokepoint |
|---|---|---|---|---|
| `fs-read-hotpath` | sink | `fs.new-hotpath-read` | `eslint-scope-2018` | `capabilities.fsReadTargets (secret-path aware)` |

## `fs-write`

| ID | Kind | Detector(s) | Corpus | Chokepoint |
|---|---|---|---|---|
| `fs-write-hotpath` | sink | `fs.new-hotpath-write` | `shai-hulud-2025`, `node-ipc-2022` | `capabilities.fsWriteTargets (path-literal aware)` |

## `graph-entry-point`

| ID | Kind | Detector(s) | Corpus | Chokepoint |
|---|---|---|---|---|
| `bundled-dependency` | entry-point | `deps.bundled-dependency-added` | _(soft-warn)_ | — |
| `direct-dependency` | entry-point | `deps.new-direct-dep` | `event-stream-2018`, `typosquat-synthetic` | — |
| `file-source` | entry-point | `deps.local-source` | _(soft-warn)_ | — |
| `git-source` | entry-point | `deps.non-registry-source` | _(soft-warn)_ | — |
| `npm-alias` | entry-point | `deps.aliased-name` | _(soft-warn)_ | — |
| `optional-dependency` | entry-point | `deps.new-direct-dep` | _(soft-warn)_ | — |
| `peer-dependency` | entry-point | `deps.new-direct-dep` | _(soft-warn)_ | — |
| `transitive-dependency` | entry-point | `deps.new-direct-dep` | `event-stream-2018` | — |
| `workspace-link` | entry-point | `deps.workspace-shadowing` | _(soft-warn)_ | — |

**Notes:**
- `bundled-dependency`: N1 FIX — analyzer recurses into bundled trees
- `file-source`: S9 FIX — absolute file: URLs flagged INFO (attacker-controlled local path)
- `git-source`: N5 FIX — git-source WARN because integrity/publisher-trust don't apply
- `npm-alias`: F6 FIX — declared vs installed name divergence
- `peer-dependency`: N6 FIX — peerDependencies merged into graph in pnpm + yarn parsers
- `transitive-dependency`: The recursive-engine invariant (engine.test.ts) is what makes transitive-injection catchable at all
- `workspace-link`: F2 FIX — link: true entry shadowing a high-value package name

## `install-hook`

| ID | Kind | Detector(s) | Corpus | Chokepoint |
|---|---|---|---|---|
| `bundled-lifecycle` | entry-point | `install.bundled-lifecycle` | _(soft-warn)_ | — |
| `lifecycle-install` | entry-point | `install.script-added` | `ua-parser-2021` | — |
| `lifecycle-postinstall` | entry-point | `install.script-added` | `shai-hulud-2025`, `coa-rc-2021`, `ua-parser-2021` | — |
| `lifecycle-preinstall` | entry-point | `install.script-added` | `coa-rc-2021`, `shai-hulud-2025` | — |
| `lifecycle-prepare` | entry-point | `install.script-added` | _(soft-warn)_ | — |

**Notes:**
- `bundled-lifecycle`: N1 FIX — analyzer recurses into every node_modules/ in a tarball

## `integrity`

| ID | Kind | Detector(s) | Corpus | Chokepoint |
|---|---|---|---|---|
| `same-version-tamper` | sink | `integrity.hash-mismatch` | `integrity-tamper-synthetic` | — |

**Notes:**
- `same-version-tamper`: S10 + F3 FIX — fires on any transition (populated→different, blank→populated, populated→blank)

## `net-egress`

| ID | Kind | Detector(s) | Corpus | Chokepoint |
|---|---|---|---|---|
| `dns` | sink | `net.new-module` | _(soft-warn)_ | `capabilities.networkModules` |
| `encoded-url` | sink | `net.encoded-endpoint` | `event-stream-2018`, `solana-web3-2024`, `lottie-player-2024` | `capabilities.encodedUrls (constant-folding aware)` |
| `fetch` | sink | `net.new-module` | _(soft-warn)_ | `capabilities.networkModules` |
| `http` | sink | `net.new-module` | `shai-hulud-2025`, `eslint-scope-2018`, `event-stream-2018` | `capabilities.networkModules` |
| `https` | sink | `net.new-module` | `shai-hulud-2025`, `coa-rc-2021`, `ua-parser-2021` | `capabilities.networkModules` |
| `net` | sink | `net.new-module` | _(soft-warn)_ | `capabilities.networkModules` |
| `url-literal` | sink | `net.new-endpoint` | `shai-hulud-2025`, `event-stream-2018`, `coa-rc-2021`, `ua-parser-2021`, `eslint-scope-2018` | `capabilities.urlLiterals + URL_REGEX (~50 TLDs)` |
| `websocket` | sink | `net.new-module` | _(soft-warn)_ | `capabilities.networkModules` |

**Notes:**
- `dns`: N3 FIX — covert exfil channel via DNS subdomain encoding

## `obfuscation-decode`

| ID | Kind | Detector(s) | Corpus | Chokepoint |
|---|---|---|---|---|
| `char-arithmetic-decoder` | sink | `code.dynamic-loading-added` | _(soft-warn)_ | — |
| `entropy-jump` | sink | `obf.entropy-jump`, `obf.new-obfuscated-file` | `event-stream-2018`, `eslint-scope-2018`, `lottie-player-2024`, `rand-user-agent-2025` | `capabilities.entropy + capabilities.suspiciousLiterals` |

**Notes:**
- `char-arithmetic-decoder`: L11 FIX — rot13/char-arithmetic decoder detection

## `publisher-trust`

| ID | Kind | Detector(s) | Corpus | Chokepoint |
|---|---|---|---|---|
| `maintainer-change` | entry-point | `meta.maintainer-change` | `shai-hulud-2025`, `solana-web3-2024`, `eslint-scope-2018`, `coa-rc-2021`, `ua-parser-2021`, `rand-user-agent-2025` | — |

**Notes:**
- `maintainer-change`: S3 FIX — trust-store with parse-based email matching (exact domain-or-subdomain); S6 FIX — populated → empty is BLOCK when old was trusted

## `secret-read`

| ID | Kind | Detector(s) | Corpus | Chokepoint |
|---|---|---|---|---|
| `process-env-destructure` | sink | `env.token-harvest` | _(soft-warn)_ | `capabilities.envAccesses` |
| `process-env-enumerate` | sink | `env.token-harvest` | `shai-hulud-2025` | `capabilities.envAccesses.keys === null` |
| `process-env-reflect` | sink | `env.token-harvest` | _(soft-warn)_ | `capabilities.envAccesses` |
| `process-env-token` | sink | `env.token-harvest` | `shai-hulud-2025` | `capabilities.envAccesses (SENSITIVE_ENV_KEYS + dataflow-aware alias resolution)` |
| `secret-file-read` | sink | `fs.new-hotpath-read` | `eslint-scope-2018` | `capabilities.fsReadTargets` |

**Notes:**
- `process-env-destructure`: L1 FIX — ObjectPattern destructure of process.env
- `process-env-enumerate`: L2 FIX — whole-object enumeration via ANY iteration primitive
- `process-env-reflect`: L5 FIX — Reflect.get alias binding

## `typosquat`

| ID | Kind | Detector(s) | Corpus | Chokepoint |
|---|---|---|---|---|
| `top-name-edit-distance` | entry-point | `deps.typosquat-candidate` | `typosquat-synthetic` | — |

**Notes:**
- `top-name-edit-distance`: D6 FIX — expanded top corpus 230 → 330; N4 FIX — scope-stripping for @evil-org/react-style attacks

---

## How to extend this map

1. Identify the capability CLASS the new attack shape belongs to (or propose a new class if truly novel — see ADR 0011).
2. Add an entry to `packages/detectors/src/capability-map.json` with:
   - `class`, `kind`, `id` (stable identifier)
   - `aliases[]` (syntactic variations)
   - `detectors[]` (detector IDs that fire on this)
   - `tests[]` (test file paths with regression coverage)
   - `corpus_refs[]` (`corpus/<id>` names) OR `soft_warn_no_corpus: true`
   - Optional: `chokepoint` (single dataflow convergence that catches novel syntax for free)
3. Run `pnpm corpus:capmap` to regenerate this doc.
4. Run `pnpm test` — the coverage gate will pass or point at the specific gap.

_Adding a signature without touching the map is now a review-visible mistake._
