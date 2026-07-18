# CAPABILITY-MAP

**Version:** 0.1 · **Source of truth:** `packages/detectors/src/capability-map.json` · **This doc is auto-generated** — do not edit by hand; run `pnpm corpus:capmap` after editing the JSON.

> The machine-readable enumeration of every capability *class* vetlock claims to cover, plus each class's sinks (runtime primitives) and entry-points (attack surfaces). ADR 0011 (completeness doctrine) is the governing law. Coverage is CI-enforced: any entry with a missing detector, missing test, or missing corpus ref (unless flagged `soft_warn_no_corpus`) fails `capability-map-coverage.test`.

## Summary

- **Total enumerated primitives:** 64
- **With corpus fixture(s):** 26 (41%)
- **Soft-warn (no corpus yet):** 38

| Class | Sink count | Entry-point count | Total |
|---|---:|---:|---:|
| `advisory-known-vuln` | 2 | 0 | 2 |
| `code-execution` | 11 | 0 | 11 |
| `dep-graph-anomaly` | 1 | 0 | 1 |
| `fs-read` | 1 | 0 | 1 |
| `fs-write` | 1 | 0 | 1 |
| `graph-entry-point` | 0 | 10 | 10 |
| `install-hook` | 1 | 5 | 6 |
| `integrity` | 1 | 0 | 1 |
| `net-egress` | 9 | 0 | 9 |
| `obfuscation-decode` | 5 | 0 | 5 |
| `publisher-trust` | 0 | 2 | 2 |
| `python-code-exec` | 2 | 0 | 2 |
| `python-env-access` | 1 | 0 | 1 |
| `python-install-hook` | 2 | 0 | 2 |
| `python-net-egress` | 2 | 0 | 2 |
| `python-supply-chain` | 1 | 0 | 1 |
| `secret-read` | 5 | 0 | 5 |
| `typosquat` | 0 | 2 | 2 |

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
| `http-resolved-url` | entry-point | `manifest-deps.http-resolved-url` | _(soft-warn)_ | `manifest.dependencies / optionalDependencies / peerDependencies value-string check — URL parse + registry-host allowlist` |
| `npm-alias` | entry-point | `deps.aliased-name` | _(soft-warn)_ | — |
| `optional-dependency` | entry-point | `deps.new-direct-dep` | _(soft-warn)_ | — |
| `peer-dependency` | entry-point | `deps.new-direct-dep` | _(soft-warn)_ | — |
| `transitive-dependency` | entry-point | `deps.new-direct-dep` | `event-stream-2018` | — |
| `workspace-link` | entry-point | `deps.workspace-shadowing` | _(soft-warn)_ | — |

**Notes:**
- `bundled-dependency`: N1 FIX — analyzer recurses into bundled trees
- `file-source`: S9 FIX — absolute file: URLs flagged INFO (attacker-controlled local path)
- `git-source`: N5 FIX — git-source WARN because integrity/publisher-trust don't apply
- `http-resolved-url`: Wave 8-LL — port from guarddog:threat-npm-http-dependency. Complements deps.non-registry-source (git+/github:/bitbucket:/gitlab: emitted by engine.ts): this detector fires on the OTHER shape — plain http:// or non-registry https:// URLs as dep specs in package.json itself, not just the lockfile resolved: field.
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
| `self-publish-shape` | sink | `install.self-publish-shape` | `shai-hulud-2025` | `co-occurrence over PackageSnapshot: install-tier lifecycle script + execModules (child_process/worker_threads/vm) + fsWriteTargets containing 'package.json'` |

**Notes:**
- `bundled-lifecycle`: N1 FIX — analyzer recurses into every node_modules/ in a tarball
- `self-publish-shape`: Wave 8-LL — port from guarddog:threat-runtime-self-propagation. The npm-worm mechanic: install-tier hook that spawns a subprocess AND rewrites the local manifest. Requires all three signals in the SAME diff to keep FP low.

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
| `dns-templated-hostname` | sink | `net.dns-templated-hostname` | _(soft-warn)_ | `capabilities.networkModules ∋ dns/* AND (char-arithmetic-decoder dynamicCode OR encodedUrls OR env-access snippet containing a DNS callee)` |
| `encoded-url` | sink | `net.encoded-endpoint` | `event-stream-2018`, `solana-web3-2024`, `lottie-player-2024` | `capabilities.encodedUrls (constant-folding aware)` |
| `fetch` | sink | `net.new-module` | _(soft-warn)_ | `capabilities.networkModules` |
| `http` | sink | `net.new-module` | `shai-hulud-2025`, `eslint-scope-2018`, `event-stream-2018` | `capabilities.networkModules` |
| `https` | sink | `net.new-module` | `shai-hulud-2025`, `coa-rc-2021`, `ua-parser-2021` | `capabilities.networkModules` |
| `net` | sink | `net.new-module` | _(soft-warn)_ | `capabilities.networkModules` |
| `url-literal` | sink | `net.new-endpoint` | `shai-hulud-2025`, `event-stream-2018`, `coa-rc-2021`, `ua-parser-2021`, `eslint-scope-2018` | `capabilities.urlLiterals + URL_REGEX (~50 TLDs)` |
| `websocket` | sink | `net.new-module` | _(soft-warn)_ | `capabilities.networkModules` |

**Notes:**
- `dns`: N3 FIX — covert exfil channel via DNS subdomain encoding
- `dns-templated-hostname`: Wave 8-KK — port from guarddog:threat-network-dns-exfil. Diff-safe: only fires when the DNS module is NEWLY imported in the changed version.

## `obfuscation-decode`

| ID | Kind | Detector(s) | Corpus | Chokepoint |
|---|---|---|---|---|
| `char-arithmetic-decoder` | sink | `code.dynamic-loading-added` | _(soft-warn)_ | — |
| `entropy-jump` | sink | `obf.entropy-jump`, `obf.new-obfuscated-file` | `event-stream-2018`, `eslint-scope-2018`, `lottie-player-2024`, `rand-user-agent-2025` | `capabilities.entropy + capabilities.suspiciousLiterals` |
| `image-decode-exec` | sink | `obf.image-decode-exec` | _(soft-warn)_ | `PackageSnapshot.files cross-reference: fsReadTargets pointing at image extensions (.png/.jpg/.gif/.bmp/.webp) + dynamicCode sink (eval/new-function/vm) in the same package` |
| `js-mangler-signature` | sink | `obf.js-mangler-signature` | _(soft-warn)_ | `count of distinct `_0x[a-f0-9]{4,6}` matches across FileCapabilities.dynamicCode/envAccesses snippets + suspiciousLiterals previews` |
| `unicode-homoglyph-boundary` | sink | `obf.unicode-homoglyph-boundary` | _(soft-warn)_ | `ASCII↔confusable-alphabet-block adjacency in urlLiterals + suspiciousLiterals previews + dynamicCode/envAccesses snippets` |

**Notes:**
- `char-arithmetic-decoder`: L11 FIX — rot13/char-arithmetic decoder detection
- `image-decode-exec`: Wave 8-LL — port from guarddog:threat-runtime-obfuscation-steganography. Byte-level scanners see a valid image; AST scanners see a fs.readFileSync and a new Function separately. This detector connects the two — image + read + dynamic-code in the SAME snapshot version.
- `js-mangler-signature`: Wave 8-KK — port from guarddog:threat-runtime-obfuscation-js-mangling. Fires when ≥3 distinct mangled identifiers appear in a NEW/CHANGED JS-like file in pair.new.
- `unicode-homoglyph-boundary`: Wave 8-KK — port from guarddog:threat-runtime-obfuscation-unicode. Diff-safe: fires when the boundary is NEW to a file that had none before, or in an added-package first-version file.

## `publisher-trust`

| ID | Kind | Detector(s) | Corpus | Chokepoint |
|---|---|---|---|---|
| `disposable-author-domain` | entry-point | `meta.disposable-author-domain` | _(soft-warn)_ | `packages/detectors/src/data/disposable-domains.json (708-entry snapshot) — domain-exact-match against the disposable-email-domains public list` |
| `maintainer-change` | entry-point | `meta.maintainer-change` | `shai-hulud-2025`, `solana-web3-2024`, `eslint-scope-2018`, `coa-rc-2021`, `ua-parser-2021`, `rand-user-agent-2025` | — |

**Notes:**
- `disposable-author-domain`: Wave 8-LL — port from guarddog:deceptive_author. Complements meta.maintainer-change: the maintainer-change detector fires on the TRANSITION, this one qualifies WHY the new address is suspect.
- `maintainer-change`: S3 FIX — trust-store with parse-based email matching (exact domain-or-subdomain); S6 FIX — populated → empty is BLOCK when old was trusted

## `python-code-exec`

| ID | Kind | Detector(s) | Corpus | Chokepoint |
|---|---|---|---|---|
| `b64-plus-exec` | sink | `code.dynamic-loading-added` | _(soft-warn)_ | `capabilities.dynamicCode (kind: char-arithmetic-decoder)` |
| `marshal-loads` | sink | `code.dynamic-loading-added` | _(soft-warn)_ | `capabilities.dynamicCode (kind: new-function)` |

**Notes:**
- `b64-plus-exec`: P4c — co-occurrence of base64.b64decode(...) and exec()/eval() in the same file is the Python analog of the JS char-arithmetic-decoder shape (REDTEAM L11): an encoded payload unpacked and executed at import time.
- `marshal-loads`: P4c — marshal.loads deserializes raw Python bytecode (.pyc payload) directly, the Python equivalent of `new Function(codeBytes)` — a common way to hide a malicious payload as compiled bytecode instead of readable source.

## `python-env-access`

| ID | Kind | Detector(s) | Corpus | Chokepoint |
|---|---|---|---|---|
| `os-environ-read` | sink | `env.token-harvest` | _(soft-warn)_ | `capabilities.envAccesses (Python PY_SENSITIVE_ENV_KEYS — PYPI_TOKEN/TWINE_PASSWORD/DJANGO_SECRET_KEY/etc — feeds the same shared EnvAccess shape)` |

**Notes:**
- `os-environ-read`: P4c — covers keyed reads (os.environ[...] / .get / os.getenv) AND whole-object enumeration (dict(os.environ), for-in, {**os.environ}), mirroring the npm process-env-token and process-env-enumerate entries but for the Python-specific sensitive-key set.

## `python-install-hook`

| ID | Kind | Detector(s) | Corpus | Chokepoint |
|---|---|---|---|---|
| `pyproject-entry-points` | sink | `install.script-added` | _(soft-warn)_ | `pyproject.toml analyzePyproject() extracts entryPoints[] — the pip/Poetry equivalent of npm's manifest.bin` |
| `setup-py-cmdclass` | sink | `install.script-added` | _(soft-warn)_ | `setup.py analyzeSetupPy() ports a cmdclass= override into manifest.scripts.install so the SAME install.script-added detector fires without a new detector` |

**Notes:**
- `pyproject-entry-points`: P4c — [project.scripts] / [tool.poetry.scripts] / entry-points console_scripts install a console command onto the user's PATH at install time — the Python analog of npm's package.json `bin` field entry point.
- `setup-py-cmdclass`: P4c — setup.py declaring a custom cmdclass overriding install's run(self) is pip's install-lifecycle-hijack primitive, the direct analog of npm's scripts.postinstall/scripts.install entry points.

## `python-net-egress`

| ID | Kind | Detector(s) | Corpus | Chokepoint |
|---|---|---|---|---|
| `socket-first-use` | sink | `net.new-module` | _(soft-warn)_ | `capabilities.networkModules` |
| `urllib-first-use` | sink | `net.new-module` | _(soft-warn)_ | `capabilities.networkModules (shared with npm — PY_NETWORK_MODULES feeds the same FileCapabilities.networkModules field)` |

**Notes:**
- `socket-first-use`: P4c — raw socket import/use is the lowest-level Python network primitive and the DNS-style covert-exfil channel (socket.gethostbyname/getaddrinfo mirrors the npm dns.lookup/resolve sink).
- `urllib-first-use`: P4c — a PyPI package's FIRST use of urllib/requests/httpx/aiohttp/urllib3 (stdlib or third-party HTTP client) that wasn't present in the prior version. Reuses net.new-module verbatim — the Python-source extractor (capability-pypi.ts) populates the same ecosystem-agnostic FileCapabilities.networkModules field npm detectors already consume.

## `python-supply-chain`

| ID | Kind | Detector(s) | Corpus | Chokepoint |
|---|---|---|---|---|
| `typosquat-underscore-hyphen` | sink | `deps.typosquat-candidate` | _(soft-warn)_ | `deps.typosquat-candidate — PEP 503 normalization treats '-', '_', and '.' as equivalent, so a PyPI-specific edit-distance/normalization pass is needed alongside the existing Damerau-Levenshtein check to catch confusables that normalize identically on PyPI but are visually/typographically distinct package names` |

**Notes:**
- `typosquat-underscore-hyphen`: P4c — PyPI name normalization (PEP 503) folds '-', '_', and '.' together, so `python-requests` and `python_requests` resolve to DIFFERENT install targets despite looking like the same package — a confusion npm's typosquat detector (which assumes npm's stricter unique-name registry) doesn't need to handle.

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
| `hyphen-permutation` | entry-point | `typo.hyphen-permutation` | _(soft-warn)_ | `packages/detectors/src/data/top-1000-npm.json (1999-entry snapshot) — hyphen-split token-set match against a top-name corpus` |
| `top-name-edit-distance` | entry-point | `deps.typosquat-candidate` | `typosquat-synthetic` | — |

**Notes:**
- `hyphen-permutation`: Wave 8-LL — port from guarddog:typosquatting (hyphen-permutation branch). Complements deps.typosquat-candidate (Damerau-Levenshtein on the full name) with a token-set matcher: `router-react` is edit-distance ≥ 6 from `react-router` (DL misses it), but hyphen-token equal — the shape a distracted developer types.
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
