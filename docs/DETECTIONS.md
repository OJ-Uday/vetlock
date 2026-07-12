# DETECTIONS.md

**Replay of historical npm supply-chain attacks through vetlock's behavioral differ.**

Every row in this document is reproducible from committed fixtures with `pnpm test` — no external network, no live registry. This file is **AUTO-GENERATED** by `packages/cli/src/corpus/generate-detections.ts`; edit that script, not this document.

## Summary

Out of **12** corpus fixtures: **11 caught** (verdict ≠ CLEAN), **1 honest miss(es)** (published limitation).

| Attack | Year | Threat | Verdict | Findings | Detectors |
|---|---|---|---|---|---|
| `coa-rc-2021` | 2021 | T1 maintainer takeover | 🚫 **BLOCK** | 5 | `exec.new-module`, `install.script-added`, `meta.maintainer-change`, `net.new-endpoint`, `net.new-module` |
| `colors-2022` | 2022 | T4 protestware / maintainer sabotage | ✅ CLEAN _(honest miss)_ | 0 | — |
| `eslint-scope-2018` | 2018 | T1 maintainer takeover | 🚫 **BLOCK** | 6 | `fs.new-hotpath-read`, `meta.maintainer-change`, `net.new-endpoint`, `net.new-module`, `obf.entropy-jump` |
| `event-stream-2018` | 2018 | T2 transitive injection | 🚫 **BLOCK** | 6 | `deps.new-direct-dep`, `meta.maintainer-change`, `net.encoded-endpoint`, `net.new-endpoint`, `net.new-module`, `obf.new-obfuscated-file` |
| `integrity-tamper-synthetic` | 2026 | T5 registry / lockfile tamper | 🚫 **BLOCK** | 1 | `integrity.hash-mismatch` |
| `lottie-player-2024` | 2024 | T1 maintainer takeover (org level) | 🚫 **BLOCK** | 2 | `code.dynamic-loading-added`, `net.encoded-endpoint` |
| `node-ipc-2022` | 2022 | T4 protestware | 🚫 **BLOCK** | 3 | `fs.new-hotpath-write`, `net.new-endpoint`, `net.new-module` |
| `rand-user-agent-2025` | 2025 | T1 maintainer takeover | 🚫 **BLOCK** | 4 | `code.dynamic-loading-added`, `meta.maintainer-change`, `net.new-endpoint`, `net.new-module` |
| `shai-hulud-2025` | 2025 | T1 maintainer takeover + T3 self-replicating worm | 🚫 **BLOCK** | 13 | `env.token-harvest`, `exec.new-module`, `fs.new-hotpath-write`, `install.script-added`, `meta.maintainer-change`, `net.new-endpoint`, `net.new-module` |
| `solana-web3-2024` | 2024 | T1 maintainer takeover | 🚫 **BLOCK** | 3 | `meta.maintainer-change`, `net.encoded-endpoint`, `net.new-module` |
| `typosquat-synthetic` | 2026 | T6 typosquat adoption | 🚫 **BLOCK** | 4 | `deps.typosquat-candidate`, `exec.new-module`, `net.new-endpoint`, `net.new-module` |
| `ua-parser-2021` | 2021 | T1 maintainer takeover | 🚫 **BLOCK** | 5 | `bin.new-native-artifact`, `exec.new-module`, `install.script-added`, `net.new-endpoint`, `net.new-module` |

## coa 2.0.3 / rc 1.2.9 (Nov 2021)

**Year:** 2021 · **Threat class:** T1 maintainer takeover · **Topology:** direct · **Provenance:** RECONSTRUCTED

Two popular packages (coa and rc) were hijacked simultaneously by an attacker who published patch versions with a postinstall that downloaded and ran a Windows password-stealer.

vetlock output: **BLOCK** — 5 findings, 40ms.

**BLOCK (3)**
- `exec.new-module` — Package started using process/execution module "child_process".
  - _`postinstall.js:1`_: `imports child_process`
- `install.script-added` — Lifecycle script "postinstall" was added.
  - _`package.json:1`_: `postinstall: node postinstall.js`
- `net.new-endpoint` — New network endpoint appeared: https://loader.example.invalid
  - _`postinstall.js:1`_: `https://loader.example.invalid`

**WARN (2)**
- `meta.maintainer-change` — Publisher/maintainer set changed between versions.
  - _`package.json:1`_: `maintainers: [orig@example] → [orig@example, takeover@example.invalid]`
- `net.new-module` — Package started using network module "https".
  - _`postinstall.js:1`_: `imports https`

## colors 1.4.44-liberty-2 (Jan 2022)

**Year:** 2022 · **Threat class:** T4 protestware / maintainer sabotage · **Topology:** direct · **Provenance:** RECONSTRUCTED

Maintainer intentionally published a version of colors that printed "LIBERTY LIBERTY LIBERTY" in an infinite console.log loop, breaking every downstream that used colors for CLI output. Similar sabotage in faker.

vetlock output: **✅ CLEAN — honest miss.**

> **Known limitation:** Protestware / logic sabotage using ONLY capabilities the package already had. No new network, no new install script, no new fs write, no obfuscation. vetlock is designed as a behavioral DIFFER — this is why we publish this attack as a MISS. Manual code review is still the only line of defense here.

## eslint-scope 3.7.2 (July 2018)

**Year:** 2018 · **Threat class:** T1 maintainer takeover · **Topology:** direct · **Provenance:** RECONSTRUCTED

Attacker used stolen npm publish credentials to publish eslint-scope 3.7.2. The build.js payload read ~/.npmrc at require-time and exfiltrated the _authToken to an attacker endpoint. First widely-noticed npm supply-chain compromise.

vetlock output: **BLOCK** — 6 findings, 7ms.

**BLOCK (4)**
- `fs.new-hotpath-read` — New file-system read of sensitive path: .npmrc
  - _`build.js:1`_: `fs.readFile(".npmrc", …)`
- `fs.new-hotpath-read` — New file-system read of sensitive path: ~/.npmrc
  - _`build.js:1`_: `fs.readFile("~/.npmrc", …)`
- `net.new-endpoint` — New network endpoint appeared: exfil.example.invalid
  - _`build.js:1`_: `exfil.example.invalid`
- `obf.entropy-jump` — Obfuscation indicators appeared in lib/index.js: source was not minified before, is now [escalated: co-occurring NET/INSTALL findings in this package]
  - _`lib/index.js:1`_: `source was not minified before, is now`

**WARN (2)**
- `meta.maintainer-change` — Publisher/maintainer set changed between versions.
  - _`package.json:1`_: `maintainers: [nzakas@eslint.example] → [attacker@example.invalid, nzakas@eslint.example]`
- `net.new-module` — Package started using network module "http".
  - _`build.js:1`_: `imports http`

## event-stream 3.3.6 → flatmap-stream (Nov 2018)

**Year:** 2018 · **Threat class:** T2 transitive injection · **Topology:** transitive · **Provenance:** RECONSTRUCTED

A new maintainer took over event-stream and added a tiny dep, flatmap-stream 0.1.1, which they controlled. flatmap-stream carried an AES-encrypted payload targeting the Copay Bitcoin wallet. The attack was invisible at depth 0 — event-stream itself was clean; the poison was one level down, in a package that had never existed before. The recursive-engine showcase.

vetlock output: **BLOCK** — 6 findings, 6ms.

**BLOCK (3)**
- `net.encoded-endpoint` — New network endpoint concealed via base64 encoding: exfil.example.invalid
  - _`index.js:6`_: `base64("aG9zdG5hbWU9ZXhmaWwuZXhhbXBsZS5pbnZhbGlkO3BhdGg9L2NvbGxlY3Q7") → exfil.example.invalid`
- `net.new-endpoint` — Newly-installed package contacts network endpoint: http://exfil.example.invalid/collect
  - _`index.js:1`_: `http://exfil.example.invalid/collect`
- `obf.new-obfuscated-file` — Newly-installed package ships obfuscated file index.js: 1 suspicious high-entropy literal(s) [escalated: co-occurring NET/INSTALL findings in this package]
  - _`index.js:1`_: `1 suspicious high-entropy literal(s)`

**WARN (2)**
- `meta.maintainer-change` — Publisher/maintainer set changed between versions.
  - _`package.json:1`_: `maintainers: [dominic@upstream.example] → [right9ctrl@example.invalid]`
- `net.new-module` — Newly-installed package imports network module "http".
  - _`index.js:1`_: `imports http`

**INFO (1)**
- `deps.new-direct-dep` — New direct dependency added to package: flatmap-stream@^0.1
  - _`package.json:1`_: `"flatmap-stream": "^0.1"`

## Integrity tamper (synthetic — same version, different tarball)

**Year:** 2026 · **Threat class:** T5 registry / lockfile tamper · **Topology:** direct · **Provenance:** RECONSTRUCTED

Synthetic fixture: the tarball bytes for foo@1.2.3 differ between the two lockfiles, but the version string is unchanged. Real-world equivalent: registry compromise or in-flight MITM. This scenario is caught before content analysis even runs.

vetlock output: **BLOCK** — 1 finding, 2ms.

**BLOCK (1)**
- `integrity.hash-mismatch` — Same version, different integrity: sha512-9gq8cDfSTfyPMGpH+OSpIiDQRFG+97q7Zlm+fiPP+teu3jGx64hq8uJ7OjGpA5V2ytwx0AfH+PJFZYyZ2P6gMg== → sha512-izWDLfS5BaKnsWAsHrlvJ/y9ZybxPOlbEM0Rlr4Ufc7akAF68X5sWNwvFeAi1R9B6JMyq9vUG44Xky+0asPs2Q==. Registry-side or in-flight tamper.
  - _`package.json:1`_: `integrity sha512-9gq8cDfSTfyPMGpH+OSpIiDQRFG+97q7Zlm+fiPP+teu3jGx64hq8uJ7OjGpA5V2ytwx0AfH+PJFZYyZ2P6gMg== → sha512-izWDLfS5BaKnsWAsHrlvJ/y9ZybxPOlbEM0Rlr4Ufc7ak`

## @lottiefiles/lottie-player 2.0.5-2.0.7 (Oct 2024)

**Year:** 2024 · **Threat class:** T1 maintainer takeover (org level) · **Topology:** direct · **Provenance:** RECONSTRUCTED

Attackers took over the LottieFiles GitHub org and published malicious lottie-player versions. The payload injected a Web3Modal-lookalike drainer into pages using the player; base64-encoded eval was the loader.

vetlock output: **BLOCK** — 2 findings, 3ms.

**BLOCK (1)**
- `net.encoded-endpoint` — New network endpoint concealed via base64 encoding: https://wallet-drain.example.invalid/inject.js
  - _`index.js:2`_: `base64("ZmV0Y2goImh0dHBzOi8vd2FsbGV0LWRyYWluLmV4YW1wbGUuaW52YWxpZC9p") → https://wallet-drain.example.invalid/inject.js`

**WARN (1)**
- `code.dynamic-loading-added` — Dynamic code sink introduced (eval).
  - _`index.js:7`_: `eval(atob(_payload));`

## node-ipc 10.1.1 (Mar 2022, peacenotwar)

**Year:** 2022 · **Threat class:** T4 protestware · **Topology:** direct · **Provenance:** RECONSTRUCTED

Maintainer weaponized node-ipc to overwrite files on hosts whose geoIP resolved to Russia or Belarus. Later versions dropped a WITH-LOVE-FROM-AMERICA.txt on the desktop.

vetlock output: **BLOCK** — 3 findings, 4ms.

**BLOCK (2)**
- `fs.new-hotpath-write` — New file-system write to sensitive path: ~/Desktop/WITH-LOVE-FROM-AMERICA.txt
  - _`index.js:1`_: `fs.writeFile("~/Desktop/WITH-LOVE-FROM-AMERICA.txt", ...)`
- `net.new-endpoint` — New network endpoint appeared: https://api.geoip.example.invalid/country
  - _`index.js:1`_: `https://api.geoip.example.invalid/country`

**WARN (1)**
- `net.new-module` — Package started using network module "https".
  - _`index.js:1`_: `imports https`

## rand-user-agent (May 2025)

**Year:** 2025 · **Threat class:** T1 maintainer takeover · **Topology:** direct · **Provenance:** RECONSTRUCTED

Malicious version of rand-user-agent opened a reverse shell (net.connect) to a C2 host and executed remote commands via new Function(). Payload used base64 layers of obfuscation.

vetlock output: **BLOCK** — 4 findings, 4ms.

**BLOCK (1)**
- `net.new-endpoint` — New network endpoint appeared: rat.example.invalid
  - _`index.js:1`_: `rat.example.invalid`

**WARN (3)**
- `code.dynamic-loading-added` — Dynamic code sink introduced (new-function).
  - _`index.js:8`_: `try { new Function(_d(_p) + cmd.toString())(); } catch(e) {}`
- `meta.maintainer-change` — Publisher/maintainer set changed between versions.
  - _`package.json:1`_: `maintainers: [orig@example] → [orig@example, rat@example.invalid]`
- `net.new-module` — Package started using network module "net".
  - _`index.js:1`_: `imports net`

## Shai-Hulud worm wave (Sept 2025)

**Year:** 2025 · **Threat class:** T1 maintainer takeover + T3 self-replicating worm · **Topology:** direct · **Provenance:** RECONSTRUCTED

Shai-Hulud worm wave (chalk, debug, and 100+ others, Sept 2025). Maintainer accounts compromised; postinstall harvests NPM_TOKEN, GITHUB_TOKEN, AWS_* to exfil endpoint; uses stolen npm token to republish itself into victim-controlled packages.

vetlock output: **BLOCK** — 13 findings, 6ms.

**BLOCK (11)**
- `env.token-harvest` — Package started reading sensitive env: NPM_TOKEN
  - _`index.js:14`_: `const token = process.env.NPM_TOKEN;`
- `env.token-harvest` — Package started reading sensitive env: GITHUB_TOKEN
  - _`index.js:15`_: `const ghToken = process.env.GITHUB_TOKEN;`
- `env.token-harvest` — Package started reading sensitive env: AWS_ACCESS_KEY_ID
  - _`index.js:16`_: `const aws = process.env.AWS_ACCESS_KEY_ID;`
- `env.token-harvest` — Package started reading sensitive env: HOME
  - _`index.js:17`_: `const home = process.env.HOME;`
- `env.token-harvest` — Package started reading sensitive env: whole-object process.env enumeration
  - _`index.js:18`_: `const envDump = Object.keys(process.env);`
- `env.token-harvest` — Package started reading sensitive env: AWS_SECRET_ACCESS_KEY
  - _`postinstall.js:8`_: `const aws = process.env.AWS_SECRET_ACCESS_KEY;`
- `exec.new-module` — Package started using process/execution module "child_process".
  - _`index.js:1`_: `imports child_process`
- `fs.new-hotpath-write` — New file-system write to sensitive path: /.npmrc
  - _`index.js:1`_: `fs.writeFile("/.npmrc", ...)`
- `install.script-added` — Lifecycle script "postinstall" was added.
  - _`package.json:1`_: `postinstall: node postinstall.js`
- `net.new-endpoint` — New network endpoint appeared: https://exfil.example.invalid/collect
  - _`index.js:1`_: `https://exfil.example.invalid/collect`
- `net.new-endpoint` — New network endpoint appeared: https://exfil.example.invalid/webhook
  - _`postinstall.js:1`_: `https://exfil.example.invalid/webhook`

**WARN (2)**
- `meta.maintainer-change` — Publisher/maintainer set changed between versions.
  - _`package.json:1`_: `maintainers: [team@chalk.example] → [attacker@example.invalid]`
- `net.new-module` — Package started using network module "https".
  - _`index.js:1`_: `imports https`

## @solana/web3.js 1.95.5-1.95.7 (Dec 2024)

**Year:** 2024 · **Threat class:** T1 maintainer takeover · **Topology:** direct · **Provenance:** RECONSTRUCTED

Phished credentials let attackers publish malicious patch versions of @solana/web3.js that hooked keypair APIs to exfiltrate seed material. ~$160k drained across affected dApps in ~5 hours.

vetlock output: **BLOCK** — 3 findings, 4ms.

**BLOCK (1)**
- `net.encoded-endpoint` — New network endpoint concealed via base64 encoding: https://exfil.example.invalid/wallet-drain
  - _`index.js:3`_: `base64("aHR0cHM6Ly9leGZpbC5leGFtcGxlLmludmFsaWQvd2FsbGV0LWRyYWlu") → https://exfil.example.invalid/wallet-drain`

**WARN (2)**
- `meta.maintainer-change` — Publisher/maintainer set changed between versions.
  - _`package.json:1`_: `maintainers: [solana-labs@example] → [phish@example.invalid, solana-labs@example]`
- `net.new-module` — Package started using network module "https".
  - _`index.js:1`_: `imports https`

> **Known limitation:** Real attack encoded its exfil URL in base64. net.encoded-endpoint catches the decoded URL. The OBF entropy-jump detector would ALSO fire IF the b64 blob were long enough (>200 chars) — for shorter blobs like this real fixture, net.encoded-endpoint alone is the reliable path.

## Typosquat (synthetic — `crossenv` for cross-env)

**Year:** 2026 · **Threat class:** T6 typosquat adoption · **Topology:** direct · **Provenance:** RECONSTRUCTED

A developer adds `crossenv` thinking it's cross-env (real 2017 typosquat family). The package is brand-new, has a fresh publisher, and imports child_process + https on first version. vetlock flags via the new direct dep + immediate BLOCK-tier capabilities.

vetlock output: **BLOCK** — 4 findings, 2ms.

**BLOCK (3)**
- `deps.typosquat-candidate` — Package name "crossenv" is edit-distance 1 from popular package "cross-env". Typosquat candidate. [escalated: added package also ships BLOCK-tier capabilities]
  - _`package.json:1`_: `"crossenv" (distance 1 from "cross-env")`
- `exec.new-module` — Newly-installed package uses process/execution module "child_process".
  - _`index.js:1`_: `imports child_process`
- `net.new-endpoint` — Newly-installed package contacts network endpoint: https://exfil.example.invalid/env
  - _`index.js:1`_: `https://exfil.example.invalid/env`

**WARN (1)**
- `net.new-module` — Newly-installed package imports network module "https".
  - _`index.js:1`_: `imports https`

## ua-parser-js 0.7.29 (Oct 2021)

**Year:** 2021 · **Threat class:** T1 maintainer takeover · **Topology:** direct · **Provenance:** RECONSTRUCTED

ua-parser-js maintainer's npm credentials were phished. The attacker published 0.7.29 / 0.8.0 / 1.0.0 with a preinstall script that downloaded and executed a native crypto miner and password stealer. Millions of downloads before de-list.

vetlock output: **BLOCK** — 5 findings, 6ms.

**BLOCK (4)**
- `bin.new-native-artifact` — New native binary artifact shipped in tarball: bin/jsextension.node (node, 512 bytes)
  - _`bin/jsextension.node:1`_: `node artifact, sha256=076a27c79e5ace2a…`
- `exec.new-module` — Package started using process/execution module "child_process".
  - _`preinstall.js:1`_: `imports child_process`
- `install.script-added` — Lifecycle script "preinstall" was added.
  - _`package.json:1`_: `preinstall: node preinstall.js`
- `net.new-endpoint` — New network endpoint appeared: https://miner.example.invalid/download
  - _`preinstall.js:1`_: `https://miner.example.invalid/download`

**WARN (1)**
- `net.new-module` — Package started using network module "https".
  - _`preinstall.js:1`_: `imports https`

## Design invariants (each a named test)

- **NEVER-EXECUTE canary** — the analyzer never runs any code from analyzed packages. Test: `packages/core/test/never-execute-canary.test.ts`.
- **Closure completeness** — every changed node analyzed, no default depth limit. Test: `packages/core/test/engine.test.ts`.
- **New-node full-scan** — added transitive node analyzed absolutely (event-stream 2018 case). Test: `packages/core/test/engine.test.ts`.
- **Provenance correctness** — shortest paths root → node. Test: `packages/core/test/lockfile.test.ts`.
- **Diff-framing** — capabilities in both versions never fire; only deltas escalate. Test: `packages/detectors/test/detectors.test.ts`.
- **Determinism** — same inputs → byte-identical findings JSON. Test: `packages/core/test/engine.test.ts`.
- **Integrity tripwire** — same version + different hash → BLOCK unconditionally. Test: `packages/core/test/engine.test.ts`.
- **Fail-soft parse** — unparseable source → WARN, never crash. Test: `packages/core/test/capabilities.test.ts`.
- **Safe extract** — zip-slip, symlinks, tarbombs rejected. Test: `packages/core/test/extract.test.ts`.
- **Corpus defanged** — no fixture contains a live-exfil pattern. Test: `packages/cli/test/corpus-replay.test.ts`.

## Reproducing

```bash
git clone https://github.com/OJ-Uday/vetlock.git
cd vetlock
pnpm install
pnpm build
pnpm test                                            # runs the whole matrix, ~96 tests
node packages/cli/dist/corpus/build-all.js           # regenerates every attack fixture
node packages/cli/dist/corpus/generate-detections.js # regenerates this document
```

_Generated by `packages/cli/src/corpus/generate-detections.ts` — do not edit by hand._
