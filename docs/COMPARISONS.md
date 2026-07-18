# vetlock vs guarddog, Socket, Snyk, npm audit — honest positioning

**Purpose.** Every supply-chain scanner claims to catch supply-chain attacks. This document explains what **vetlock actually does that the alternatives do not**, and — equally important — what the alternatives do that vetlock does not. If you're standing up a defense-in-depth pipeline, you probably want two or three of these tools together, not one.

The comparison is deliberately **capability-shaped**, not marketing-shaped. Every "yes" and "no" below is backed by a public source (source repo, docs page, or product page). Corrections welcome as issues or PRs.

## 1. The threat-model diagram — where each tool sits on the timeline

A modern npm supply-chain attack (Shai-Hulud 2025, rand-user-agent 2025, ua-parser-js 2021, …) unfolds along this timeline:

```
  ┌─────────────────┐   ┌──────────────────┐   ┌─────────────────┐   ┌──────────────┐   ┌──────────────┐
  │  1. developer   │──▶│  2. npm install  │──▶│  3. postinstall │──▶│  4. exfil    │──▶│  5. PR       │
  │  types          │   │     resolves +   │   │     hook runs   │   │     token /  │   │     lands    │
  │  `npm i foo`    │   │     downloads    │   │     ON DEV BOX  │   │     env vars │   │     in CI    │
  └─────────────────┘   └──────────────────┘   └─────────────────┘   └──────────────┘   └──────────────┘
                                                          │
                                                          │  ← DAMAGE HAPPENS HERE
                                                          ▼
                                                   TOO LATE for any
                                                   PR-time / CI-time
                                                   scanner to help

  Where each tool sits on this timeline:

  ┌────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │                                                                                                    │
  │      ▲ vetlock `add`          ▲ vetlock `diff`   ▲ Socket Firewall (CLI proxy, commercial)         │
  │      │ (pre-fetch,            │ (CI, PR-time)    ▲ Socket GitHub App (PR-time)                     │
  │      │  local behavioral)     ▲ guarddog (CI or dev CLI, point-in-time)                            │
  │                               ▲ Snyk (CI, PR-time; advisory DB match)                              │
  │                               ▲ npm audit (CI or local, advisory DB match)                         │
  │                                                                                                    │
  │  step 1               step 2              step 3           step 4           step 5                 │
  └────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

Two important qualifiers on the diagram:

1. **"Pre-fetch" means before ANY npm code from the analyzed package runs.** For vetlock `add` the tarball is fetched, extracted to a sandbox, statically analyzed, and only then does npm see the install command. For Socket Firewall the fetch is intercepted at the *registry-proxy* layer; Socket's SaaS backend decides pass/block based on their reputation database. Both prevent execution, but the trust model is different — vetlock is local behavioral analysis (offline, no auth), Socket Firewall is a SaaS DB lookup (network dependent, subscription).

2. **"Point-in-time" (guarddog) means one version at a time, no diff.** Every URL, every install script, every network call is treated as a fresh observation, not as a delta. That is not a bug — it's a design choice — but it means guarddog cannot say *"axios STARTED contacting a new domain"* the way vetlock's diff engine can. It just says *"axios contacts these domains,"* and the analyst has to remember whether that's new.

## 2. Feature matrix

| Capability                                                                     | vetlock                                       | guarddog       | Socket                        | Snyk       | npm audit  |
| :----------------------------------------------------------------------------- | :-------------------------------------------- | :------------- | :---------------------------- | :--------- | :--------- |
| **Pre-install execution prevention (developer CLI, offline)**                  | Yes (`vetlock add`, Wave 8-JJ) [1]            | No             | Partial [2]                   | No         | No         |
| **Pre-install execution prevention (SaaS proxy)**                              | No (by design — no SaaS)                      | No             | Yes (Socket Firewall) [3]     | No         | No         |
| **Diff-framed detection (before / after lockfile)**                            | Yes (`vetlock diff`)                          | No             | No                            | No         | No         |
| **CVE / GHSA advisory database lookup**                                        | No (by design — behavioral, not advisory)     | No             | Yes (via Socket data)         | Yes        | Yes (GHSA) |
| **Behavioral detection of NEW capability (novel malice, no CVE required)**     | Yes                                           | Yes            | Yes                           | Partial    | No         |
| **Capability-map + coverage gate (CI refuses a coverage regression)**          | Yes [4]                                       | No             | No                            | No         | No         |
| **Assurance harness — standing adversary, robustness + metamorphic + differential ledger** | Yes                                | No             | No                            | No         | No         |
| **MITRE ATT&CK tactic on every finding**                                       | Wave 8-MM adopts [5]                          | Yes            | Yes                           | No         | No         |
| **Package-level risk score (0-10 or equivalent)**                              | Wave 8-MM adopts [5]                          | Yes (0–10)     | Yes (0–100)                   | Yes (CVSS) | No         |
| **SARIF output for GitHub code-scanning**                                      | Yes (`--sarif`; Wave 8-MM promotes to default)| Yes            | Not documented                | Yes        | No         |
| **Trust-store maintainer awareness (BUILTIN_TRUST_STORE + user allowlist)**    | Yes                                           | Partial [6]    | Partial                       | No         | No         |
| **Python (PyPI) parity via AST-driven detectors**                              | Yes (`packages/core/src/adapter-pypi.ts`)     | Partial (YARA) | Partial                       | Yes        | No (Node-only) |
| **JS / npm coverage**                                                          | Yes                                           | Yes            | Yes                           | Yes        | Yes        |
| **Go / RubyGems / GitHub Actions coverage**                                    | No (npm + PyPI only)                          | Yes            | Yes (Go)                      | Yes        | No         |
| **Free / open-source (Apache-2.0 or MIT)**                                     | Yes (Apache-2.0)                              | Yes (Apache-2.0) | No (commercial) [7]         | No (commercial with free tier) | Yes (bundled with npm) |
| **Self-hosted, no auth wall, zero telemetry**                                  | Yes                                           | Yes            | No                            | No         | Yes        |
| **NEVER-EXECUTE canary — soul test that fails the build if any package code runs** | Yes ([ADR 0005](adr/0005-never-execute.md))  | Sandbox-based (Landlock / Seatbelt) [8] | Not documented | Not applicable (advisory DB) | Not applicable (advisory DB) |
| **Adversarial / red-team test suite bundled with the tool**                    | Yes ([REDTEAM-2026-07-12.md](REDTEAM-2026-07-12.md), 35 confirmed exploits, 31 closed) | Sample corpus | Not documented | Not documented | Not applicable |
| **Compound-suspicion escalator (co-occurring signals → BLOCK)**                | Yes                                           | Yes (via risk engine) | Yes                    | No         | No         |
| **Hyphen-permutation typosquat detection (`foo-bar` ⇄ `bar-foo`)**             | Wave 8-KK adopts [5]                          | Yes            | Not documented                | No         | No         |
| **Rule-file-based detector authoring (declarative)**                           | Partial (JSON capability-map; ports being added) | Yes (YARA)   | Not user-authored             | Not user-authored | No |

**Notes:**

- [1] `vetlock add` lands in Wave 8-JJ (pre-install gate CLI, wraps `npm install <pkg>` with a pre-fetch behavioral scan). See the CTA in the root README.
- [2] "Partial" — vetlock's `add` command is the local-only, offline route to pre-install prevention. It is not a SaaS proxy.
- [3] Socket Firewall intercepts registry traffic and consults Socket's cloud database. Requires a Socket subscription + network availability + trusting the vendor with the identity of every package your team installs.
- [4] `packages/detectors/src/capability-map.json` — every capability × sink × detector × test × corpus-ref is enumerated; `capability-map.test.ts` refuses to merge additions without a matching fixture. See [`docs/CAPABILITY-MAP.md`](CAPABILITY-MAP.md).
- [5] Wave 8-KK / 8-LL / 8-MM are landing the near-1:1 detector ports and the architectural insights (MITRE tactics, risk score, SARIF-first) surfaced by the [guarddog comparative audit](../assurance/docs/audits/guarddog-comparative-audit.md).
- [6] guarddog has a `deceptive_author` heuristic (disposable-domain match, being ported as `meta.disposable-author-domain` in Wave 8-KK) but no BUILTIN_TRUST_STORE / user-side allowlist.
- [7] Socket has a free tier for small OSS projects (per their pricing page) but core product is commercial; Socket Firewall in particular is a subscription feature.
- [8] guarddog runs archive extraction inside Landlock (Linux) / Seatbelt (macOS). vetlock does not extract arbitrary tarballs — it operates on tarballs npm has already extracted for the developer — so the sandbox trade-off is different. If vetlock ever scans arbitrary URLs directly, an equivalent sandbox will land first ([threat-model note](THREAT-MODEL.md)).

## 3. Where vetlock is intentionally different

This is the part that gets lost in feature-matrix comparisons. Some of the "no" columns above are **not gaps** — they're the shape of the product.

### 3.1 vetlock is not an advisory-DB lookup tool

If you want to know whether `lodash@4.17.19` matches a known CVE, use `npm audit`, `osv-scanner`, or Snyk. That is a solved problem. vetlock's answer to "does this package have a known vulnerability?" is **"we don't know and we don't check"** — because that is not the class of attack vetlock exists to catch.

vetlock catches the class of attack where **there is no CVE yet**. The malware is fresh, the maintainer just got their account taken over, the package published five minutes ago. Advisory databases lag zero-days by days-to-weeks; the diff-framed behavioral engine catches the update in the PR that introduces it.

### 3.2 vetlock has no point-in-time verdict on a package

"Is `express` safe?" is not a question vetlock answers. `express` in isolation, ambient at rest, is neither safe nor unsafe from vetlock's perspective. **Only the diff between two versions of express matters.**

This is why the pretty output says *"express STARTED reading NPM_TOKEN,"* not *"express reads NPM_TOKEN."* The verb tense is not marketing — it is the entire product bet.

The consequence: a package that ships a first-ever malicious version cannot be "graded" by vetlock, because there is no previous version to diff against. First-version-cluster mode (`deps.first-version-cluster`) covers the "brand-new namespace with clustered version publish shape" pattern for exactly this case, but that is a *heuristic on the timing of publishes*, not a rating of the package itself.

If you want per-package point-in-time ratings, use Socket or guarddog. vetlock is the diffing complement, not the substitute.

### 3.3 vetlock does not rate every package 0-10

There is no "vetlock score" you can look up for `chalk` on npm's dependency browser. A package that has no changes has no verdict. A package with changes has a verdict on THE CHANGES, not on the package.

Wave 8-MM adds a package-level 0-10 score aggregating findings *when there are findings*, so CI can gate on `--fail-above 7.5` without wiring per-detector rules. But the score is derived from the current diff's findings, not from an ambient reputation lookup.

### 3.4 vetlock does not clone repos or check registry integrity

Two of guarddog's metadata detectors (§1.5 G-18 metadata-manifest mismatch, §1.5 G-19 repository-integrity mismatch) require either a network call to the registry API or a git clone of the declared repo. vetlock's design is offline-by-default; both are documented as intentional non-goals in the [comparative audit](../assurance/docs/audits/guarddog-comparative-audit.md). Users who need them run guarddog alongside vetlock — the tools are complementary.

### 3.5 vetlock does not sandbox package execution

Because vetlock does not execute package code. Ever. See [ADR 0005](adr/0005-never-execute.md) and `packages/core/test/never-execute-canary.test.ts` — the canary fails the build if any static-analysis pass would accidentally run a package's code. This is the single most load-bearing invariant in the codebase; every detector is written under it.

Compare: guarddog uses Landlock / Seatbelt sandboxes around **archive extraction** (not execution — extraction). Socket Firewall uses a registry proxy but the packages that pass still run. `npm audit` and Snyk don't touch package code at all (they match versions to advisories). The invariants are different across tools and worth understanding before you compose them.

## 4. When to use which tool

Honest recommendations. Pick the pattern that matches your team's flow; the tools compose.

### "I `npm install foo` from the CLI daily on my dev box"

**Use `vetlock add`.** (Wave 8-JJ.) It wraps `npm install`, fetches the tarball, does a behavioral scan pre-execution, and refuses installs that trip BLOCK-tier detectors. Offline, no auth, no telemetry. It is the closest thing to a *safe-npm-install* the OSS ecosystem has.

If you also want a SaaS opinion on the package's overall reputation, run **Socket Firewall** in front of it — Socket's DB has good coverage of known-malicious packages and the two layers stack cleanly (Socket blocks known-bad, vetlock blocks behaviorally-suspicious).

### "I want CI to block a PR that adds a new suspicious dependency"

**Use `vetlock diff` in your PR workflow.** Configure the [GitHub Action](../action/README.md), set `fail-on: install.script-added,env.token-harvest,net.new-endpoint,integrity.hash-mismatch` — the PR sticky comment + SARIF upload cover the reviewer + code-scanning surfaces.

If the org is big enough to justify commercial spend, layer **Socket GitHub App** on top for the ambient "this dep is reported bad by our fleet" signal, and keep **Snyk** for CVE-based blocking. Three axes, three tools.

### "I want a CVE / GHSA audit of my current dependency tree"

**Use `npm audit` or `osv-scanner`.** Free, well-maintained, purpose-built. vetlock does not have and will not add an advisory-DB lookup — that is the wrong tool. `osv-scanner` in particular covers 20+ ecosystems from one binary.

If you need enterprise-grade CVE tracking with fix suggestions, remediation SLAs, and license compliance, **Snyk** is the standard commercial choice.

### "I want a per-package rating / reputation on any dependency I look at"

**Use Socket.** Socket's whole product is the graded per-package view (0-100 across Supply Chain / Quality / Maintenance / Vulnerability / License axes). guarddog and vetlock both refuse to give you that grade — they only speak to what a specific package does, not what it *is*.

### "I want a broad rule catalog of known-bad fingerprints (crypto miners, reverse shells, stego, homoglyphs, disposable-domain authors)"

**Use guarddog today; vetlock is catching up.** guarddog's 54 YARA rules + 9 metadata heuristics + risk engine is the biggest OSS rule catalog in the space right now. vetlock's [comparative audit](../assurance/docs/audits/guarddog-comparative-audit.md) inventories every guarddog rule and classifies each as REAL GAP / PARTIAL / COVERED / INTENTIONAL-NON-GOAL — the 10 near-1:1 ports identified there are landing across Waves 8-KK and 8-LL.

### "I want to combine tools honestly"

Recommended stack for a security-serious team, cheapest to most expensive:

1. **npm audit** (bundled with npm) — free CVE floor.
2. **vetlock diff** in PR CI — free behavioral diff floor.
3. **vetlock add** on dev CLI — free pre-install gate on dev boxes.
4. **guarddog** as a scheduled scanner over top-N direct deps — free deeper rule catalog for the packages you care about most.
5. **Socket GitHub App** for ambient PR reputation signal — commercial, but the SaaS DB catches things a local scanner cannot.
6. **Snyk** for enterprise CVE workflows, remediation SLAs, license compliance — commercial.

The tools do not overlap fully. Every one of them catches things the others miss. **The safe assumption is that any single scanner has a false-negative floor of 20-40% on real-world attacks;** the point of composing them is to drive that floor down.

## 5. Where these numbers come from

Every "yes" and "no" in §2 is derived from public sources:

- **guarddog**: [github.com/DataDog/guarddog](https://github.com/DataDog/guarddog) — read on 2026-07-15. See also [`../assurance/docs/audits/guarddog-comparative-audit.md`](../assurance/docs/audits/guarddog-comparative-audit.md) for the full detector-by-detector inventory that vetlock's coverage claims are measured against.
- **Socket**: [socket.dev](https://socket.dev) product page — Socket Firewall, GitHub App, dependency-search scoring.
- **Snyk**: [snyk.io](https://snyk.io) product page — advisory DB coverage, SARIF output, commercial tiers.
- **npm audit**: `npm audit` bundled with npm CLI ≥ 6, backed by the GitHub Advisory Database.
- **vetlock**: this repository at `HEAD` — every "yes" is anchored to a specific file (detector source, test, ADR) linked from the [README](../README.md) or the [capability map](CAPABILITY-MAP.md).

If any row is wrong, please open an issue citing the source that contradicts it — corrections are landed the same day. This document is meant to be usable by procurement, security-review committees, and skeptical engineers; getting it wrong on the record hurts everyone.
