# vetlock red-team report

_2026-07-12 · vetlock v0.2.0 · adversarial-verify pass complete_

## Statistics

| Stage | Count |
|---|---|
| Total exploits proposed (6 red-teamers × 2 rounds) | **48** |
| After dedup (3 merged as duplicates) | **45** |
| **CONFIRMED** by independent adversarial verifier | **35** |
| PLAUSIBLE (verifier couldn't trace end-to-end) | 1 |
| PARTIAL (works less severely than claimed) | 7 |
| REFUTED (verifier proved does not work) | 2 |

**Confirmation rate: 35/45 = 73%.** The verifier defaulted to REFUTED and required a full source-level trace to CLEAN or non-BLOCK. That the confirm rate is this high indicates the exploits were code-anchored, not speculative.

## Executive summary

Vetlock is not a reliable defense against a competent supply-chain attacker today. Six independent red-team teams generated 48 exploit candidates in disjoint territories; after de-duplication and an adversarial verifier that defaults to *refuted*, **35 of 45 candidates (73%) were confirmed end-to-end, 1 was plausible, 7 were partial, and only 2 were refuted**. That confirmation rate is not a sign that the red team was lenient — the verifier required a complete source-level trace from attacker input to CLEAN or non-BLOCK verdict — it is a sign that vetlock's detection surface has structural gaps at every layer: lockfile parsing, AST analysis, escalation logic, config trust, and cache lookup. Twelve of the confirmed exploits are severity **critical** (D1, D2, F1, F2, L1, L2, L3, L9, N1, N2, S1, S2, S10) and four more are compositional **BLOCK-severity** chains (C1, C2, C3, C5) that produce a fully clean verdict on genuinely malicious diffs.

An attacker aware of these findings would not attempt anything subtle. The three cheapest, highest-impact avenues, in order, are: (1) **ship the payload inside `bundledDependencies/*/node_modules/**` (N1)** — analyze.ts:116 unconditionally skips every `node_modules/` path, so 13 detectors go silent for zero effort; (2) **include a `.vetlock.json` in the same malicious PR (S2, C1, C2, D1, D2, D3)** — the config file is trusted from the diff under review and offers half a dozen documented knobs (`ignorePackages`, `severityOverride`, `ignorePathsInside: [""]`, `trustedPublishers: [""]`) that each silence the entire finding stream against the attacker's own package; and (3) **hand vetlock a pnpm-lock.yaml or yarn.lock (F1)** — the CLI advertises support but crashes with exit 3, which most CI configurations will treat as an infrastructure blip and not a security failure. None of these require any code obfuscation, AST cleverness, or novel evasion technique. They are configuration and format quirks.

## Cross-cutting themes

- **Detectors match literal AST shapes and string constants rather than semantic behavior.** Every process-env / require / child_process detector fires only on one canonical spelling of the operation, so trivially equivalent alternatives are invisible: destructured env (L1), spread env (L2), `Reflect.get(process.env, …)` (L5), computed alias `process["env"]` (L8), `require.call(null, 'child_process')` (L3), `eval("require('child_process')")` (L10), rot13-encoded URLs (L11), bare hostnames on unlisted TLDs (L4). This is not a small set of oversights — it is the structural cost of pattern-matching an untyped, dynamic language with a fixed list of syntactic templates. An attacker who spends thirty minutes with the visitor code can pick any equivalent form vetlock does not enumerate.

- **The `.vetlock.json` config file is trusted from the same diff it is meant to police.** S2 is the umbrella, and D1, D2, D3, C1, and C2 are five distinct ways the same trust boundary is monetised: overriding severity (D1), zero-prefix path ignores (D2), empty-string trust lists (D3), advisory-known package ignores (C1), and hardcoded evidence-file conventions that make one path prefix wipe an entire detector class (C2). Any red-team run against a tool that ships a config file will find variants of this — but the specific defect here is that string fields are accepted with no `.min(1)`, no wildcard restriction, and no round-trip semantic check against a benign baseline.

- **Escalation rules can be gamed by staying just under a co-occurrence threshold.** The escalation engine requires *combinations* of categories to promote WARN→BLOCK: OBF needs NET or INSTALL (S8, L9), typosquat needs a BLOCK-tier capability (D5), compound-3 needs both ≥3 findings *and* ≥2 categories (D4, S5). An attacker who ships OBF+EXEC+ENV+FS — the exact Shai-Hulud shape (L9) — never triggers the OBF→BLOCK rule because none of those four is NET or INSTALL. The rules encode analyst intuition about what a "real" attack looks like; the intuition is out of date.

- **Blindspots in name/module allowlists give free evasion by naming.** TOP_NPM_NAMES is missing openai, stripe, firebase, nodemailer, discord.js, and the entire `@sentry/*` and `@nestjs/*` scopes (D6). EXEC/NETWORK_MODULES is missing `inspector`, `trace_events`, `async_hooks` (N2) and `dns` (N3). URL_REGEX omits `.top`, `.pw`, `.zip`, `.click`, `.info`, `wss://`, and bare hostnames (L4, N3, L11). These are list-completeness bugs, but "add more entries" is not a fix — the underlying defect is that critical detection is gated on manually curated finite lists.

- **The analyzer conflates "what the lockfile says" with "what npm install actually installs."** F2 (link:true is skipped), F6 (yarn npm: alias hides real tarball name), N5 (git+ssh / patch: resolved fields are analyzed against registry content), C5 (case-preserved names miss lowercase TOP_SET / trust-store / advisory lookups), S9 (attacker-controlled file:// path), S10 (blank old integrity suppresses the tripwire), and S1 (integrity used as cache key before verification) are all instances of the same class: the parser trusts fields the attacker writes as ground truth for identity, path, or content.

## Priority recommendations

1. **Stop trusting `.vetlock.json` when it is part of the diff under review.** Load the config from the *before* side of the PR, or require it to live on a signed baseline branch, or reject any run where `.vetlock.json` appears in the changeset. Closes **S2, C1, C2, D1, D2, D3** (six confirmed criticals/BLOCKs). **Small** effort — one CLI flag, one existence check, one clear failure mode.

2. **Analyze `node_modules/**` inside tarballs.** Change `isAnalyzableSource` in analyze.ts:116 to include bundled node_modules — either recursively analyze them as first-class packages or, at minimum, run the capability detectors on their JS. Closes **N1** (single-shot 13-detector bypass, currently the cheapest full evasion). **Medium** effort — the extractor already walks these files; the guard is one line, but you will need per-file scoping for evidence.

3. **Make the pnpm/yarn code path actually work, or advertise npm-only and exit clean.** F1 (advertised-support crash) is a critical because CI treats exit 3 as flake, not fail. Fixing this properly means finishing the LockGraph shape for pnpm/yarn; a cheap intermediate is a `WARN unsupported-lockfile-format` finding with a non-zero-but-explicit exit code that CI can distinguish. Closes **F1**. **Medium** if fixed properly, **small** if the intermediate WARN path is acceptable.

4. **Rewrite the process/env/require detectors to bind at the *value* level, not the AST-node level.** Track the value flowing through variables and member access so `Reflect.get(process.env, x)`, `{...process.env}`, `const {NPM_TOKEN} = process.env`, `process["env"]`, and `require.call(null, 'child_process')` collapse to the same finding as the canonical form. Closes **L1, L2, L3, L5, L8, L10** (five criticals + one high). **Large** — this is real dataflow work in `capabilities.ts`, not a pattern addition, but each remaining literal-shape detector is another future exploit.

5. **Remove the co-occurrence gates on escalation rules where the individual signals are already high-signal.** OBF should escalate on OBF+EXEC or OBF+ENV or OBF+FS as well as OBF+NET/INSTALL (S8). Typosquat should escalate on any BLOCK-tier *or* multiple WARN-tier capabilities (D5). Compound-3 should escalate on 3+ WARN in any 1+ categories, dropping the ≥2 categories requirement (D4, S5). Closes **D4, D5, S5, S8, L9**. **Small** — these are threshold changes in `detectors/src/index.ts`, but they will require regression testing against known-benign packages.

6. **Fix the integrity-changed tripwire so an empty old integrity does not suppress it.** Treat `oldIntegrity === ''` on an existing name as "unknown-before, present-after" and emit the T5 BLOCK; separately, do not accept a lockfile-supplied integrity as a *cache key* before content verification. Closes **S1, S10** (two criticals) and hardens **C6** (plausible). **Small** for the T5 patch; **medium** for the cache-key fix, since the cache path has performance implications.

7. **Reject or hard-warn on `link: true`, yarn `npm:` aliases, git+ / patch: / file:// resolved fields whose apparent name diverges from the fetched name.** Analyze what will be *installed*, not what the lockfile *labels* it. Closes **F2, F6, N5, S9**. **Medium** — the fetchTarball path and lockfile parser both need to grow a "declared-vs-effective" identity concept.

8. **Reject empty-string entries and wildcard-adjacent values in every config field.** Schema-level `.min(1)`, reject `""` in `trustedPublishers` values (D3), `ignorePathsInside` values (D2), and any exact-match string that would degenerate to a match-all under `.includes` / `.startsWith`. Closes **D2, D3** and preempts the next generation of empty-string-degeneration bugs. **Small** — pure zod schema tightening.

9. **Fail-closed on analyzer errors and timeouts.** Currently `safeExtract` errors and >90s parses silently emit zero findings (S4), and unterminated backtick chains crash `@babel/traverse` (L6). A tarball that costs vetlock more than $X wall-clock or throws should emit a BLOCK-tier `analysis-failed` finding, not CLEAN. Closes **S4, L6** and the tail of similar future defects. **Small**.

10. **Match publisher trust-store entries with equality on parsed email components, not substring `.includes`.** Parse the email to `local@domain`, compare `domain` exactly (with an optional subdomain-suffix rule). Closes **S3**. **Small** — one function in `publishers.ts`.

## Methodology retrospective

The territory partitioning (Language / Format / System / Compositional / Defender-corner / Novel) worked well for coverage but leaked at the seams. Language and Format shared the AST-shape / lockfile-shape boundary cleanly; System covered cache and TOCTOU; Compositional was the highest-yield territory because it forced red-teamers to chain findings that individually looked minor (C1, C2, C3, C5 all combine 2–4 primitives into full-CLEAN outcomes). The Novel category earned its budget with N1, N2, N3, and N5 — genuinely orthogonal blindspots that would not have surfaced from a purely defensive read of the codebase. The one visible overlap was between Language (L11: rot13 URLs) and Novel (N3: DNS-subdomain exfil): both attack the "how does exfil leave the box" surface but from opposite ends of the pipeline; better dispatch would have kept them together. The one visible gap was **install-script surface** — no red-teamer meaningfully attacked the `install-script-added` / `preinstall`/`postinstall` detection path, and there is likely low-hanging fruit there.

The "default to refuted" verifier is doing its job. The 73% confirmation rate is not a signal of leniency — of the 10 non-confirmed outcomes, one was plausible, seven were partial (real defects with over-claimed impact), and only two were fully refuted. A lenient verifier produces almost no partials because it accepts the red-teamer's framing wholesale; the seven partials (F9, N4, F10, F8, C4, S7, S8) are exactly the "the mechanism is real but you overstated it" verdicts you want from a strict verifier. The two full refutations (F7 YAML-alias bomb, N6 pnpm peerDependencies) both turned on library-behavior claims that source inspection contradicted. The high confirm rate reflects that the red-teamers proposed *specific*, code-anchored exploits rather than speculative behaviors — a consequence of the six-team parallel structure and the pre-instruction to trace to a line number.

Three things I would change in a future run against a similar tool. First, **budget one team for install-hook / lifecycle-script exploits explicitly** — this was the ghost territory here. Second, **have the verifier flag partials by the axis they were over-claimed on** (severity, exploitability, reachability) rather than a single label; the seven partials collapsed useful distinctions. Third, **run the verifier at reduced effort as a first-pass filter and full effort only on the survivors** — the confirm rate suggests roughly two-thirds of verifier compute went to green-lighting well-researched claims, which is wasted intelligence when the goal is to catch the speculative minority.

---

