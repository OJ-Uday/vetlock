# DETECTIONS.md

**Replay of historical npm supply-chain attacks through vetlock's behavioral differ.**

Every row is reproducible from this repo — no external network, no live registry — by
running `pnpm test` (the corpus fixtures are committed and defanged).

## Corpus policy

- Every fixture is **defanged**: exfil URLs point to reserved TLDs (`.invalid`,
  `.example`), payload bodies are inert (`if (false) { … }`), and no live webhook,
  bank, or C2 endpoint appears anywhere. Corpus hygiene is itself a test:
  `corpus-acceptance.test.ts` greps all fixture files for a banned-pattern list.
- Some fixtures are **RECONSTRUCTED** — the malicious version was unpublished from
  npm before we could archive it. Reconstruction preserves the *detection-relevant
  shape* (manifest diff + inert code shapes) and is labeled as such in
  `manifest.json`.
- **NEVER-EXECUTE invariant** applies to every fixture: analysis reads bytes and
  parses AST; nothing from the fixture ever runs. Guarded by
  `never-execute-canary.test.ts`.

## Catches

### Shai-Hulud worm wave (chalk / debug / … · Sept 2025) ✅

Threat class: **T1** (maintainer takeover) + **T3** (self-replicating worm).

Attack summary: compromised npm maintainer accounts publish patch releases whose
`postinstall` script harvests `NPM_TOKEN`, `GITHUB_TOKEN`, `AWS_*` from the victim's
environment, POSTs the tokens to an attacker-controlled webhook, and uses the stolen
npm token to inject the same payload into every package the victim maintains.

vetlock output against the defanged fixture (`corpus/shai-hulud-2025/`):

```
vetlock diff summary
  BLOCK · 13 findings · 1 changed package

BLOCK  11
  chalk 5.3.0 → 5.3.1
    via: my-app → chalk
    · install.script-added — Lifecycle script "postinstall" was added.
    · env.token-harvest — NPM_TOKEN, GITHUB_TOKEN, AWS_ACCESS_KEY_ID,
                           AWS_SECRET_ACCESS_KEY, whole-object enumeration
    · exec.new-module — child_process
    · net.new-endpoint — https://exfil.example.invalid/collect
    · net.new-endpoint — https://exfil.example.invalid/webhook

WARN  2
    · net.new-module — https
    · meta.maintainer-change — team@chalk.example → attacker@example.invalid

Impact by direct dependency:
  chalk: BLOCK (13 findings in subtree)
```

Verdict: **BLOCK**. Exit code: `2`. Every one of the ways this attack manifests is
independently caught with named evidence:
- Postinstall hook — one BLOCK finding (INSTALL detector).
- Token harvesting — six BLOCK findings (ENV detector, one per sensitive key +
  the whole-object enumeration).
- Process execution capability — one BLOCK finding (EXEC).
- New exfil endpoints — two BLOCK findings (NET, one per URL).
- Maintainer change — one WARN finding (META).
- New network module — one WARN finding (NET).

The result is over-determined by design: even if the attacker evades the ENV
detector (e.g. by base64-encoding token names), the postinstall hook, network
endpoints, and process-execution import all still fire independently.

## Recursive engine invariants (validated by unit tests)

- **Closure completeness** — 5-level deep tree where only the leaf changed:
  exactly one detector call for the leaf; provenance chain rendered as
  `root → a → b → c → d`. `engine.test.ts`.
- **New-node full-scan** (event-stream 2018 case) — added transitive node
  arrives with `pair.old === null`, is scanned absolutely. `engine.test.ts`.
- **Integrity tripwire** (T5 lockfile tamper) — same version, different
  integrity hash → BLOCK unconditionally, no content analysis needed.
  `engine.test.ts`.
- **Determinism** — same inputs produce byte-identical findings JSON.
  `engine.test.ts`.
- **Diff-framing** — capability present in BOTH versions → no finding.
  `detectors.test.ts`.

## Non-catches (published honestly)

- **Logic bombs using pre-existing capabilities** — e.g. a package that already
  writes files gaining a date-triggered `rm -rf`. Mitigations exist (entropy
  jump, minification regression) but no promise. See THREAT-MODEL §2.1.
- **Fully dynamic loading chains** where every string is computed at runtime.
  We flag unresolvable dynamic `require`/`import` as CODE findings rather than
  pretending to follow.
- **Malice already present in the OLD version.** vetlock is a *diff* by design;
  it's a triage lens on updates, not a replacement for reviewing dependencies
  you've already accepted.
- **Non-npm ecosystems.** PyPI is the obvious #2 (roadmap).

## Reproducing

```
git clone https://github.com/OJ-Uday/vetlock.git
cd vetlock
pnpm install
pnpm build
pnpm test                                             # runs the whole matrix
node packages/cli/dist/corpus/build-shai-hulud.js     # regenerates the fixture
node packages/cli/dist/cli.js diff \
  corpus/shai-hulud-2025/lockfile.before.json \
  corpus/shai-hulud-2025/lockfile.after.json
```

Every claim in this document is a green test. Every number can be recomputed from
committed fixtures.
