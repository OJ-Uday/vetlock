# ADR 0012: Static (single-version) scan mode — "what does this thing DO?"

**Status:** Accepted, 2026-07-14

## Context

vetlock v0.3.0 answers *"what changed?"* — a diff between two lockfiles.
That's the highest-leverage question for the PR-review use case, and it's
where the false-positive floor stays low because we only surface capability
*deltas*.

But diff mode can't answer three real user questions:

1. **Vetting a brand-new dependency.** No prior version exists → diff is
   impossible → the answer must be a static profile.
2. **Auditing an existing tree.** "What does my current `node_modules` do,
   collectively?" is a legitimate question a security team asks before a
   major release.
3. **The live scanner on the site.** Someone pastes a single lockfile and
   wants to see something meaningful. Diff-mode requires two lockfiles, so
   the current live scanner needs a synthetic "empty" before-lockfile — a
   footgun and a UX limp.

## Decision

Add **`vetlock scan`** as a first-class CLI verb alongside `vetlock diff`.
Scan mode runs the same engine over a single input and produces a
**Capability Profile** — per-package and rolled up over the whole tree.

### Concrete surface

```
vetlock scan <target>

  <target> = <package>@<version>          # single-package scan
           | path/to/lockfile             # tree scan
           | path/to/node_modules-dir     # local-tree scan (installed deps)
```

### Output shape

A finding in scan mode carries `direction: 'absolute'` — a new enum value in
`Direction` (was `'added' | 'changed' | 'removed'`; now
`'added' | 'changed' | 'removed' | 'absolute'`). All detectors that ran in
diff mode continue to run — the difference is framing:

**Diff mode:**
```
· env.token-harvest — Package STARTED reading NPM_TOKEN
    index.js:14  process.env.NPM_TOKEN
```

**Scan mode:**
```
· env.token-harvest — Package reads NPM_TOKEN
    index.js:14  process.env.NPM_TOKEN
```

The finding, evidence, provenance, and severity are the same. The verb tense
is different — and that's the whole point: scan mode can't say "started
doing X" because there's no baseline.

### Capability Profile (the top-level output)

```
vetlock scan chalk@5.3.1
──────────────────────────────────────────────
Capability profile — chalk 5.3.1

  code-execution:   ⛔ BLOCK  (child_process, index.js:1)
  net-egress:       ⛔ BLOCK  (https, index.js:1)
  secret-read:      ⛔ BLOCK  (NPM_TOKEN, GITHUB_TOKEN, AWS_*)
  fs-write:         ⛔ BLOCK  (~/.npmrc)
  install-hook:     ⛔ BLOCK  (postinstall)
  obfuscation:      ✓ none
  wasm:             ✓ none
  bundled-deps:     ✓ none

Blast radius (tree scan mode only):
  packages exercising capability X: N
```

The **capability manifest** is the collapse-to-headline: "this tree can
execute code [3 pkgs], write outside scope [1], egress to 4 domains, run 2
install scripts, read 3 secrets." That's the SBOM-of-behavior — a different
artifact from an SBOM-of-names and, arguably, more useful for a security
review.

### Posture-framed severity, not diff-framed

Diff mode has a natural severity model: "started doing X" is almost always
worse than "was already doing X" (a package's declared purpose already covers
its existing capabilities). Scan mode can't lean on that.

Instead scan mode uses **posture-framed severity**:

- `BLOCK` — the capability's default severity in vetlock's schema (e.g.
  `env.token-harvest` is BLOCK-default regardless of mode).
- Anomaly signal — if an optional `ecosystem-norm baseline` is available, a
  posture-framed finding can be marked ANOMALOUS when the package is outside
  the norm for its class ("a leaf logging library that reads NPM_TOKEN + adds
  an install script + egresses is anomalous even with no prior version").
- Honest degradation — when no norm baseline is available, the CLI prints
  "capabilities reported, no norm comparison" instead of pretending we have
  a comparison. (No lying by ambient assertion.)

The norm baseline is a v2 feature; v1 scan mode ships with posture-only
severity and the honest degradation message. Norm-baseline work is deferred
to a follow-up ADR (0015 or later) with its own dataset governance.

## Enforcement

- **`scan-absolute-findings.test`** — feed a single-package input into the
  engine; assert every emitted finding has `direction: 'absolute'`.
- **`scan-tree-rollup.test`** — feed a lockfile; assert the per-package
  findings roll up into a whole-tree capability manifest with correct counts.
- **`scan-no-baseline-degrades-honestly.test`** — when no norm-baseline is
  configured, assert the output includes the "no norm comparison" degraded
  message rather than a fake severity ranking.
- **NEVER-EXECUTE canary (ADR 0005)** runs unchanged. Static analysis, static
  in every mode.

## Rationale

- **Live-scanner UX unlock.** The site's scanner currently requires two
  lockfiles or hacks a synthetic empty one. Scan mode is the honest verb for
  "here's my lockfile, what does it do?" — one input, real analysis.
- **New-dependency vetting.** Security teams evaluate a candidate library
  BEFORE they add it. Scan mode is the tool for that; diff mode structurally
  can't be.
- **Rollup is a real product.** "This tree exercises capability X across N
  packages" is the SBOM-of-behavior a regulated buyer actually wants (an
  SBOM-of-names doesn't answer "what does it do?").
- **Zero engine reuse cost.** Every detector already runs on both sides of
  a diff; running on one side alone is a re-framing, not new engine work.

## Consequences

- The `Direction` type union grows to include `'absolute'`. Every existing
  detector that emitted `'added' | 'changed' | 'removed'` is unchanged; a new
  scan-mode wrapper in the engine sets `direction: 'absolute'` on the way out.
- Finding message text needs a small tense-adjustment layer (diff mode says
  "started X"; scan mode says "does X"). This is a rendering-time transform
  (`packages/cli/src/tty.ts`) and NOT a detector-code change — the finding
  itself carries the mode, and the renderer decides how to phrase it.
- The `--format osif` export from ADR 0013 works in both diff mode and scan
  mode: diff produces `entry_point: <how the change happened>`; scan produces
  `entry_point: <the discovered entry-point>`.
- Site's live scanner (companion PACKET-VETLOCK-SITE.md) migrates from the
  current hack (fake empty before-lockfile) to a real `vetlock scan` call.
  That's a P4a-blocking site change.
- Doc updates: README's positioning ladder (`diff` primary → `scan` also-
  primary), THREAT-MODEL adds a "scan-mode threats" subsection (a scan-mode-
  only user still gets NEVER-EXECUTE and safe-extract, but there's no
  integrity-tripwire signal — a same-version tamper attack needs the diff
  frame to detect).

## Non-goals

- Scan mode does NOT trigger network scans, port scans, or any active
  probing. "Scan" here means "static analysis of a package's own bytes,"
  not "vulnerability scan of the running system." The word is used in the
  vetlock-lockfile-ecosystem sense, not the network-security sense — every
  README/doc mention should include a one-line "we scan the package's own
  content, we don't scan your network" disambiguation.
- Scan mode does not attempt to run install-time code to observe what would
  happen. NEVER-EXECUTE (ADR 0005) still applies.
- Scan mode does not persist any of the target's source content in the
  hosted path — the ephemeral-analysis invariant (ADR 0008) still applies.
