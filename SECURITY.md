# Security policy

## Reporting a vulnerability

Please **do not** open a public issue for security-sensitive reports. Instead, contact:

- **GitHub Security Advisories:** https://github.com/OJ-Uday/vetlock/security/advisories/new

We'll acknowledge receipt within 3 business days and aim to have a fix (or a documented
mitigation) within 30 days of receipt for high-severity issues, sooner for critical.

## Scope

vetlock is a static analyzer that never executes analyzed package code (see
[docs/adr/0005-never-execute.md](docs/adr/0005-never-execute.md)). The security-critical
surfaces we care most about:

- **Safe extraction** (`packages/core/src/extract.ts`). Zip-slip, symlinks, tarbombs. A
  regression here would let a malicious tarball write outside vetlock's temp dir.
- **NEVER-EXECUTE invariant.** If someone finds a code path that causes analyzer machinery
  to invoke content from an analyzed package, that's a critical issue.
- **Parser resilience.** Any input that panics vetlock hard (segfault, hang > 30 s) qualifies.
- **Cache poisoning.** The snapshot cache is content-addressed; anyone who can trick it into
  returning the wrong snapshot for a hash has changed our results.
- **Registry auth handling.** pacote does most of this; report configuration paths that could
  leak credentials.

## Not in scope

- **Correctness of the detector taxonomy itself.** Missing a novel attack shape is an FP/FN
  research issue, not a vulnerability. File it as a normal bug or a detector proposal.
- **Third-party dependency vulnerabilities.** Please report those upstream first; we'll
  bump quickly once fixed.

## Supply-chain hygiene of vetlock itself

- Releases go out with `npm publish --provenance` (SLSA attestation) — a security tool must
  not itself be a supply-chain risk.
- All commits are signed.
- CI has vetlock running on its own PRs (`vetlock-dogfood.yml`).

## Known limitations (post-v0.3.0 red-team review)

A follow-up red-team pass after v0.3.0 (docs/REDTEAM-2026-07-12.md) surfaced 15 additional
exploit candidates without a `REDTEAM <ID> FIX` code tag. One (N4) was closed directly; the
rest are disclosed here rather than silently left open. "Fix effort" reflects the original
red-team assessment; none of these are fixed as of this writing.

- **C1 — GHSA-cited findings droppable via `ignorePackages`.** `applyConfig`'s
  `ignorePackages` filter runs before verdict recomputation and has no exemption for
  findings carrying a GHSA/CVE annotation, so a same-PR `.vetlock.json` can still erase a
  known-malicious-version citation. Partially mitigated by the config-trust boundary
  (`decideConfigApplication` — REDTEAM S2/C1/C2/D1 FIX) when the config is genuinely in the
  diff, but a config committed to a trusted baseline *before* the malicious PR still
  suppresses the finding with zero visibility. Tracking: give advisory-annotated findings a
  hard verdict floor that `ignorePackages` cannot clear, independent of config trust.
- **C2 — `ignorePathsInside: ["package.json"]` silences all manifest-anchored findings for a
  package,** including `integrity.hash-mismatch` (an `ALWAYS_APPLY_DETECTORS` entry) —
  because the `ignorePathsInside` filter is a `.filter()` step that runs before the
  `ALWAYS_APPLY_DETECTORS` exemption, which only guards the later severity-override/allowlist
  `.map()` steps. Same partial mitigation/gap as C1. Tracking: give manifest-synthesized
  findings (`integrity.hash-mismatch`, `meta.maintainer-change`, `install.script-added`) a
  non-file-shaped evidence anchor so `ignorePathsInside` structurally cannot match them, and
  make the `ALWAYS_APPLY_DETECTORS` exemption cover the drop-filters too, not just the
  severity-mutating steps.
- **C4 — pnpm workspace-only lockfiles with no `importers['.']` produce an empty root,
  emptying `rollupByDirect` and provenance for every finding.** Confirmed open via direct
  repro (`parsePnpmLockText` on a workspace-only fixture yields `root deps: []`). Same root
  cause as F8. Tracking: merge all importers into a synthetic root in
  `packages/core/src/lockfile-pnpm.ts`, plus a loud renderer warning when
  `rollupByDirect` is empty. Fix effort was assessed small, but touches the pnpm parser's
  root-resolution contract and several renderers — deferred rather than rushed within the
  20-minute budget for this pass.
- **C6 — cache-poisoning compositional variant.** The core S1 cache-poisoning attack is
  closed (HMAC-authenticated cache entries, `packages/core/src/cache.ts` — verified: a
  forged envelope without the per-install HMAC key is rejected and treated as absent). C6's
  residual concern — an attacker with a *legitimate* prior cache-write (their own earlier
  `vetlock` run under the same uid) planting a benign snapshot that a later lockfile pins to
  by matching integrity — is not fully addressed; the HMAC defends against foreign-uid
  writes, not against a same-uid process choosing to cache something misleading before the
  target PR is reviewed. Tracking: re-verify integrity against the original tarball location
  on cache hit rather than trusting the stored snapshot unconditionally.
- **F3 — CLOSED (this pass).** REDTEAM S10 closed "old integrity blank, new populated." The
  mirror direction — old integrity populated, new integrity blank — was left open and, worse,
  pinned as intentional by an existing test (`redteam-S1-S10.test.ts > "does NOT fire when new
  integrity is blank"`). That test was itself the bug. The corrected rule fires whenever the
  (old, new) integrity pair is not-equal AND at least one side is populated; only both-blank
  produces no signal. See `packages/core/src/changeset.ts` (F3 FIX block) and the replacement
  regression tests in `redteam-S1-S10.test.ts`.
- **F5 — believed closed, not independently regression-tested under this ID.** F5 describes
  the same "same-PR config self-exemption" shape as S2/C1/C2/D1. Verified via direct repro
  that `decideConfigApplication` + `applyConfig` together preserve BLOCK severity for the
  exact fixture in the F5 report. No new F5-specific regression test was added since the
  existing `redteam-config-trust.test.ts` suite already exercises this shape; if a reviewer
  wants an F5-labeled test for traceability, that's a small addition.
- **F7 — YAML alias-expansion bomb in `pnpm-lock.yaml` is unguarded.**
  `packages/core/src/lockfile-pnpm.ts` calls `yaml.load(yamlText)` with js-yaml's default
  schema (alias resolution enabled) and no post-parse size cap or timeout. Confirmed:
  `js-yaml`'s `FAILSAFE_SCHEMA` disables the anchor/alias round-trip (verified — the
  10-level nested-alias fixture that expands to ~46 MB under the default schema parses to a
  few flat strings/arrays under `FAILSAFE_SCHEMA`), which is close to the suggested fix, but
  switching schemas changes what shapes the parser accepts and needs verification against
  every real-world pnpm-lock.yaml fixture in `corpus/` before it ships — that verification
  didn't fit in the 20-minute budget for this item. Tracking: switch to
  `FAILSAFE_SCHEMA` (or add an explicit post-parse `JSON.stringify(...).length` cap) with a
  full corpus-replay pass to confirm no legitimate lockfile shape regresses.
- **F8 — pnpm workspace importer confusion (provenance-only variant of C4).** Same root
  cause and same fix as C4; see above.
- **F9 — pnpm parser silently drops packages whose keys don't match the strict
  `name@version` grammar.** Confirmed via direct repro:
  `parsePnpmPackageKey('malicious-1.0.0')`, `'(peer)malicious@1.0.0'`, `'foo@'`, and
  `'@1.0.0'` all return `null` and the corresponding tarball is never fetched or analyzed.
  Tracking: add a fallback name-extraction path keyed off `resolution.tarball`, or emit a
  WARN finding pointing at the unparseable key instead of silently continuing.
- **F10 — `safeExtract`'s `totalBytes` accounting is racy across concurrent tar entries.**
  Confirmed via code read: `packages/core/src/extract.ts` buffers each entry's chunks into a
  `Buffer[]` and only calls `hooks.addTotal(bytes)` after the entry's write completes
  (line ~273); `inFlight` tracks in-flight promises for join purposes but does not bound
  concurrency. A tarball with many entries just under the per-entry cap can spike RSS well
  past `maxTotalBytes` before accounting catches up. Fix requires refactoring
  `writeFileEntry` into a streaming/backpressure-aware writer with a concurrency semaphore —
  assessed as medium effort, out of scope for a 5-line close.
- **L7 — CLOSED, verified under the L1/L2/L5 FIX tag (not a new tag).** `const { X, ...rest }
  = process.env` is handled by the `RestElement` branch at
  `packages/core/src/capabilities.ts:943-946`, which records `keys: null` (whole-object
  enumeration) — `env.ts`'s `isSensitive` treats `keys === null` as sensitive, so this
  produces a BLOCK finding. Regression coverage already exists at
  `packages/core/test/redteam-L1-L10-dataflow.test.ts:79-80`. No code change needed; listed
  here only for audit completeness.
- **N4 — CLOSED this pass.** See `packages/detectors/src/typo.ts` (scope-stripping +
  trusted-scope allowlist) and `packages/detectors/test/redteam-tail-N4.test.ts`.
- **N6 — pnpm/yarn lockfile parsers never merge `peerDependencies` into the dependency
  graph,** so a malicious package reachable ONLY via a peer-dependency edge has no parent in
  the graph and no provenance. Confirmed via code read of
  `packages/core/src/lockfile-pnpm.ts` (deps merge omits `peerDependencies`) and
  `packages/core/src/lockfile-yarn.ts` (`YarnEntry` interface has no `peerDependencies`
  field at all). The suggested fix is a genuinely small, isolated change (add the field to
  both parsers' merge sets) with no existing test pinning the current behavior — this is the
  best CLOSE-NOW candidate for a fast follow-up, deferred here only because it didn't fit
  inside this pass's time budget after C1/C2/C4/C6/F3/F7/F8/F9/F10 verification.
- **S7 — advisory prerelease-republish evasion.** `semver.satisfies('1.2.9-hotfix', '=1.2.9',
  { includePrerelease: true })` is `false` — confirmed directly — so a compromised prerelease
  republish of an advisory-listed version loses its GHSA citation and confidence bump. The
  codebase already has an `adjacentAdvisories()` helper (REDTEAM C3 FIX,
  `packages/detectors/src/advisories.ts:177`) built for a related "adjacent version" evasion,
  but it is exported and unit-tested standalone — never called from `runAll()`
  (`packages/detectors/src/index.ts`). Tracking: either extend `adjacentAdvisories` to cover
  the prerelease-of-exact-match shape and wire it into `runAll`, or normalize the version
  (strip prerelease tag) before the primary `advisoriesForVersion` check.
- **S8 — CLOSED, verified under the L9/S8 FIX tag (not a new tag).** Escalation 1 in
  `packages/detectors/src/index.ts:98` already expands the OBF-escalation risky-category set
  to `{NET, INSTALL, EXEC, ENV, FS}` — exactly the suggested fix. No code change needed;
  listed here only for audit completeness.

None of the above are exploitable to defeat the NEVER-EXECUTE invariant or achieve code
execution inside the vetlock process itself; they are detection-evasion / false-negative
classes in the diff-analysis pipeline. Tracked for a follow-up pass — see
docs/REDTEAM-2026-07-12.md "Post-v0.3.0 status" for the running count.
