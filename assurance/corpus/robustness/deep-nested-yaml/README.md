# deep-nested-yaml — pnpm-lock.yaml with pathological YAML nesting

**First entry in the assurance robustness corpus** (packet §5 P1). Landed with P1.3.
**Status: GAP CLOSED — wave 4-T (see bottom of file for commit SHA).**

## What this demonstrates

A `pnpm-lock.yaml`-shaped YAML document with `child:` keys nested 100+ levels deep. Real
pnpm-lock files nest 3-6 levels, so this input is syntactically legal but semantically
absurd — exactly the shape an attacker delivers.

## Engine behavior BEFORE fix (2026-07-14, `origin/main@c20a66d`)

`@vetlock/core`'s `parseLockfileText` dispatched to `parsePnpmLockText` for `pnpm-lock.yaml`
inputs, which called `js-yaml`. `js-yaml` has a built-in `maxDepth: 100` guard and throws a
`YAMLException` when exceeded. The engine did not catch this — the exception escaped to the
caller.

**Assurance runner outcome:** `kind: 'crash'`, `error.name: 'YAMLException'`,
`error.message: "nesting exceeded maxDepth (100) (...)"`.

**Oracle verdict:** `oracleNoCrash` FAIL, `oracleFailSafe` FAIL. `oracleNoHang` and
`oracleNoOom` pass (the exception fires within milliseconds, well under bounds).

## Engine behavior AFTER fix (wave 4-T)

`parsePnpmLockText` now wraps `yaml.load()` in a try/catch. Any parse error — including
`YAMLException` with the `maxDepth (100)` message — is rethrown as
`UnsupportedLockfileError`. The assurance runner (`worker.ts` + `child-entry.ts`)
recognizes `UnsupportedLockfileError` on the `engine:parseLockfileText` path and translates
it to the `fail-safe` channel, mirroring how it already handles
`extractCapabilities.parseError` and `runDiff` `analysis.failed`.

**Assurance runner outcome:** `kind: 'fail-safe'`, with a single BLOCK-severity
`analysis-failed` finding whose reason references `maxDepth`.

**Oracle verdict:** all four (`oracleNoCrash`, `oracleFailSafe`, `oracleNoHang`,
`oracleNoOom`) PASS.

## Why blocking this matters (attack class in the wild)

An attacker who can influence the lockfile of a scanned dependency (via a compromised
publish or a typo-squat) can DoS the analyzer by embedding a deep-nested YAML payload. If
vetlock is running as a CI check on every PR, a crash-on-analysis input turns the analyzer
into a merge blocker via denial-of-service — every PR touching that dep fails until the
scanner is either fixed or bypassed. Bypassing an analyzer is worse than blocking it.

The correct engine behavior is to catch the `YAMLException` and emit an
`analysis.failed` finding (BLOCK severity, `META` category) — the engine's existing
fail-safe convention. This turns the DoS surface into a "we couldn't analyze this,
so we're blocking conservatively" — which is what a security tool must do.

## How the gap was found

Assurance harness P1.3, generator `deep-nested-yaml` (assurance/src/robustness/deep-nested-yaml.ts).
Seed 1, params `{depth: 100}` — deterministic. Reproduce with:

```ts
import { deepNestedYaml } from '@vetlock/assurance/robustness';
import { runBounded } from '@vetlock/assurance/runner';

const input = deepNestedYaml.generate(1, { depth: 100 });
const outcome = await runBounded(
  {
    kind: 'engine:parseLockfileText',
    enginePath: '@vetlock/core',
    text: input.text,
    filename: input.filename,
  },
  { wallMs: 5_000, heapMb: 128, seed: 42 },
);
// AFTER wave 4-T: outcome.kind === 'fail-safe', with an analysis-failed BLOCK finding.
// (BEFORE: outcome.kind === 'crash', outcome.error.name === 'YAMLException'.)
```

## Fixture

`fixture.pnpm-lock.yaml` — the exact input the generator produces at depth=100. Committed
for offline replay + defang-guard scanning (must remain empty of live network/exec/etc.).

## Regression test

`assurance/test/robustness/no-crash.test.ts::deep-nested-yaml`. Assertion post-flip:

```ts
// Now (wave 4-T fix landed):
expect(outcome.kind).toBe('fail-safe');
expect(oracleFailSafe(outcome).pass).toBe(true);
```

## Status

- **Found:** 2026-07-14 (assurance P1.3)
- **Filed as engine gap:** 2026-07-14 (wave 4-T)
- **Fix landed:** 2026-07-14, branch `wave4-t-startup-fix-yaml-maxdepth`, engine-side
  commit `d8b100a` (core: wrap js-yaml.load in fail-safe; rewrap YAMLException as
  UnsupportedLockfileError). Assurance-side assertion flip lands in the follow-up
  commit on the same branch.
- **Superseded by:** (empty — corpus entries are never superseded lightly)

