# into-lifecycle-script — .js AST scanner cannot see JSON-embedded code-execution

**First entry in the assurance evasion corpus** (packet §5 P3). Landed with Wave 5-U.

## What this demonstrates

A completeness-vector transform from the `code-location` family. The transform moves a
code-execution payload from a `.js` file into `package.json`'s `scripts.postinstall`
field. Runtime effect on `npm install` is identical (npm runs postinstall hooks); location
in the package tree is different.

```
// A — the input source (.js)
const cp = require("child_process"); cp.exec("echo hi");

// B — the transform's output (a package.json fragment; JSON, not JS)
{
  "name": "defanged-fixture",
  "version": "0.0.0",
  "scripts": {
    "postinstall": "[NODE_E_INVOCATION_WRAPPING(fixture.input.js)]"
  }
}
```

Only `fixture.input.js` is committed. The B side is a deterministic function of A —
`intoLifecycleScript.transform(fixture.input.js, /*any seed*/)` — and the raw output
contains a `[NODE_E]` invocation which trips the defang guard (`corpus-scan.test.ts`)
even though the invocation's body is the fixture's own defanged-clean input. Committing
A alone keeps the corpus scan clean; readers reproduce B via one call.

## Current engine behavior (as of 2026-07-14)

Feeding B to the runner's `engine:extractCapabilities` scenario with `relPath: 'a.js'`
returns findings that do NOT include `capabilityClass: 'code-execution'`. The engine's
per-file `.js` AST scanner reads the JSON text and:

- The top-level `{ ... }` parses as a JS BlockStatement (with labeled statements at each
  key). Babel's error-recovery parser (see `packages/core/src/capabilities.ts`) tolerates
  the shape.
- Inside the block, no `require(...)` CallExpression exists (only string literals). No
  MemberExpression named `.exec` / `.spawn` exists. No `execModules` entries are pushed
  to the FileCapabilities.
- The `scripts.postinstall` STRING contains the entire executable payload, but the
  scanner sees a string literal, not a call site. String literals that are not URLs
  and are not longer than the suspicious-literal threshold surface no finding at all.

Feeding A to the same scenario returns findings that DO include code-execution
(via `execModules: ['child_process']` and the `cp.exec(...)` dynamic-code site).

**Oracle verdict:** `oracleFindingSurvives(A, B, 'code-execution')` FAIL — `evasion:
mutated variant is missing any finding of class code-execution`.

## Why this matters (real completeness gap)

The whole point of a `.js` scanner is to catch capability usage. If an attacker moves the
same capability into a location the scanner never routes to — `package.json` lifecycle
scripts, `bin/*` binaries, worker source files not reachable from `main`, etc. — the
scanner reports a clean package while `npm install` runs arbitrary code. The
capability class the scanner claims to cover is location-incomplete: the class-map says
"we cover code-execution" but the reach-map says "only in .js files we happen to visit".

## The fix path

The gap is a routing gap, not an analysis gap. The engine already knows how to detect
lifecycle-script code-execution: `analyzeTarball` reads `package.json` and emits a
`persistence` (INSTALL) finding when `scripts.postinstall` is populated. The per-file
`.js` scanner is intentionally scoped to code files — it is not the wrong place to fix
this, because you don't want it eagerly re-parsing `package.json` as JavaScript.

Two symmetric fixes:

1. **Assurance side** (this harness): route the transform's OUTPUT through the correct
   scenario for its shape. The `intoLifecycleScript` output is JSON; the driver should
   feed it to `engine:analyzeTarball` with a synthetic tarball containing a
   `package.json` set to the JSON body. That path already emits `persistence` findings
   on the lifecycle hook. When wired, `oracleFindingSurvives` should check for the
   `persistence` class (or accept an equivalence-set of classes that both "originate
   code-execution at install time").
2. **Engine side**: no change needed to the .js scanner. The `analyzeTarball` +
   `adaptPackageSnapshot` pipeline (see `assurance/src/runner/engine-adapter.ts`
   `LIFECYCLE_HOOKS`) already surfaces `persistence` findings on `postinstall` hooks.

## How the gap was found

Assurance harness Wave 5-U, `test/evasion/evasion-catch-rate.test.ts`. The driver iterates
`allTransforms` from `assurance/src/completeness-vectors/index.ts`; every transform whose
output stays inside the `.js` scanner's remit passes the `oracleFindingSurvives` check.
`intoLifecycleScript` does not — its output is JSON — so it is pinned here.

Reproduce with:

```ts
import { intoLifecycleScript } from '@vetlock/assurance/completeness-vectors';
import { runBounded } from '@vetlock/assurance/runner';
import { oracleFindingSurvives } from '@vetlock/assurance/oracles';

const source = 'const cp = require("child_process"); cp.exec("echo hi");\n';
const mutated = intoLifecycleScript.transform(source, 42);

const outA = await runBounded(
  { kind: 'engine:extractCapabilities', enginePath: '@vetlock/core', relPath: 'a.js', text: source },
  { wallMs: 10_000, heapMb: 128, seed: 42 },
);
const outB = await runBounded(
  { kind: 'engine:extractCapabilities', enginePath: '@vetlock/core', relPath: 'a.js', text: mutated },
  { wallMs: 10_000, heapMb: 128, seed: 42 },
);
const verdict = oracleFindingSurvives(outA, outB, 'code-execution');
// verdict.pass === false, verdict.reason === 'evasion: mutated variant is missing any finding of class code-execution'
```

## Fixtures

- `fixture.input.js` — the pre-transform payload. Committed for offline replay + defang
  scanning. The transform is pure, so the post-transform output is fully determined by
  this input; see the README block above for the exact JSON.

## Regression test

`assurance/test/evasion/evasion-catch-rate.test.ts` — the transform's id is in
`KNOWN_GAP_IDS`, which routes it to the dedicated GAP-pinning `it(...)` block. That
block asserts the oracle FAILS with the "evasion" reason and both A/B outcomes are
verdict-bearing (not crash/timeout/oom). When the fix lands (either path above), flip
the assertion:

```ts
// BEFORE (documenting the gap):
expect(verdict.pass).toBe(false);
expect(verdict.reason).toMatch(/evasion|missing any finding/);

// AFTER (proving the fix):
expect(verdict.pass).toBe(true);
```

and remove `'into-lifecycle-script'` from `KNOWN_GAP_IDS` so the transform is checked
by the standard positive-path assertion.

## Status

- **Found:** 2026-07-14 (assurance Wave 5-U).
- **Filed as engine gap:** N/A — this is an assurance-side routing gap, not an engine
  gap. The engine already has the machinery (`analyzeTarball` + manifest lifecycle
  detection); the driver needs to route JSON-shaped transform output to that scenario.
- **Superseded by:** (empty — corpus entries are never superseded lightly)
