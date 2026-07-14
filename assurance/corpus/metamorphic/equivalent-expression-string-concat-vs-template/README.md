# equivalent-expression-string-concat-vs-template — analyzer emits extra URL literal from concat folding

**First entry in the assurance metamorphic corpus** (packet §5 P3). Landed with Wave 4-Q.

## What this demonstrates

A metamorphic pair from the `equivalent-expression` family. Both programs build the same
runtime URL against `example.com`; only the syntactic form differs.

```
// A — string concatenation
const http = require("http");
const host = "example" + ".com";
http.request("http://" + host + "/api");

// B — template literals
const http = require("http");
const host = `example.com`;
http.request(`http://${host}/api`);
```

At runtime the two programs are indistinguishable: same imports, same call, same string
argument, same effect. Under the metamorphic invariant, the analyzer's per-file capability
set MUST be identical.

## Current engine behavior (as of 2026-07-14)

`@vetlock/core`'s `extractCapabilities` reports:

- **A:** 4 findings — `http` module + THREE URL literals: `example.com`,
  `http://example.com`, `http://example.com/api`.
- **B:** 3 findings — `http` module + TWO URL literals: `example.com`,
  `http://example.com/api`.

The extra literal in A is `http://example.com` — the analyzer's constant-folding pass over
the concat expression `"http://" + host + "/api"` evidently emits the intermediate value
`"http://" + host` (which folds to `http://example.com`) as its own URL literal before
continuing on to fold in `+ "/api"`. The template-literal form in B folds the entire
substitution in one pass and emits only the final URL.

**Oracle verdict:** `oracleIdentityInvariant` FAIL — `findings count differs (4 vs 3)`.

## Why this matters (real completeness gap)

An analyzer's capability decision surface must be invariant under source-code shape when
runtime behavior is identical. If the engine reports different capabilities for A and B, a
downstream rule that keys on "number of distinct URL literals" (e.g. "flag any file with
>2 distinct URL constants") would fire on A but not B. An attacker can rewrite the
concatenation as a template literal — a mechanical transformation any minifier or
formatter can perform — to slip under the threshold.

The correct engine behavior is to normalize the intermediate constant-folded values away.
A URL literal set should contain only the *final* folded values, not every intermediate
step of the folding walk. The two programs are runtime-equivalent, so their capability
sets must be equal.

## How the gap was found

Assurance harness Wave 4-Q, pair generator `equivalent-expression` sub-case
`string-concat-vs-template` (assurance/src/metamorphic/equivalent-expression.ts). Emitted
by `generatePairBattery(2026, 20)` at battery indices 2 and 17 (the seed-derived cycle
hits this sub-case twice in a 20-entry battery). Reproduce with:

```ts
import { equivalentExpression } from '@vetlock/assurance/metamorphic';
import { runBounded } from '@vetlock/assurance/runner';
import { oracleIdentityInvariant } from '@vetlock/assurance/oracles';

// Emit the exact pair the battery uses at index 2.
// The seed-derivation is (2026 * 0x9e3779b1 + 2 * 0x85ebca6b) | 0.
const seed = (Math.imul(2026 | 0, 0x9e3779b1) + Math.imul(2 | 0, 0x85ebca6b)) | 0;
const pair = equivalentExpression.generate(seed);

const outcomeA = await runBounded(
  { kind: 'engine:extractCapabilities', enginePath: '@vetlock/core', relPath: 'pair.js', text: pair.a },
  { wallMs: 5_000, heapMb: 128, seed: 42 },
);
const outcomeB = await runBounded(
  { kind: 'engine:extractCapabilities', enginePath: '@vetlock/core', relPath: 'pair.js', text: pair.b },
  { wallMs: 5_000, heapMb: 128, seed: 42 },
);
const verdict = oracleIdentityInvariant(outcomeA, outcomeB);
// verdict.pass === false, verdict.reason includes 'findings count differs (4 vs 3)'
```

## Fixtures

- `fixture.a.js` — Program A (concatenation form). Committed for offline replay + defang-guard scanning.
- `fixture.b.js` — Program B (template-literal form). Same runtime semantics as A.

## Regression test

`assurance/test/metamorphic/invariance-e2e.test.ts` — the per-pair test for
`equivalent-expression-string-concat-vs-template` currently pins the gap: it asserts the
oracle FAILS with `findings count differs (4 vs 3)`. When STARTUP fixes the analyzer's
constant-folding pass to emit only final folded values, flip the assertion:

```ts
// BEFORE (documenting the gap):
expect(verdict.pass).toBe(false);
expect(verdict.reason).toMatch(/findings count differs \(4 vs 3\)/);

// AFTER (proving the fix):
expect(verdict.pass).toBe(true);
```

## Status

- **Found:** 2026-07-14 (assurance Wave 4-Q)
- **Filed as engine gap:** pending. STARTUP owns the fix (likely
  `packages/core/src/capabilities.ts` — the URL-literal collection pass in
  `extractCapabilities`). Assurance test pins the current behavior until STARTUP commits.
- **Superseded by:** (empty — corpus entries are never superseded lightly)
