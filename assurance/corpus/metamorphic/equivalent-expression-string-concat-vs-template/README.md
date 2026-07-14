# equivalent-expression-string-concat-vs-template — analyzer emits extra URL literal from concat folding

**First entry in the assurance metamorphic corpus** (packet §5 P3). Landed with
Wave 4-Q; **CLOSED in Wave 5-W** — see Status section for the fix commit SHA.

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

## Original engine behavior (pre-fix, as of 2026-07-14)

`@vetlock/core`'s `extractCapabilities` reported:

- **A:** 4 findings — `http` module + THREE URL literals: `example.com`,
  `http://example.com`, `http://example.com/api`.
- **B:** 3 findings — `http` module + TWO URL literals: `example.com`,
  `http://example.com/api`.

The extra literal in A was `http://example.com` — the analyzer's constant-folding pass
over the concat expression `"http://" + host + "/api"` emitted the intermediate value
`"http://" + host` (which folds to `http://example.com`) as its own URL literal before
continuing on to fold in `+ "/api"`. The template-literal form in B folds the entire
substitution in one pass and emits only the final URL.

**Original oracle verdict:** `oracleIdentityInvariant` FAIL — `findings count differs (4 vs 3)`.

## Post-fix engine behavior (Wave 5-W)

`extractCapabilities` now reports IDENTICAL findings for both forms:

- **A:** 3 findings — `http` module + TWO URL literals: `example.com`, `http://example.com/api`.
- **B:** 3 findings — `http` module + TWO URL literals: `example.com`, `http://example.com/api`.

**Post-fix oracle verdict:** `oracleIdentityInvariant` PASS.

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
// Post-Wave-5-W: verdict.pass === true.
// Pre-Wave-5-W:  verdict.pass === false, verdict.reason included 'findings count differs (4 vs 3)'.
```

## Fix (Wave 5-W)

`packages/core/src/capabilities.ts` → the internal `iterateFolds` generator. The
post-fold sweep visits every AST node the constant-folding pass resolved to a
string and re-runs `URL_REGEX` / `LOOKS_LIKE_PATH` / `tryDecodeUrl` against each
folded value. Pre-fix, that visitor emitted every folded node — including
BinaryExpression nodes whose parent BinaryExpression was itself folded. The
fix: skip any folded node whose immediate parent is also folded.

Rationale: the parent's folded value is the concatenation of the child's plus
its siblings, so it's a strict superset of the child's — any URL / path /
encoded-URL signal present in the child is already emitted by the parent's
sweep. Emitting both was redundant AND asymmetric across shape (template
literals fold in one pass and never produced the inner intermediate).

Constraints preserved by the fix:

- The FINAL folded URL is still emitted — the outermost folded value's parent
  is a CallExpression / VariableDeclarator (not folded), so the sweep still
  reaches it.
- Deep concat chains (`"a" + "b" + "c" + "d"`) collapse to a single outer
  emission — verified by the nested-concat guard in the regression test.
- Direct `StringLiteral` visitor emissions are unaffected — the dedupe applies
  only to the fold-map sweep. A bare `"https://example.invalid/api"` literal in
  source is still extracted through the same StringLiteral path it always was.

## Fixtures

- `fixture.a.js` — Program A (concatenation form). Committed for offline replay + defang-guard scanning.
- `fixture.b.js` — Program B (template-literal form). Same runtime semantics as A.

## Regression tests

- `packages/core/test/capabilities-url-literal-invariance.test.ts` — engine-level
  pin: feeds both forms through `extractCapabilities` and asserts identical
  urlLiterals set + count. Adds a nested-concat guard so the fix itself can't
  silently regress into re-emitting intermediates.
- `assurance/test/metamorphic/invariance-e2e.test.ts` → the dedicated
  `CLOSED (Wave 5-W): equivalent-expression-string-concat-vs-template` test —
  routes the pair through the full bounded-runner pipeline and asserts
  `oracleIdentityInvariant` PASSES. If a future engine change re-introduces
  the intermediate emission, this test fires with the corpus reference
  immediately visible.

## Status

- **Found:** 2026-07-14 (assurance Wave 4-Q)
- **Filed as engine gap:** yes — STARTUP owned the fix in
  `packages/core/src/capabilities.ts` (the `iterateFolds` post-fold sweep).
- **CLOSED:** 2026-07-14 (assurance Wave 5-W). Fix commit SHA: `6f9ece02c438708f7f575502770b016199f577b8`.
- **Superseded by:** (empty — corpus entries are never superseded lightly)
