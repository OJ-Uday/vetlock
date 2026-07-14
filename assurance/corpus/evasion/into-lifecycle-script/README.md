# into-lifecycle-script — CLOSED (Wave 6-AA routing fix)

**First entry in the assurance evasion corpus** (packet §5 P3). Landed with Wave 5-U;
routing-fix-closed by Wave 6-AA.

## Status

- **Found:** 2026-07-14 (assurance Wave 5-U).
- **Filed as engine gap:** N/A — this is an assurance-side routing gap, not an engine
  gap. The engine already has the machinery (`analyzeTarball` + manifest lifecycle
  detection); the driver was routing the transform's JSON output to the wrong scenario.
- **Closed:** 2026-07-14 (assurance Wave 6-AA). Routing fix — the transform's output goes
  to `engine:analyzeTarball` (manifest pipeline), not `engine:extractCapabilities` (per-file
  .js AST scanner). See `assurance/test/evasion/evasion-catch-rate.test.ts` — the entry is
  now in `ANALYZE_TARBALL_ROUTED_IDS` and has a dedicated `it(...)` block that materializes
  the transform output as a real tarball on disk and proves the payload's capability
  surfaces as `persistence` (via `adaptPackageSnapshot`'s `LIFECYCLE_HOOKS` set).

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

## The routing gap (pre-Wave 6-AA)

Feeding B to the runner's `engine:extractCapabilities` scenario with `relPath: 'a.js'`
returned findings that did NOT include `capabilityClass: 'code-execution'`. The engine's
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

Feeding A to the same scenario returned findings that DO include code-execution
(via `execModules: ['child_process']` and the `cp.exec(...)` dynamic-code site).

**Old oracle verdict (against extractCapabilities on both sides):**
`oracleFindingSurvives(A, B, 'code-execution')` FAIL — `evasion: mutated variant is
missing any finding of class code-execution`.

## Why the routing gap mattered

The whole point of a `.js` scanner is to catch capability usage. If an attacker moves the
same capability into a location the scanner never routes to — `package.json` lifecycle
scripts, `bin/*` binaries, worker source files not reachable from `main`, etc. — the
scanner reports a clean package while `npm install` runs arbitrary code. The engine's
manifest pipeline (`analyzeTarball` + `adaptPackageSnapshot`) already had the machinery
to catch this — the assurance harness was just routing the wrong shape to the wrong
scenario.

## The fix (Wave 6-AA — assurance-side)

The gap was an assurance-side routing gap, not an engine analysis gap. The engine already
detects lifecycle-script code-execution: `analyzeTarball` reads `package.json` and emits a
`persistence` (INSTALL) finding when `scripts.postinstall` is populated
(`adaptPackageSnapshot`'s `LIFECYCLE_HOOKS` set — `assurance/src/runner/engine-adapter.ts`).

The fix routes the transform's OUTPUT through the correct scenario for its shape:

1. Materialize a real synthetic tarball on disk:
   - `package/package.json` = the transform's JSON output verbatim (contains the
     `scripts.postinstall` payload).
   - `package/index.js` = a stub `module.exports` so the tarball is well-formed.
2. Feed the tarball path through `engine:analyzeTarball`.
3. Assert the AFTER outcome contains a `persistence` finding whose `meta.hook === 'postinstall'`
   and whose `meta.script` starts with `node -e ` — proving the payload rode intact through
   the manifest pipeline.

Both extractCapabilities (BEFORE, on the .js source → `code-execution`) and analyzeTarball
(AFTER, on the tarball → `persistence`) surface the capability. The completeness of the
code-location vector is proven end-to-end without exercising a scanner path that was never
supposed to see JSON.

Uses `makeTgz` from `packages/core/test/tgz-builder.ts` (the engine's own test-helper);
the sibling `never-execute-under-stress.test.ts` already re-uses it, keeping the tarball
construction discipline uniform across assurance suites.

## How the gap was found

Assurance harness Wave 5-U, `test/evasion/evasion-catch-rate.test.ts`. The driver iterates
`allTransforms` from `assurance/src/completeness-vectors/index.ts`; every transform whose
output stays inside the `.js` scanner's remit passed the `oracleFindingSurvives` check.
`intoLifecycleScript` did not — its output is JSON — so it was pinned here as a
GAP-pin-shaped corpus entry until Wave 6-AA landed the routing fix.

Reproduce with:

```ts
import { promises as fs } from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { intoLifecycleScript } from '@vetlock/assurance/completeness-vectors';
import { runBounded } from '@vetlock/assurance/runner';
import { makeTgz } from '../../packages/core/test/tgz-builder';

const source = 'const cp = require("child_process"); cp.exec("echo hi");\n';
const mutated = intoLifecycleScript.transform(source, 42);

// Materialize a synthetic tarball with mutated as package.json.
const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'lifecycle-'));
const tgz = makeTgz([
  { name: 'package/package.json', content: Buffer.from(mutated, 'utf8') },
  { name: 'package/index.js', content: Buffer.from("module.exports = {};\n", 'utf8') },
]);
const tarballPath = path.join(tmpDir, 'fixture.tgz');
await fs.writeFile(tarballPath, tgz);

const outB = await runBounded(
  { kind: 'engine:analyzeTarball', enginePath: '@vetlock/core', tarballPath },
  { wallMs: 10_000, heapMb: 128, seed: 42 },
);

// outB.findings contains a `persistence` finding with meta.hook === 'postinstall'
// and meta.script starting with `node -e ` — the payload survived intact.
```

## Fixtures

- `fixture.input.js` — the pre-transform payload. Committed for offline replay + defang
  scanning. The transform is pure, so the post-transform output is fully determined by
  this input; see the README block above for the exact JSON.

## Regression test

`assurance/test/evasion/evasion-catch-rate.test.ts` — the transform's id is in
`ANALYZE_TARBALL_ROUTED_IDS` (not `KNOWN_GAP_IDS`). The dedicated `it(...)` block
materializes the synthetic tarball and asserts:

- BEFORE (extractCapabilities on the .js source) contains `code-execution`.
- AFTER (analyzeTarball on the tarball) contains `persistence`.
- The persistence finding is anchored on `postinstall` with a `node -e ...` script.

This is a positive-path completeness assertion (not a GAP-pin) — the fix landed with
Wave 6-AA and there is nothing to flip.
