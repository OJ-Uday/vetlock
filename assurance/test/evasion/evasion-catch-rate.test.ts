/**
 * evasion-catch-rate — the completeness driver's end-to-end assertion (packet §5 P3 tail).
 *
 * WHAT this file measures
 * -----------------------
 * The metrics collector (assurance/src/metrics/collector.ts) buckets tests by their
 * `test/<dir>/` prefix. Tests placed under `test/evasion/` are counted toward the
 * `evasionCatchRate = passed / (passed + failed)` metric that surfaces in ASSURANCE.md.
 *
 * Before this file existed, no tests lived under `test/evasion/` and the metric rendered
 * `null → "no data (tier not yet active)"`. This file populates the bucket by running
 * every completeness-vector transform (Wave 1B-G, `assurance/src/completeness-vectors/`)
 * against a defanged fixture that reliably triggers a known capability class, then asking
 * `oracleFindingSurvives` whether the finding of that class SURVIVED the transform.
 *
 * WHY "survives" is the right question
 * ------------------------------------
 * A completeness vector is a semantics-preserving transform. If the engine's detectors
 * catch the ORIGINAL and MISS the transformed variant, that's a completeness gap — a real
 * spelling of the same capability class the scanner claims to cover. The oracle names
 * this precisely: `beforeOutcome` must contain the class; `afterOutcome` (the transformed
 * variant) must ALSO contain the class. A missing after-hit is an evasion.
 *
 * KNOWN GAPS PROTOCOL (packet rule #6, mirrors metamorphic-invariance)
 * -------------------------------------------------------------------
 * When a transform genuinely evades the detector, the failing pair is pinned as a corpus
 * entry under `assurance/corpus/evasion/<transform-id>/` (README + fixture + assertion-flip
 * instructions) and the test PINS the current failing behavior (`expect(verdict.pass)
 * .toBe(false)`) so:
 *   • the metric reflects the truth (`passed/(passed+failed)` is honest),
 *   • the harness stays green (no red CI on known-and-triaged gaps),
 *   • the assertion flips to `.toBe(true)` when STARTUP closes the gap in the engine.
 *
 * The routing between "GAP-pinning" and "positive survives" assertions happens through
 * the `KNOWN_GAP_IDS` set below — same shape as the metamorphic-invariance test.
 */

import { describe, it, expect } from 'vitest';
import { runBounded } from '../../src/runner/index.js';
import { oracleFindingSurvives } from '../../src/oracles/finding-survives.js';
import { scanForDefangViolations } from '../../src/defang/index.js';
import type { Bounds, RunOutcome } from '../../src/oracles/types.js';
import {
  allTransforms,
  type CompletenessTransform,
} from '../../src/completeness-vectors/index.js';

/**
 * extractCapabilities is a pure per-file AST scan — the same bounds the metamorphic-e2e
 * uses are more than enough. Seed is the packet's standard 42.
 */
const BOUNDS: Bounds = { wallMs: 10_000, heapMb: 128, seed: 42 };

/**
 * Defanged sources that reliably trigger the target capability class on the current
 * engine. Both bodies:
 *   • require() a module that lands in the engine's NETWORK_MODULES / EXEC_MODULES set,
 *   • use `echo` (defang-allowlisted) so the fixture is functional-looking without being
 *     runnable malware,
 *   • target *.invalid / example.com hosts so `scanForDefangViolations` clears them.
 */
const CAUGHT_SOURCES: Readonly<Record<string, string>> = {
  // `require("child_process")` → engine emits code-execution class via execModules,
  // AND `cp.exec("echo hi")` → engine emits code-execution via the call itself. Two
  // findings of the same class, so a widening transform that touches ONLY the call
  // still leaves the module-import finding intact.
  'code-execution': 'const cp = require("child_process"); cp.exec("echo hi");\n',
  // `require("http")` lands in NETWORK_MODULES; the URL literal lands in urlLiterals;
  // both surface as net-egress. Defanged via RFC 2606 example.com.
  'net-egress': 'const http = require("http"); http.request("http://example.com/p");\n',
};

/**
 * Transform ids known to evade the engine's detectors on the current build. Each id
 * has a corpus entry under `assurance/corpus/evasion/<id>/README.md` with the full
 * write-up (what evaded, why it matters, the fixture, and the exact assertion-flip
 * a fix should produce). These transforms are routed to the GAP-pinning assertion
 * below (`expect(verdict.pass).toBe(false)`); every OTHER transform runs the positive
 * "finding survived" assertion.
 *
 * When STARTUP fixes a gap, remove the id from this set and let the standard-path
 * assertion take over.
 */
const KNOWN_GAP_IDS: ReadonlySet<string> = new Set<string>([
  // into-lifecycle-script — the transform emits a package.json JSON fragment, not JS.
  // The engine's per-file `.js` AST scanner cannot see JSON semantics (no require, no
  // MemberExpression). The full pipeline (engine:analyzeTarball) IS location-aware —
  // it reads package.json manifests and emits persistence findings on lifecycle hooks
  // — but the per-file .js scanner in isolation is location-incomplete by design.
  // Corpus: assurance/corpus/evasion/into-lifecycle-script/README.md.
  'into-lifecycle-script',
]);

/**
 * Feed one source string through the bounded runner's engine:extractCapabilities
 * scenario. Mirrors `analyzeSource` in `test/metamorphic/invariance-e2e.test.ts` — same
 * synthetic path for BEFORE and AFTER so `location.file` normalization is a wash and the
 * oracle's decision reflects the capability set the scanner extracted.
 */
async function analyzeSource(text: string, relPath: string): Promise<RunOutcome> {
  return runBounded(
    {
      kind: 'engine:extractCapabilities',
      enginePath: '@vetlock/core',
      relPath,
      text,
    },
    BOUNDS,
  );
}

describe('evasion catch-rate — completeness-vector transforms preserve capability findings', () => {
  // Meta-assertion: the driver is enumerating the same transforms the barrel exports.
  // If a transform is added to `allTransforms` but forgotten here (or a source class is
  // missing from CAUGHT_SOURCES), the driver would silently skip it and the metric would
  // silently under-report. This one-liner keeps the surface honest.
  it('battery covers every registered transform and has a caught source for its class', () => {
    expect(allTransforms.length).toBeGreaterThan(0);
    for (const t of allTransforms) {
      expect(
        CAUGHT_SOURCES[t.targetClass],
        `no CAUGHT_SOURCES entry for transform ${t.id}'s targetClass=${t.targetClass}`,
      ).toBeDefined();
    }
  });

  for (const transform of allTransforms) {
    // Positive "survives" assertions for transforms not in KNOWN_GAP_IDS. The GAP-pinning
    // assertion for each known gap lives in its own `it(...)` block below (mirrors the
    // metamorphic-invariance file's structure so a gap's PIN and its REGRESSION-GUARD
    // are visible side-by-side in the file).
    if (KNOWN_GAP_IDS.has(transform.id)) continue;

    it(
      `${transform.family}/${transform.id}: finding survives transform (class=${transform.targetClass})`,
      async () => {
        const source = CAUGHT_SOURCES[transform.targetClass];
        // Belt + braces: the fixture must be defang-clean before we hand it to the runner.
        // A dirty fixture would violate packet rule #2 regardless of whether it "works" as
        // a test. The scan is cheap; a false positive here surfaces the problem loudly.
        expect(scanForDefangViolations(source).clean).toBe(true);

        const mutated = transform.transform(source, /*seed*/ 42);
        // Non-triviality: a transform whose target pattern isn't present should be a no-op
        // and skip this test. If the source doesn't exercise the transform, the assertion
        // is meaningless (before === after → trivially "survives" but nothing is proven).
        // Every transform-source pair in CAUGHT_SOURCES is hand-chosen to exercise the
        // transform, so a no-op here is a broken pairing worth flagging.
        expect(
          mutated,
          `transform ${transform.id} was a no-op on source for class ${transform.targetClass} — pair the transform with a source it actually mutates`,
        ).not.toBe(source);
        expect(scanForDefangViolations(mutated).clean).toBe(true);

        const [outA, outB] = await Promise.all([
          analyzeSource(source, 'a.js'),
          analyzeSource(mutated, 'a.js'),
        ]);

        const verdict = oracleFindingSurvives(outA, outB, transform.targetClass);
        if (!verdict.pass) {
          // Loud, structured failure. If this fires in CI, the transform is a REAL
          // completeness gap that hasn't been triaged yet — the operator should pin it
          // as a corpus entry (add `assurance/corpus/evasion/<id>/README.md` + fixture,
          // add the id to KNOWN_GAP_IDS, add a GAP-pinning `it(...)` block below), or
          // land the engine fix that closes it.
          throw new Error(
            `EVASION: transform ${transform.id} evaded ${transform.targetClass} detector.\n` +
              `  reason: ${verdict.reason}\n` +
              `  evidence: ${JSON.stringify(verdict.evidence)}\n` +
              `  before source:\n${source}\n` +
              `  after source:\n${mutated}`,
          );
        }
        expect(verdict.pass).toBe(true);
      },
      // extract is milliseconds in practice; give the runner headroom for a cold worker
      // spawn plus vitest fork overhead.
      30_000,
    );
  }

  // ------------------------------------------------------------------------------------------
  // KNOWN GAPS — pin the current failing behavior; each assertion flips green when STARTUP
  // closes the underlying engine gap. Each gap has a corpus entry with README + fixture at
  // `assurance/corpus/evasion/<id>/`.
  // ------------------------------------------------------------------------------------------

  it(
    'GAP: into-lifecycle-script — engine:extractCapabilities on a .js relpath cannot see JSON-embedded code-execution',
    async () => {
      const source = CAUGHT_SOURCES['code-execution']!;
      const transform = allTransforms.find((t) => t.id === 'into-lifecycle-script');
      // Guard: if the transform is ever unregistered / renamed, we want the gap-pin to
      // FAIL LOUDLY rather than silently skip.
      expect(transform, 'expected transform into-lifecycle-script to be registered').toBeDefined();
      if (!transform) return;

      const mutated = transform.transform(source, /*seed*/ 42);
      expect(scanForDefangViolations(source).clean).toBe(true);
      // NOTE: mutated output is NOT defang-checked here. `intoLifecycleScript` wraps
      // any meaningful code-execution payload in `node -e "<payload>"`, which the defang
      // guard's `node -e` pattern (correctly) flags as a runnable exec invocation. That
      // "violation" is precisely what the transform is designed to produce — the whole
      // point of the code-location vector is to demonstrate that a package can hide
      // code-execution inside package.json where the .js scanner never looks. Rule #2
      // applies to fixtures COMMITTED to the corpus (see test/defang/corpus-scan.test.ts);
      // the transform's per-test runtime output is not committed and is handed to the
      // engine's AST scanner, which reads it but never executes it.

      // Feed the transformed payload to the per-file .js extractor. The transform
      // produced a package.json JSON fragment ({"name":..., "scripts":{"postinstall":
      // "node -e ..."}}). At the top level, `{ ... }` parses as a JS BLOCK statement
      // with labeled statements; the JS AST scanner sees no `require`, no `.exec`,
      // no MemberExpression it recognises — so no code-execution finding surfaces.
      const [outA, outB] = await Promise.all([
        analyzeSource(source, 'a.js'),
        analyzeSource(mutated, 'a.js'),
      ]);

      const verdict = oracleFindingSurvives(outA, outB, 'code-execution');

      // What the engine currently does: no code-execution finding on the JSON body →
      // the oracle reports "evasion: mutated variant is missing any finding of class
      // code-execution". The harness caught the gap.
      expect(verdict.pass).toBe(false);
      expect(verdict.reason).toMatch(/evasion|missing any finding/);

      // Both A and B produced a runner-verdict-bearing outcome (ok OR fail-safe). Crash /
      // timeout / oom would be a robustness problem for a different test bucket. The
      // gap is on the analysis surface, not on the runner's own axes.
      expect(['ok', 'fail-safe']).toContain(outA.kind);
      expect(['ok', 'fail-safe']).toContain(outB.kind);

      // WHEN THE FIX LANDS: the correct fix is location-aware routing — the assurance
      // harness (or the engine's own analyzeTarball path) recognises the transform's
      // JSON shape and feeds it to the manifest/lifecycle scanner instead of the .js
      // scanner. When that lands, replace the `expect(verdict.pass).toBe(false)` above
      // with `expect(verdict.pass).toBe(true)` and remove `'into-lifecycle-script'`
      // from KNOWN_GAP_IDS.
    },
    30_000,
  );
});
