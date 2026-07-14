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
 *
 * ROUTING NOTE (Wave 6-AA — into-lifecycle-script fix)
 * ----------------------------------------------------
 * Some transforms produce output that is NOT a .js file body — notably `intoLifecycleScript`
 * emits a `package.json` JSON fragment representing a synthetic package's manifest. Feeding
 * that JSON through `engine:extractCapabilities` (a per-file `.js` AST scanner) is a routing
 * bug: the engine cannot see JSON-embedded code-execution because it isn't parsing JSON.
 * The correct pipeline is `engine:analyzeTarball`, which reads manifest scripts and emits
 * `persistence` findings via `adaptPackageSnapshot`.
 *
 * These transforms are marked in `ANALYZE_TARBALL_ROUTED_IDS` so the standard
 * extractCapabilities loop skips them, and each has a dedicated `it(...)` block below that
 * routes through the correct scenario. This is an ASSURANCE-side fix (the harness was
 * routing wrong); the engine already had the machinery to catch lifecycle-hook persistence
 * capabilities via the manifest pipeline.
 */

import { describe, it, expect } from 'vitest';
import { promises as fs } from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as crypto from 'node:crypto';
import { runBounded } from '../../src/runner/index.js';
import { oracleFindingSurvives } from '../../src/oracles/finding-survives.js';
import { scanForDefangViolations } from '../../src/defang/index.js';
import type { Bounds, RunOutcome } from '../../src/oracles/types.js';
import {
  allTransforms,
  type CompletenessTransform,
} from '../../src/completeness-vectors/index.js';
import { makeTgz } from '../../../packages/core/test/tgz-builder.js';

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
 * Transform ids whose output is NOT a .js file body and therefore doesn't belong in the
 * `engine:extractCapabilities` (per-file `.js` AST scanner) loop below. These transforms
 * are routed to `engine:analyzeTarball` via dedicated `it(...)` blocks at the end of this
 * file — the transform's output becomes the `package.json` inside a synthetic tarball, and
 * the oracle checks that the resulting manifest-pipeline findings preserve the payload's
 * capability (typically translated to `persistence` for lifecycle-hook payloads).
 *
 * This is a routing map, not a gap list. When a new transform emits non-.js output, add
 * its id here AND wire a dedicated `it(...)` block that feeds the correct scenario.
 */
const ANALYZE_TARBALL_ROUTED_IDS: ReadonlySet<string> = new Set<string>([
  // into-lifecycle-script — the transform emits a package.json JSON fragment with a
  // populated `scripts.postinstall`. The engine's per-file .js AST scanner (which this
  // file's default loop uses) cannot see JSON semantics. The correct pipeline is
  // engine:analyzeTarball, which reads manifest.scripts and emits `persistence` findings
  // via adaptPackageSnapshot (LIFECYCLE_HOOKS set includes postinstall).
  // Corpus: assurance/corpus/evasion/into-lifecycle-script/README.md.
  'into-lifecycle-script',
]);

/**
 * Known GAPS — transforms that DO produce .js output but genuinely evade the current
 * engine on the extractCapabilities pipeline. Empty as of Wave 6-AA; kept as an extension
 * point mirroring metamorphic-invariance's KNOWN_GAP_IDS. When populated, each gap has a
 * dedicated GAP-pinning `it(...)` block below (see the metamorphic-invariance file for the
 * canonical shape).
 */
const KNOWN_GAP_IDS: ReadonlySet<string> = new Set<string>();

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
    // Skip transforms whose output is routed through a different scenario (analyze-tarball
    // for JSON-shaped output) — those have dedicated it() blocks below. Also skip transforms
    // in KNOWN_GAP_IDS (extractCapabilities-shape gaps whose GAP-pinning assertion lives in
    // its own it() block below).
    if (ANALYZE_TARBALL_ROUTED_IDS.has(transform.id)) continue;
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
  // ANALYZE-TARBALL-ROUTED transforms — the transform's output is a package.json JSON
  // fragment (not a .js body), so extractCapabilities cannot see it. Route the output
  // through engine:analyzeTarball where adaptPackageSnapshot emits `persistence` findings
  // on manifest lifecycle hooks. This is the assurance-side fix landed in Wave 6-AA.
  // ------------------------------------------------------------------------------------------

  it(
    'code-location/into-lifecycle-script: finding survives via engine:analyzeTarball (payload lands in package.json.scripts.postinstall → persistence)',
    async () => {
      // Locate the transform via the same barrel enumeration the standard loop uses. If
      // the transform is ever unregistered / renamed, this fails loudly rather than
      // silently skipping — matches the guard in the sibling metamorphic-invariance file.
      const transform: CompletenessTransform | undefined =
        allTransforms.find((t) => t.id === 'into-lifecycle-script');
      expect(transform, 'expected transform into-lifecycle-script to be registered').toBeDefined();
      if (!transform) return;

      // BEFORE: the raw .js payload. Fed through extractCapabilities to prove the baseline
      // contains the code-execution capability (the class the transform claims to
      // preserve). Uses the standard defanged fixture; scanForDefangViolations must pass.
      const source = CAUGHT_SOURCES['code-execution']!;
      expect(scanForDefangViolations(source).clean).toBe(true);

      // AFTER: the transform emits a package.json JSON fragment whose `scripts.postinstall`
      // wraps the payload in `node -e "<payload>"`. That output belongs in the manifest
      // pipeline, not the per-file .js AST scanner. Path 1 (packet §5 P3 recommended):
      // materialize a real synthetic tarball on disk and hand it to engine:analyzeTarball.
      //
      // NOTE: the raw transform output triggers the defang guard's `node -e` pattern by
      // design — that's precisely the exec vector the fixture demonstrates. The tarball
      // is written to a per-test tmp dir (never committed), so packet rule #2 (defang
      // corpus scan) does not apply here. See the corpus README for the same discussion.
      const mutated = transform.transform(source, /*seed*/ 42);
      expect(mutated, 'transform must be non-trivial for the code-execution fixture').not.toBe(source);

      // Build the synthetic package tarball. npm-style layout: single root `package/`
      // directory, `package.json` = the transform's output, plus a stub `index.js` so the
      // tarball looks like a well-formed package. Both use `makeTgz` from the engine's
      // own test-helper (assurance already re-uses it in never-execute-under-stress).
      const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'wave6-aa-lifecycle-'));
      try {
        const tgz = makeTgz([
          { name: 'package/package.json', content: Buffer.from(mutated, 'utf8') },
          {
            name: 'package/index.js',
            content: Buffer.from("module.exports = { hello: 'defanged' };\n", 'utf8'),
          },
        ]);
        const tarballPath = path.join(tmpDir, `into-lifecycle-${crypto.randomBytes(4).toString('hex')}.tgz`);
        await fs.writeFile(tarballPath, tgz);

        // BEFORE outcome: extractCapabilities on the raw .js source produces the baseline
        // code-execution finding (via execModules: ['child_process'] + the cp.exec call
        // site). This proves the fixture is well-formed under the class the transform
        // claims to preserve.
        const outA = await analyzeSource(source, 'a.js');
        // AFTER outcome: analyzeTarball on the synthetic tarball. adaptPackageSnapshot's
        // LIFECYCLE_HOOKS set catches `postinstall` and emits a `persistence` finding.
        // A capability-preserving completeness check on the code-location vector must
        // treat that as the class the fixture landed in — the payload didn't disappear;
        // it moved to a location whose class is `persistence` (install-time execution).
        const outB = await runBounded(
          {
            kind: 'engine:analyzeTarball',
            enginePath: '@vetlock/core',
            tarballPath,
          },
          BOUNDS,
        );

        // Both outcomes must be verdict-bearing. Crash/timeout/oom on either side means
        // the analysis itself broke on the input — a robustness bug for a different suite.
        expect(['ok', 'fail-safe']).toContain(outA.kind);
        expect(['ok', 'fail-safe']).toContain(outB.kind);

        // Oracle: the payload's capability survives the code-location transform. In the
        // BEFORE run it surfaces as `code-execution`; in the AFTER run it surfaces as
        // `persistence` (the manifest pipeline's class for lifecycle-hook payloads).
        // Both are correct spellings of "this package runs code at install time"; the
        // scanner's coverage of the code-location family is complete iff at least one
        // shows up on each side.
        //
        // We assert directly on the class set of AFTER (rather than calling
        // oracleFindingSurvives) because oracleFindingSurvives takes a single class
        // argument and this transform legitimately maps the class family across the
        // extract/analyze boundary. The oracle's own invariants (BEFORE has the class,
        // AFTER is verdict-bearing, AFTER contains the class) are re-checked inline.
        const beforeClasses =
          outA.kind === 'ok' || outA.kind === 'fail-safe'
            ? new Set(outA.findings.map((f) => f.capabilityClass))
            : new Set<string>();
        const afterClasses =
          outB.kind === 'ok' || outB.kind === 'fail-safe'
            ? new Set(outB.findings.map((f) => f.capabilityClass))
            : new Set<string>();

        expect(beforeClasses.has('code-execution')).toBe(true);
        expect(afterClasses.has('persistence')).toBe(true);

        // Bonus proof: the persistence finding is specifically anchored on `postinstall`
        // (not merely any lifecycle hook), and the recorded script begins with `node -e`
        // — evidence that the transform's payload really did survive intact through the
        // manifest pipeline.
        if (outB.kind === 'ok' || outB.kind === 'fail-safe') {
          const persistenceHits = outB.findings.filter(
            (f) => f.capabilityClass === 'persistence',
          );
          const hooks = new Set(
            persistenceHits
              .map((f) => f.meta?.['hook'])
              .filter((h): h is string => typeof h === 'string'),
          );
          expect(hooks.has('postinstall')).toBe(true);
          const postinstallFinding = persistenceHits.find(
            (f) => f.meta?.['hook'] === 'postinstall',
          );
          expect(typeof postinstallFinding?.meta?.['script']).toBe('string');
          expect((postinstallFinding!.meta!['script'] as string).startsWith('node -e ')).toBe(true);
        }
      } finally {
        await fs.rm(tmpDir, { recursive: true, force: true }).catch(() => {});
      }
    },
    30_000,
  );
});
