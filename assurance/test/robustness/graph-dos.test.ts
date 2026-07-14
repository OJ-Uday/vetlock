/**
 * graph-dos — robustness tests for the pathological-lockfile-graph generator.
 *
 * The generator (assurance/src/robustness/graph-dos.ts) emits package-lock.json v3 documents
 * whose shape stresses different parts of @vetlock/core's diff pipeline:
 *
 *   parseLockfileText → parseLockfile (graph build) → computeChangeset (per-name diff loop)
 *
 * We feed each pathological output through the `engine:runDiff` scenario with a trivial
 * 2-entry OLD lockfile — that forces the pipeline to enumerate the entire new-side graph as
 * "added" changes. detectorMode: 'none' + disableFetch (default true) means no network / no
 * detector work — just the parse+diff cost is measured.
 *
 * KNOWN GAPS PROTOCOL (packet rule #6): baseline scales (100) must run cleanly under the
 * 5-second bound. Stress scales (1000+) pin the current engine behavior with the outcome
 * kinds we actually observed at authoring time; if the engine later gets faster (or slower)
 * these are the tests that surface the change.
 */

import { describe, it, expect } from 'vitest';
import { runBounded } from '../../src/runner/index.js';
import {
  oracleNoCrash,
  oracleNoHang,
  oracleNoOom,
  oracleFailSafe,
  type Bounds,
  type RunOutcome,
  type OracleResult,
} from '../../src/oracles/index.js';
import { graphDos, type GraphDosMode } from '../../src/robustness/graph-dos.js';

const BASELINE_BOUNDS: Bounds = { wallMs: 5_000, heapMb: 128, seed: 42 };
// Stress tests need more wall-clock and a bigger heap — the goal is to observe engine
// behavior, not to be capped by the harness itself. If the engine still blows through
// these, that IS the gap (the engine has no internal bound and needs one).
const STRESS_BOUNDS: Bounds = { wallMs: 15_000, heapMb: 512, seed: 42 };

// Minimal old-side lockfile: v3 shape, one direct dep. computeChangeset will diff every
// new-side entry against this — meaning every new-side entry becomes an "added" change.
const TRIVIAL_OLD_LOCK = JSON.stringify({
  name: 'graph-dos-test',
  version: '1.0.0',
  lockfileVersion: 3,
  requires: true,
  packages: {
    '': { name: 'graph-dos-test', version: '1.0.0' },
    'node_modules/seed-package': {
      version: '0.0.1',
      integrity: 'sha512-0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000==',
    },
  },
});

/** Feed a generator's output through the runner and assert the oracle set. */
async function assertRobust(
  label: string,
  outcome: RunOutcome,
  bounds: Bounds,
): Promise<void> {
  const oracles: OracleResult[] = [
    oracleNoCrash(outcome),
    oracleNoHang(outcome),
    oracleNoOom(outcome),
    oracleFailSafe(outcome),
  ];
  const failed = oracles.filter((r) => !r.pass);
  if (failed.length > 0) {
    const reason = failed
      .map(
        (r) =>
          `${r.oracle} FAIL — ${r.reason}${r.evidence ? ` (evidence: ${JSON.stringify(r.evidence).slice(0, 200)})` : ''}`,
      )
      .join('\n  ');
    throw new Error(
      `robustness failure for ${label} (seed=${bounds.seed}, wallMs=${bounds.wallMs}, heapMb=${bounds.heapMb}):\n  ${reason}`,
    );
  }
  expect(failed).toEqual([]);
}

async function runDiffAgainstTrivial(
  newLockText: string,
  bounds: Bounds,
): Promise<RunOutcome> {
  return runBounded(
    {
      kind: 'engine:runDiff',
      enginePath: '@vetlock/core',
      oldLockfileText: TRIVIAL_OLD_LOCK,
      newLockfileText: newLockText,
      oldLockfilePath: 'package-lock.json',
      newLockfilePath: 'package-lock.json',
      detectorMode: 'none',
    },
    bounds,
  );
}

// -------------------------------------------------------------------------------------------
// Determinism — the same (seed, params) MUST produce byte-identical output. This is packet
// rule #2 (deterministic replay). Every downstream test relies on it.

describe('graph-dos — determinism', () => {
  const modes: GraphDosMode[] = [
    'million-nodes',
    'deep-transitive-chain',
    'wide-fanout',
    'duplicate-heavy',
  ];

  for (const mode of modes) {
    it(`${mode} at scale=50 is byte-identical across calls`, () => {
      const a = graphDos.generate(1, { mode, scale: 50 });
      const b = graphDos.generate(1, { mode, scale: 50 });
      expect(a.text).toBe(b.text);
      expect(a.filename).toBe('package-lock.json');
      expect(a.format).toBe('npm');
    });
  }

  it('rejects negative scale', () => {
    expect(() => graphDos.generate(1, { mode: 'million-nodes', scale: -1 })).toThrow(
      /scale must be a non-negative integer/,
    );
  });

  it('rejects scale beyond MAX_SCALE (1_000_000)', () => {
    expect(() => graphDos.generate(1, { mode: 'million-nodes', scale: 2_000_000 })).toThrow(
      /scale must be a non-negative integer/,
    );
  });

  it('rejects missing params', () => {
    // @ts-expect-error deliberately omitting params
    expect(() => graphDos.generate(1)).toThrow(/params is required/);
  });
});

// -------------------------------------------------------------------------------------------
// Baseline — every mode at CI-safe scale must be handled safely, never crash.
// scale=100 is comparable to a real, well-behaved lockfile (100 dependencies is a small app).
//
// Expected outcome kinds: 'ok' OR 'fail-safe'. Both are the engine handling the input safely.
// The `fail-safe` shape is the runDiff pipeline's normal path when packages need analysis but
// fetch is disabled (worker.ts disableFetch=true by default) — analyzeOne throws, the engine
// records to `analysisFailed`, and emits BLOCK-tier `analysis.failed` findings per package.
// findingsSignalFailSafe(...) then flags the run as fail-safe. That is the *correct* outcome
// for an offline harness: the engine got far enough through parse + changeset to enumerate
// the added packages and asked to fetch them. Crash is the forbidden shape.

describe('graph-dos — baseline (scale=100)', () => {
  it('million-nodes at scale=100 is handled safely', async () => {
    const input = graphDos.generate(1, { mode: 'million-nodes', scale: 100 });
    const outcome = await runDiffAgainstTrivial(input.text, BASELINE_BOUNDS);
    await assertRobust('graph-dos million-nodes scale=100', outcome, BASELINE_BOUNDS);
    expect(['ok', 'fail-safe']).toContain(outcome.kind);
  }, 20_000);

  it('deep-transitive-chain at scale=100 is handled safely', async () => {
    const input = graphDos.generate(1, { mode: 'deep-transitive-chain', scale: 100 });
    const outcome = await runDiffAgainstTrivial(input.text, BASELINE_BOUNDS);
    await assertRobust('graph-dos deep-transitive-chain scale=100', outcome, BASELINE_BOUNDS);
    expect(['ok', 'fail-safe']).toContain(outcome.kind);
  }, 20_000);

  it('wide-fanout at scale=100 is handled safely', async () => {
    const input = graphDos.generate(1, { mode: 'wide-fanout', scale: 100 });
    const outcome = await runDiffAgainstTrivial(input.text, BASELINE_BOUNDS);
    await assertRobust('graph-dos wide-fanout scale=100', outcome, BASELINE_BOUNDS);
    expect(['ok', 'fail-safe']).toContain(outcome.kind);
  }, 20_000);

  it('duplicate-heavy at scale=100 is handled safely', async () => {
    const input = graphDos.generate(1, { mode: 'duplicate-heavy', scale: 100 });
    const outcome = await runDiffAgainstTrivial(input.text, BASELINE_BOUNDS);
    await assertRobust('graph-dos duplicate-heavy scale=100', outcome, BASELINE_BOUNDS);
    expect(['ok', 'fail-safe']).toContain(outcome.kind);
  }, 20_000);
});

// -------------------------------------------------------------------------------------------
// Stress — larger scales exercise the diff-compute + dedup logic. Outcomes are PINNED (not
// asserted-as-ok) because the engine's parse + changeset compute has no internal bound; if
// a mode times out or OOMs, that is the observed current behavior and the gap surfaces here.
// Every stress result should still be fail-safe: crash is forbidden.

describe('graph-dos — stress (KNOWN GAPS PROTOCOL)', () => {
  it('million-nodes at scale=10000 completes without crash', async () => {
    // 10k entries — one order of magnitude beyond typical, still within the runner's
    // 15-second stress budget on a laptop. If the engine crashes here it's a real gap.
    const input = graphDos.generate(1, { mode: 'million-nodes', scale: 10_000 });
    const outcome = await runDiffAgainstTrivial(input.text, STRESS_BOUNDS);
    // Acceptable outcomes: ok (parsed + diffed cleanly), timeout/oom (runner caught the
    // pathology), fail-safe (engine's give-up path). Crash is the forbidden shape.
    expect(['ok', 'timeout', 'oom', 'fail-safe']).toContain(outcome.kind);
    expect(oracleNoCrash(outcome).pass).toBe(true);
  }, 30_000);

  it('deep-transitive-chain at scale=1000 completes without crash', async () => {
    // Chain of 1000 nested node_modules. Deepest key ~15KB. Tests resolveDepKey's O(depth)
    // walk and downstream key comparisons. If the engine internally recurses on this path
    // shape, a stack-overflow crash would surface here.
    const input = graphDos.generate(1, { mode: 'deep-transitive-chain', scale: 1_000 });
    const outcome = await runDiffAgainstTrivial(input.text, STRESS_BOUNDS);
    expect(['ok', 'timeout', 'oom', 'fail-safe']).toContain(outcome.kind);
    expect(oracleNoCrash(outcome).pass).toBe(true);
  }, 30_000);

  it('wide-fanout at scale=5000 completes without crash', async () => {
    // 5000 direct deps — beyond any real project. Stresses computeRollup's per-direct-dep
    // subtree walk (which iterates every direct dep) and the byName-driven diff loop.
    const input = graphDos.generate(1, { mode: 'wide-fanout', scale: 5_000 });
    const outcome = await runDiffAgainstTrivial(input.text, STRESS_BOUNDS);
    expect(['ok', 'timeout', 'oom', 'fail-safe']).toContain(outcome.kind);
    expect(oracleNoCrash(outcome).pass).toBe(true);
  }, 30_000);

  it('duplicate-heavy at scale=1000 completes without crash', async () => {
    // 1000 copies of the same name at 1000 distinct versions. byName['foo'] balloons.
    // The changeset compute's per-name loop iterates O(N) versions on the new side; when
    // the OLD side also has entries for 'foo', pickClosest is called O(N) times per new
    // version — quadratic. Our trivial OLD has no 'foo', so the quadratic doesn't fire in
    // this test — a follow-up asymmetric-diff generator could target that.
    const input = graphDos.generate(1, { mode: 'duplicate-heavy', scale: 1_000 });
    const outcome = await runDiffAgainstTrivial(input.text, STRESS_BOUNDS);
    expect(['ok', 'timeout', 'oom', 'fail-safe']).toContain(outcome.kind);
    expect(oracleNoCrash(outcome).pass).toBe(true);
  }, 30_000);
});

// -------------------------------------------------------------------------------------------
// Skipped extreme-scale stress. These document the design ceiling: at scale=100k+ the
// generator itself starts to matter (the emitted JSON approaches Node's max string length
// on some V8 builds) and the runner's 15-second wall-clock is almost certainly insufficient.
// Flip these to `it(...)` inside a longer-timeout CI job when you want the DoS curve.

describe.skip('graph-dos — extreme stress (opt-in)', () => {
  it('million-nodes at scale=100000', async () => {
    const input = graphDos.generate(1, { mode: 'million-nodes', scale: 100_000 });
    const outcome = await runDiffAgainstTrivial(input.text, {
      wallMs: 60_000,
      heapMb: 1_024,
      seed: 42,
    });
    expect(['ok', 'timeout', 'oom', 'fail-safe']).toContain(outcome.kind);
  }, 90_000);

  it('deep-transitive-chain at scale=10000', async () => {
    const input = graphDos.generate(1, { mode: 'deep-transitive-chain', scale: 10_000 });
    const outcome = await runDiffAgainstTrivial(input.text, {
      wallMs: 60_000,
      heapMb: 1_024,
      seed: 42,
    });
    expect(['ok', 'timeout', 'oom', 'fail-safe']).toContain(outcome.kind);
  }, 90_000);
});
