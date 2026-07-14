/**
 * runner-integration — harness self-invariants that don't map to a single named packet test.
 *
 * Companion to the three named files split out of the original harness-invariants.test.ts:
 *   robustness-bounded-time.test.ts  — wallMs bound holds for hangs
 *   robustness-bounded-mem.test.ts   — heap cap holds for allocation blowups
 *   worker-timeout-fires.test.ts     — timer can't be starved
 *
 * This file holds the two remaining harness self-invariants, plus a concurrent-races probe
 * that doesn't have its own packet name but proves the same "harness before engine" claim:
 *
 *   seed-echo-invariant       — bounds.seed round-trips into every RunOutcome kind. Enables
 *                               callers (report, differential ledger) to link a run's seed
 *                               back to its outcome for reproducibility.
 *   single-resolve            — the runner's internal `settled` guard against double-resolve
 *                               holds under concurrent hang scenarios that straddle wallMs.
 *   back-to-back-no-leak      — sequential runs don't accumulate leaked workers. A real leak
 *                               would surface as fd/thread-pool exhaustion inside the vitest
 *                               fork well before 50 sequential invocations complete.
 *
 * Property discipline is the same as the named-invariant files: numRuns small enough that
 * the whole suite runs on every PR without getting muted (packet rule #5).
 */

import { describe, it, expect } from 'vitest';
import * as fc from 'fast-check';
import { runBounded } from '../../src/runner/index.js';
import type { Bounds, RunOutcome } from '../../src/oracles/types.js';

// Generous bounds for "normal scenario should complete" property runs. wallMs is comfortably
// bigger than what a synthetic:normal worker actually needs (~a hundred ms including spawn).
const GENEROUS_BOUNDS: Bounds = { wallMs: 5_000, heapMb: 128, seed: 42 };

// 32-bit-unsigned seed range, matching the shape the report uses.
const SEED_MIN = 0;
const SEED_MAX = 0xffff_ffff;

describe('runBounded — seed-echo-invariant', () => {
  // Every RunOutcome kind carries a `seed` field, and it must be the seed the caller passed.
  // Property-test with random 32-bit unsigned seeds and every outcome kind we can produce
  // synthetically (ok / crash / timeout / fail-safe). OOM is exercised separately in
  // robustness-bounded-mem.test.ts.

  it('property: normal scenarios echo bounds.seed verbatim', async () => {
    await fc.assert(
      fc.asyncProperty(fc.integer({ min: SEED_MIN, max: SEED_MAX }), async (seed) => {
        const bounds: Bounds = { ...GENEROUS_BOUNDS, seed };
        const outcome = await runBounded({ kind: 'synthetic:normal' }, bounds);
        expect(outcome.kind).toBe('ok');
        expect(outcome.seed).toBe(seed);
      }),
      { numRuns: 15 },
    );
  }, 60_000);

  it('property: crash outcomes echo bounds.seed verbatim', async () => {
    await fc.assert(
      fc.asyncProperty(fc.integer({ min: SEED_MIN, max: SEED_MAX }), async (seed) => {
        const bounds: Bounds = { ...GENEROUS_BOUNDS, seed };
        const outcome = await runBounded({ kind: 'synthetic:crash' }, bounds);
        expect(outcome.kind).toBe('crash');
        expect(outcome.seed).toBe(seed);
      }),
      { numRuns: 10 },
    );
  }, 60_000);

  it('property: timeout outcomes echo bounds.seed verbatim', async () => {
    await fc.assert(
      fc.asyncProperty(fc.integer({ min: SEED_MIN, max: SEED_MAX }), async (seed) => {
        const bounds: Bounds = { wallMs: 200, heapMb: 128, seed };
        const outcome = await runBounded(
          { kind: 'synthetic:hang', mode: 'await-forever' },
          bounds,
        );
        expect(outcome.kind).toBe('timeout');
        expect(outcome.seed).toBe(seed);
      }),
      { numRuns: 10 },
    );
  }, 60_000);

  it('property: fail-safe outcomes echo bounds.seed verbatim', async () => {
    await fc.assert(
      fc.asyncProperty(fc.integer({ min: SEED_MIN, max: SEED_MAX }), async (seed) => {
        const bounds: Bounds = { ...GENEROUS_BOUNDS, seed };
        const outcome = await runBounded(
          { kind: 'synthetic:fail-safe', reason: 'analysis-failed' },
          bounds,
        );
        expect(outcome.kind).toBe('fail-safe');
        expect(outcome.seed).toBe(seed);
      }),
      { numRuns: 10 },
    );
  }, 60_000);
});

describe('runBounded — single-resolve (concurrent races)', () => {
  // The runner has a `settled` guard against double-resolve — a worker can post a message a
  // microsecond before the wallMs timer fires, in which case both the 'message' handler AND
  // the setTimeout callback race to call finish(). Direct observation of the "did resolve
  // twice?" question is impossible (a promise can only resolve once by construction), so the
  // best proxy is: run many concurrent scenarios whose completion time straddles wallMs and
  // assert one outcome per invocation.
  it('N concurrent hangs return exactly N outcomes (no double-fires, no swallowed resolves)', async () => {
    const N = 8;
    const bounds: Bounds = { wallMs: 250, heapMb: 128, seed: 99 };
    const runs = Array.from({ length: N }, () =>
      runBounded({ kind: 'synthetic:hang', mode: 'busy-loop' }, bounds),
    );
    const outcomes = await Promise.all(runs);
    expect(outcomes).toHaveLength(N);
    // Each outcome must be a valid RunOutcome; none can be undefined or a leaked object.
    for (const o of outcomes) {
      expect(o.kind).toBe('timeout');
      expect(o.seed).toBe(99);
    }
  }, 30_000);
});

describe('runBounded — back-to-back-no-leak', () => {
  // If the runner leaked a worker per invocation, back-to-back sequential runs would either
  // slow catastrophically (fd exhaustion, thread pool starvation) or throw an EMFILE-like
  // error inside the vitest fork. Running 50 sequential invocations and asserting all succeed
  // is a cheap proxy — a real leak surfaces well before 50 on most CI boxes.
  it('50 sequential normal runs all succeed', async () => {
    const N = 50;
    for (let i = 0; i < N; i++) {
      // Small workMs so the total suite time stays modest (~50 * ~120ms of worker spawn = 6s).
      const outcome = await runBounded(
        { kind: 'synthetic:normal', workMs: 1 },
        GENEROUS_BOUNDS,
      );
      expect(outcome.kind).toBe('ok');
    }
  }, 120_000);

  it('50 sequential mixed-outcome runs all resolve to a valid RunOutcome', async () => {
    // Cycles across the outcome kinds we can produce cheaply — no leak accumulates regardless
    // of the exit path (message, error, or timeout). OOM is excluded (too slow at 50 reps).
    const N = 50;
    const kinds: Array<RunOutcome['kind']> = [];
    for (let i = 0; i < N; i++) {
      const which = i % 4;
      let outcome: RunOutcome;
      if (which === 0) {
        outcome = await runBounded({ kind: 'synthetic:normal', workMs: 1 }, GENEROUS_BOUNDS);
      } else if (which === 1) {
        outcome = await runBounded({ kind: 'synthetic:crash' }, GENEROUS_BOUNDS);
      } else if (which === 2) {
        outcome = await runBounded(
          { kind: 'synthetic:fail-safe', reason: 'analysis-failed' },
          GENEROUS_BOUNDS,
        );
      } else {
        outcome = await runBounded(
          { kind: 'synthetic:hang', mode: 'await-forever' },
          { wallMs: 100, heapMb: 128, seed: 3 },
        );
      }
      kinds.push(outcome.kind);
    }
    // No undefineds, no unrecognized kinds — every invocation produced a valid outcome.
    const valid = new Set(['ok', 'timeout', 'oom', 'crash', 'fail-safe']);
    for (const k of kinds) {
      expect(valid.has(k)).toBe(true);
    }
    // And we saw variety — the mix wasn't silently collapsing to one kind (which would
    // hint that later runs are inheriting broken state from earlier ones).
    const distinctKinds = new Set(kinds);
    expect(distinctKinds.size).toBeGreaterThanOrEqual(3);
  }, 180_000);
});
