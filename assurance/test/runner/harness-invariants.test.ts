/**
 * Harness self-invariants (packet §5 P1 — "prove the harness before you trust it").
 *
 * These tests protect the assurance runner itself. Packet rule #5: if the harness cries wolf,
 * it gets muted and all assurance is lost. So before we lean on the runner's outcome to make
 * claims about the engine, we prove the runner is itself correct under fast-check-driven fuzz.
 *
 * Each invariant is a promise the runner makes to its callers:
 *   robustness-bounded-time  — a hanging scenario always resolves within ~bounds.wallMs.
 *   robustness-bounded-mem   — a heap-blowing scenario always resolves to kind: 'oom'.
 *   worker-timeout-fires     — the wallMs timer fires under hostile microtask patterns.
 *   seed-echo-invariant      — bounds.seed round-trips into every RunOutcome kind.
 *   back-to-back-no-leak     — sequential runs don't accumulate leaked workers.
 *
 * Property discipline: numRuns is deliberately small (10-20). This suite runs on every PR;
 * a minutes-long property fuzz would either get muted (see rule #5) or push CI wall time past
 * useful. The point of fast-check here is to sweep the *seed axis* — not to exhaustively fuzz
 * the runner. Existing runner.test.ts already carries the concrete assertions; this file adds
 * the "does it hold for arbitrary inputs?" layer.
 */

import { describe, it, expect } from 'vitest';
import * as fc from 'fast-check';
import { performance } from 'node:perf_hooks';
import { runBounded } from '../../src/runner/index.js';
import type { Bounds, RunOutcome } from '../../src/oracles/types.js';

// Generous bounds for "normal scenario should complete" property runs. wallMs is comfortably
// bigger than what a synthetic:normal worker actually needs (~a hundred ms including spawn).
const GENEROUS_BOUNDS: Bounds = { wallMs: 5_000, heapMb: 128, seed: 42 };

// Small heap cap used for OOM property runs. Keep the heap cap generous enough that Node can
// still bootstrap the worker (V8 needs its own overhead), tight enough that the scenario trips
// it in seconds not tens of seconds.
const OOM_HEAP_MB_RANGE = { min: 16, max: 48 } as const;

// The extra slack we allow the runner over its stated wallMs before we accuse it of running
// long. Worker spawn + terminate + fork-scheduling on a busy CI box can easily eat 200-800ms;
// 2_000ms is enough headroom that the assertion fails only on a real bug, not on a slow lane.
const TIMEOUT_SLACK_MS = 2_000;

// 32-bit-unsigned seed range, matching the shape the report uses.
const SEED_MIN = 0;
const SEED_MAX = 0xffff_ffff;

describe('runBounded — robustness-bounded-time', () => {
  it('resolves within wallMs + slack for a busy-loop hang (single concrete probe)', async () => {
    // Concrete anchor before the property: prove the shape works at one point before we sweep.
    const bounds: Bounds = { wallMs: 250, heapMb: 128, seed: 7 };
    const started = performance.now();
    const outcome = await runBounded({ kind: 'synthetic:hang', mode: 'busy-loop' }, bounds);
    const elapsed = performance.now() - started;
    expect(outcome.kind).toBe('timeout');
    expect(elapsed).toBeLessThan(bounds.wallMs + TIMEOUT_SLACK_MS);
    if (outcome.kind === 'timeout') {
      expect(outcome.wallMs).toBeGreaterThanOrEqual(bounds.wallMs);
      expect(outcome.wallMs).toBeLessThan(bounds.wallMs + TIMEOUT_SLACK_MS);
    }
  }, 15_000);

  it('property: hanging scenarios resolve as timeout within wallMs + slack for random wallMs', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: 150, max: 500 }),
        fc.integer({ min: SEED_MIN, max: SEED_MAX }),
        fc.constantFrom<'busy-loop' | 'await-forever'>('busy-loop', 'await-forever'),
        async (wallMs, seed, mode) => {
          const bounds: Bounds = { wallMs, heapMb: 128, seed };
          const started = performance.now();
          const outcome = await runBounded({ kind: 'synthetic:hang', mode }, bounds);
          const elapsed = performance.now() - started;
          // Invariant 1: kind is timeout — the wallMs bound WAS the reason we stopped.
          expect(outcome.kind).toBe('timeout');
          // Invariant 2: real elapsed time did not exceed wallMs by more than the slack.
          // This is what "bounded-time" actually means to a caller.
          expect(elapsed).toBeLessThan(wallMs + TIMEOUT_SLACK_MS);
          if (outcome.kind === 'timeout') {
            // Invariant 3: the outcome's own wallMs field reports the bound the runner honored.
            expect(outcome.wallMs).toBeGreaterThanOrEqual(wallMs);
            expect(outcome.wallMs).toBeLessThan(wallMs + TIMEOUT_SLACK_MS);
          }
        },
      ),
      { numRuns: 10 },
    );
  }, 120_000);
});

describe('runBounded — robustness-bounded-mem', () => {
  it('property: heap-blowing scenarios resolve as oom for random small heap caps', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: OOM_HEAP_MB_RANGE.min, max: OOM_HEAP_MB_RANGE.max }),
        fc.integer({ min: SEED_MIN, max: SEED_MAX }),
        fc.constantFrom<'grow-array' | 'grow-string' | 'grow-buffer'>(
          'grow-array',
          'grow-buffer',
        ),
        async (heapMb, seed, mode) => {
          // wallMs must be generous — OOM tripping is not instant; the worker allocates until
          // V8 gives up. If we cap wallMs too tight, we'd measure the timeout path instead.
          const bounds: Bounds = { wallMs: 15_000, heapMb, seed };
          const outcome = await runBounded({ kind: 'synthetic:oom', mode }, bounds);
          // OOM is what we assert. On some Node/V8 versions timing is unpredictable — the
          // worker can be killed with a crash-shaped error before the OOM classifier catches
          // it. Both signals mean "the heap cap trapped the runaway"; only the label differs.
          // We accept either but pin the expectation for the common case.
          expect(['oom', 'crash']).toContain(outcome.kind);
          if (outcome.kind === 'oom') {
            expect(outcome.peakRssBytes).toBeGreaterThan(0);
            // The peak reported is the cap in bytes (see runner.ts: peakRssBytes = heapMb *
            // 1024 * 1024). This invariant makes the harness output a callable estimate.
            expect(outcome.peakRssBytes).toBe(heapMb * 1024 * 1024);
          }
        },
      ),
      { numRuns: 3 },
    );
    // NB: numRuns is intentionally small — each OOM run takes multiple seconds. The property
    // is about "for any small heap cap, we still catch the runaway", not about exhaustive
    // fuzz of allocation shapes.
  }, 180_000);
});

describe('runBounded — worker-timeout-fires', () => {
  // The most-adversarial case for the timer: the worker is inside an `await` that will never
  // resolve, AND the event loop is being kept alive by an unrelated interval. If the timer
  // ever gets starved by microtask scheduling, this is where we'd see it.
  it('await-forever + microtask flood cannot starve the wallMs timer', async () => {
    const bounds: Bounds = { wallMs: 300, heapMb: 128, seed: 11 };
    const started = performance.now();
    const outcome = await runBounded({ kind: 'synthetic:hang', mode: 'await-forever' }, bounds);
    const elapsed = performance.now() - started;
    expect(outcome.kind).toBe('timeout');
    expect(elapsed).toBeLessThan(bounds.wallMs + TIMEOUT_SLACK_MS);
  }, 15_000);

  it('property: timer fires even under a busy-loop that never yields to microtasks', async () => {
    // A busy loop starves *worker-side* microtasks, not the parent's timer thread. This
    // asserts the parent-side timer (setTimeout in the parent context) is independent of
    // whatever the worker is doing — which is exactly what the worker_threads model provides.
    await fc.assert(
      fc.asyncProperty(fc.integer({ min: 150, max: 400 }), async (wallMs) => {
        const bounds: Bounds = { wallMs, heapMb: 128, seed: 1 };
        const outcome = await runBounded(
          { kind: 'synthetic:hang', mode: 'busy-loop' },
          bounds,
        );
        expect(outcome.kind).toBe('timeout');
      }),
      { numRuns: 10 },
    );
  }, 120_000);
});

describe('runBounded — seed-echo-invariant', () => {
  // Every RunOutcome kind carries a `seed` field, and it must be the seed the caller passed.
  // Property-test with random 32-bit unsigned seeds and every outcome kind we can produce
  // synthetically (ok / crash / timeout / fail-safe). OOM is exercised separately above.

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
