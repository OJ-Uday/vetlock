/**
 * worker-timeout-fires — the wallMs timer cannot be starved.
 *
 * Named test from packet §5 P1. Split out of harness-invariants.test.ts so the file name
 * matches the semantic invariant, which makes failing-CI logs self-describing (the metrics
 * collector still buckets `test/runner/*` into the "robustness" bucket via path — no metric
 * change from the split).
 *
 * Invariant this file proves: even under adversarial patterns designed to starve the timer
 * (await-forever pinned on a microtask that never resolves; a busy loop that never yields to
 * microtasks), the parent-side wallMs timer still fires and produces `kind: 'timeout'`.
 * Worker_threads gives us this property for free — the parent's setTimeout runs in the
 * parent context, independent of whatever the worker is doing. This suite asserts we
 * actually get that free property in practice.
 */

import { describe, it, expect } from 'vitest';
import * as fc from 'fast-check';
import { performance } from 'node:perf_hooks';
import { runBounded } from '../../src/runner/index.js';
import type { Bounds } from '../../src/oracles/types.js';

// The extra slack we allow the runner over its stated wallMs before we accuse it of running
// long. Worker spawn + terminate + fork-scheduling on a busy CI box can easily eat 200-800ms;
// 2_000ms is enough headroom that the assertion fails only on a real bug, not on a slow lane.
const TIMEOUT_SLACK_MS = 2_000;

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
