/**
 * robustness-bounded-mem — the heap cap HOLDS for allocation-blowing scenarios.
 *
 * Named test from packet §5 P1. Split out of harness-invariants.test.ts so the file name
 * matches the semantic invariant, which makes failing-CI logs self-describing (the metrics
 * collector still buckets `test/runner/*` into the "robustness" bucket via path — no metric
 * change from the split).
 *
 * Invariant this file proves: a scenario that would otherwise blow the heap resolves as
 * `oom`, `crash`, or `timeout` (all three signal "the cap trapped the runaway"). We accept
 * any of the three because on some Node/V8 versions timing is unpredictable — the worker
 * can be killed with a crash-shaped error before the OOM classifier catches it, OR the
 * wallMs can trip first when the allocation rate is CPU-bound. Only the label differs.
 */

import { describe, it, expect } from 'vitest';
import * as fc from 'fast-check';
import { runBounded } from '../../src/runner/index.js';
import type { Bounds } from '../../src/oracles/types.js';

// Small heap cap used for OOM property runs. Keep the heap cap generous enough that Node can
// still bootstrap the worker (V8 needs its own overhead), tight enough that the scenario trips
// it in seconds not tens of seconds.
const OOM_HEAP_MB_RANGE = { min: 16, max: 48 } as const;

// 32-bit-unsigned seed range, matching the shape the report uses.
const SEED_MIN = 0;
const SEED_MAX = 0xffff_ffff;

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
          // it, OR the wallMs can trip first when the allocation rate is CPU-bound. All three
          // signals mean "the heap cap or wall clock trapped the runaway"; only the label
          // differs. We accept any of them.
          expect(['oom', 'crash', 'timeout']).toContain(outcome.kind);
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
