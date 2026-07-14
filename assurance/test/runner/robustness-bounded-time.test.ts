/**
 * robustness-bounded-time — the wallMs bound HOLDS for hanging scenarios.
 *
 * Named test from packet §5 P1. Split out of harness-invariants.test.ts so the file name
 * matches the semantic invariant, which makes failing-CI logs self-describing (the metrics
 * collector still buckets `test/runner/*` into the "robustness" bucket via path — no metric
 * change from the split).
 *
 * Invariant this file proves: a scenario that would otherwise hang forever resolves with
 * `kind === 'timeout'` within `bounds.wallMs + slack` wall time, and the outcome's own
 * `wallMs` field reports the honored bound.
 *
 * Property discipline: numRuns is deliberately small (10). This suite runs on every PR;
 * a minutes-long property fuzz would either get muted (packet rule #5) or push CI wall time
 * past useful. The point of fast-check here is to sweep the seed axis — not to exhaustively
 * fuzz the runner. runner.test.ts already carries the concrete assertions; this file adds
 * the "does it hold for arbitrary inputs?" layer.
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
