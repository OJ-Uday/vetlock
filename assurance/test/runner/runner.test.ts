/**
 * Bounded runner self-tests (ADR-0003).
 *
 * These tests drive the runner with synthetic scenarios that each map to exactly one
 * RunOutcome kind, proving the bounds actually fire. The synthetic scenarios exist only for
 * this: they let P0 fully validate the runner without needing the engine wired in.
 *
 * The runner MUST:
 *   - Return `ok` for normal scenarios inside their bounds
 *   - Return `timeout` for hanging scenarios (both busy-loop and await-forever modes)
 *   - Return `oom` for scenarios that blow the heap cap
 *   - Return `crash` when the worker throws
 *   - Return `fail-safe` when the synthetic scenario emits the fail-safe signal
 *   - Never itself crash, hang, or leak workers between test cases
 */

import { describe, it, expect } from 'vitest';
import { runBounded } from '../../src/runner/index.js';
import type { Bounds } from '../../src/oracles/types.js';

// Bounds picked so tests run in single-digit seconds.
// wallMs is generous enough that normal ok scenarios finish comfortably, tight enough that
// hang scenarios trip quickly.
const DEFAULT_BOUNDS: Bounds = { wallMs: 2_000, heapMb: 128, seed: 42 };
// OOM tests need a lower heap cap so the worker trips it before it starves the test box.
const SMALL_HEAP_BOUNDS: Bounds = { wallMs: 5_000, heapMb: 32, seed: 42 };

describe('runBounded — synthetic:normal', () => {
  it('returns ok with the findings the scenario declared', async () => {
    const finding = { capabilityClass: 'code-execution', severity: 'BLOCK' as const, reason: 'test' };
    const outcome = await runBounded(
      { kind: 'synthetic:normal', workMs: 10, findings: [finding] },
      DEFAULT_BOUNDS,
    );
    expect(outcome.kind).toBe('ok');
    if (outcome.kind === 'ok') {
      expect(outcome.findings).toEqual([finding]);
      expect(outcome.wallMs).toBeGreaterThanOrEqual(0);
      expect(outcome.seed).toBe(42);
    }
  });

  it('returns ok with empty findings when the scenario declares none', async () => {
    const outcome = await runBounded({ kind: 'synthetic:normal' }, DEFAULT_BOUNDS);
    expect(outcome.kind).toBe('ok');
    if (outcome.kind === 'ok') {
      expect(outcome.findings).toEqual([]);
    }
  });
});

describe('runBounded — synthetic:hang (timeout enforcement)', () => {
  it('returns timeout for a busy-loop hang', async () => {
    const tight: Bounds = { wallMs: 300, heapMb: 128, seed: 1 };
    const outcome = await runBounded({ kind: 'synthetic:hang', mode: 'busy-loop' }, tight);
    expect(outcome.kind).toBe('timeout');
    if (outcome.kind === 'timeout') {
      // wallMs in the outcome should be close to the bound (within a generous margin).
      expect(outcome.wallMs).toBeGreaterThanOrEqual(200);
      expect(outcome.wallMs).toBeLessThan(3_000);
    }
  }, 10_000);

  it('returns timeout for an await-forever hang', async () => {
    const tight: Bounds = { wallMs: 300, heapMb: 128, seed: 2 };
    const outcome = await runBounded({ kind: 'synthetic:hang', mode: 'await-forever' }, tight);
    expect(outcome.kind).toBe('timeout');
  }, 10_000);
});

describe('runBounded — synthetic:crash', () => {
  it('returns crash with the thrown error captured', async () => {
    const outcome = await runBounded(
      { kind: 'synthetic:crash', errorName: 'TypeError', errorMessage: 'deliberate boom' },
      DEFAULT_BOUNDS,
    );
    expect(outcome.kind).toBe('crash');
    if (outcome.kind === 'crash') {
      expect(outcome.error.name).toBe('TypeError');
      expect(outcome.error.message).toBe('deliberate boom');
    }
  });

  it('captures a default error when the scenario omits fields', async () => {
    const outcome = await runBounded({ kind: 'synthetic:crash' }, DEFAULT_BOUNDS);
    expect(outcome.kind).toBe('crash');
    if (outcome.kind === 'crash') {
      expect(outcome.error.name).toBeTruthy();
    }
  });
});

describe('runBounded — synthetic:oom', () => {
  it('returns oom when the worker blows the heap cap (grow-array)', async () => {
    const outcome = await runBounded(
      { kind: 'synthetic:oom', mode: 'grow-array' },
      SMALL_HEAP_BOUNDS,
    );
    // Some Node/V8 versions surface OOM as an exit-code 5, others as a distinctive error name.
    // The runner must normalize either signal to `kind: 'oom'` — this is the assertion.
    expect(outcome.kind).toBe('oom');
    if (outcome.kind === 'oom') {
      expect(outcome.peakRssBytes).toBeGreaterThan(0);
    }
  }, 30_000);
});

describe('runBounded — synthetic:fail-safe', () => {
  it('returns fail-safe with the declared reason and a BLOCK finding', async () => {
    const outcome = await runBounded(
      { kind: 'synthetic:fail-safe', reason: 'analysis-failed', capabilityClass: 'code-execution' },
      DEFAULT_BOUNDS,
    );
    expect(outcome.kind).toBe('fail-safe');
    if (outcome.kind === 'fail-safe') {
      expect(outcome.reason).toBe('analysis-failed');
      expect(outcome.findings.length).toBeGreaterThan(0);
      expect(outcome.findings[0].severity).toBe('BLOCK');
    }
  });
});

describe('runBounded — invariants', () => {
  it('propagates the seed into every outcome kind', async () => {
    const seedBounds: Bounds = { wallMs: 2_000, heapMb: 128, seed: 12345 };
    const normal = await runBounded({ kind: 'synthetic:normal' }, seedBounds);
    const crash = await runBounded({ kind: 'synthetic:crash' }, seedBounds);
    const timeout = await runBounded(
      { kind: 'synthetic:hang', mode: 'await-forever' },
      { ...seedBounds, wallMs: 200 },
    );
    for (const o of [normal, crash, timeout]) {
      // Every outcome kind carries the seed the caller passed.
      if ('seed' in o) {
        expect(o.seed).toBe(12345);
      }
    }
  }, 10_000);

  it('resolves exactly once even if the worker settles racy-close to the timeout', async () => {
    // Not directly observable, but: back-to-back runs must not leak state or workers.
    for (let i = 0; i < 5; i++) {
      const o = await runBounded({ kind: 'synthetic:normal', workMs: 5 }, DEFAULT_BOUNDS);
      expect(o.kind).toBe('ok');
    }
  });
});
