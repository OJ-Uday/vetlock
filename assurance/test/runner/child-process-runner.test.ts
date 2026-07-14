/**
 * Child-process runner tests (ADR-0003 extension).
 *
 * Mirror of runner.test.ts but drives `runBoundedInProcess`. Purpose:
 *   1. Prove the child_process fallback observes the same failure modes worker_threads does
 *      (ok / timeout / crash / oom / fail-safe) → parity contract on RunOutcome.
 *   2. Prove the fallback observes what worker_threads MISSES: an uncatchable native abort
 *      (`process.abort()`, SIGABRT). This is the whole reason the fallback exists — the
 *      worker_threads runner would take the parent Node process (and the vitest tinypool
 *      host) down with the child. This test would abort the entire test file if run
 *      through the worker_threads path.
 *
 * The v8-abort scenario type is a child-only extension (see child-entry.ts's ChildOnlyScenario
 * union); it's cast through `as never` here because it isn't in the shared Scenario type.
 */

import { describe, it, expect } from 'vitest';
import { runBoundedInProcess } from '../../src/runner/index.js';
import type { Bounds, RunOutcome } from '../../src/oracles/types.js';
import type { Scenario } from '../../src/runner/index.js';

const DEFAULT_BOUNDS: Bounds = { wallMs: 5_000, heapMb: 128, seed: 42 };
// OOM tests need a lower heap cap so the child trips it in bounded time.
const SMALL_HEAP_BOUNDS: Bounds = { wallMs: 10_000, heapMb: 32, seed: 42 };

describe('runBoundedInProcess — synthetic:normal', () => {
  it('returns ok with the findings the scenario declared', async () => {
    const finding = { capabilityClass: 'code-execution', severity: 'BLOCK' as const, reason: 'test' };
    const outcome = await runBoundedInProcess(
      { kind: 'synthetic:normal', workMs: 10, findings: [finding] },
      DEFAULT_BOUNDS,
    );
    expect(outcome.kind).toBe('ok');
    if (outcome.kind === 'ok') {
      expect(outcome.findings).toEqual([finding]);
      expect(outcome.wallMs).toBeGreaterThanOrEqual(0);
      expect(outcome.seed).toBe(42);
    }
  }, 15_000);

  it('returns ok with empty findings when the scenario declares none', async () => {
    const outcome = await runBoundedInProcess({ kind: 'synthetic:normal' }, DEFAULT_BOUNDS);
    expect(outcome.kind).toBe('ok');
    if (outcome.kind === 'ok') {
      expect(outcome.findings).toEqual([]);
    }
  }, 15_000);
});

describe('runBoundedInProcess — synthetic:hang (timeout enforcement)', () => {
  it('returns timeout for a busy-loop hang', async () => {
    // wallMs is generous vs. the worker_threads runner because spawning a Node child
    // takes ~100-300ms on typical hardware; a 300ms budget would classify spawn overhead
    // as a hang.
    const tight: Bounds = { wallMs: 1_500, heapMb: 128, seed: 1 };
    const outcome = await runBoundedInProcess({ kind: 'synthetic:hang', mode: 'busy-loop' }, tight);
    expect(outcome.kind).toBe('timeout');
    if (outcome.kind === 'timeout') {
      expect(outcome.wallMs).toBeGreaterThanOrEqual(1_000);
      expect(outcome.wallMs).toBeLessThan(10_000);
    }
  }, 15_000);

  it('returns timeout for an await-forever hang', async () => {
    const tight: Bounds = { wallMs: 1_500, heapMb: 128, seed: 2 };
    const outcome = await runBoundedInProcess(
      { kind: 'synthetic:hang', mode: 'await-forever' },
      tight,
    );
    expect(outcome.kind).toBe('timeout');
  }, 15_000);
});

describe('runBoundedInProcess — synthetic:crash', () => {
  it('returns crash with the thrown error captured', async () => {
    const outcome = await runBoundedInProcess(
      { kind: 'synthetic:crash', errorName: 'TypeError', errorMessage: 'deliberate boom' },
      DEFAULT_BOUNDS,
    );
    expect(outcome.kind).toBe('crash');
    if (outcome.kind === 'crash') {
      expect(outcome.error.name).toBe('TypeError');
      expect(outcome.error.message).toBe('deliberate boom');
    }
  }, 15_000);

  it('captures a default error when the scenario omits fields', async () => {
    const outcome = await runBoundedInProcess({ kind: 'synthetic:crash' }, DEFAULT_BOUNDS);
    expect(outcome.kind).toBe('crash');
    if (outcome.kind === 'crash') {
      expect(outcome.error.name).toBeTruthy();
    }
  }, 15_000);
});

describe('runBoundedInProcess — synthetic:oom', () => {
  it('returns oom when the child blows the heap cap (grow-array)', async () => {
    const outcome = await runBoundedInProcess(
      { kind: 'synthetic:oom', mode: 'grow-array' },
      SMALL_HEAP_BOUNDS,
    );
    // The child_process runner normalizes SIGABRT, exit code 5/134, and stderr OOM
    // patterns all to `kind: 'oom'`. Any of them counts.
    expect(outcome.kind).toBe('oom');
    if (outcome.kind === 'oom') {
      expect(outcome.peakRssBytes).toBeGreaterThan(0);
      expect(outcome.seed).toBe(42);
    }
  }, 30_000);
});

describe('runBoundedInProcess — synthetic:fail-safe', () => {
  it('returns fail-safe with the declared reason and a BLOCK finding', async () => {
    const outcome = await runBoundedInProcess(
      { kind: 'synthetic:fail-safe', reason: 'analysis-failed', capabilityClass: 'code-execution' },
      DEFAULT_BOUNDS,
    );
    expect(outcome.kind).toBe('fail-safe');
    if (outcome.kind === 'fail-safe') {
      expect(outcome.reason).toBe('analysis-failed');
      expect(outcome.findings.length).toBeGreaterThan(0);
      expect(outcome.findings[0].severity).toBe('BLOCK');
    }
  }, 15_000);
});

describe('runBoundedInProcess — V8 abort (the whole point of the fallback)', () => {
  it('survives an uncatchable native abort (process.abort) that would crash worker_threads', async () => {
    // synthetic:v8-abort is a child-only scenario kind. It's not in the shared Scenario
    // union — the worker_threads runner would reject it — because the whole design is that
    // ONLY the child-process runner can observe an uncatchable native abort without dying
    // itself. We cast through `never` (via the intermediate unknown) to hand this hostile
    // kind to the child.
    const hostile = { kind: 'synthetic:v8-abort', mode: 'process-abort' } as unknown as Scenario;
    const outcome: RunOutcome = await runBoundedInProcess(hostile, DEFAULT_BOUNDS);
    // SIGABRT maps to `kind: 'oom'` per the runner's classification (V8's abort code
    // convention). What matters is the parent SURVIVED to observe it — if the fallback
    // used worker_threads, this test file would have died before this assertion ran.
    expect(outcome.kind).toBe('oom');
    if (outcome.kind === 'oom') {
      expect(outcome.seed).toBe(42);
    }
  }, 15_000);
});

describe('runBoundedInProcess — invariants', () => {
  it('propagates the seed into every outcome kind', async () => {
    const seedBounds: Bounds = { wallMs: 5_000, heapMb: 128, seed: 12345 };
    const normal = await runBoundedInProcess({ kind: 'synthetic:normal' }, seedBounds);
    const crash = await runBoundedInProcess({ kind: 'synthetic:crash' }, seedBounds);
    const timeout = await runBoundedInProcess(
      { kind: 'synthetic:hang', mode: 'await-forever' },
      { ...seedBounds, wallMs: 1_500 },
    );
    for (const o of [normal, crash, timeout]) {
      if ('seed' in o) {
        expect(o.seed).toBe(12345);
      }
    }
  }, 30_000);

  it('resolves exactly once even across back-to-back runs (no leaked child processes)', async () => {
    for (let i = 0; i < 3; i++) {
      const o = await runBoundedInProcess({ kind: 'synthetic:normal', workMs: 5 }, DEFAULT_BOUNDS);
      expect(o.kind).toBe('ok');
    }
  }, 30_000);
});
