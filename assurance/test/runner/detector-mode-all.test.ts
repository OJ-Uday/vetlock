/**
 * Wave 4-R — detectorMode: 'all' integration wiring.
 *
 * The engine:runDiff scenario now supports 'all' in addition to 'none'. Under 'all', the
 * worker dynamic-imports @vetlock/detectors and wires runAll(pair) as the engine's
 * runDetectors callback. This is the plumbing prerequisite for future evasion-catch-rate
 * and enumerated-coverage metrics — those tiers cannot even run without a real detector
 * closure hooked up to runDiff.
 *
 * This test proves the wiring works end-to-end:
 *   1. runBounded with detectorMode: 'all' produces a valid outcome (ok / fail-safe).
 *   2. findings is an array (may be empty for a benign zero-diff — that's fine; the
 *      escalation rules in runAll never fabricate findings out of nothing).
 *   3. The scenario passes structured-clone (no closures leaked into the message).
 *
 * The test intentionally uses a benign npm v3 lockfile with a zero diff (same version
 * pinned on both sides). That path avoids the fetch code entirely — the engine never
 * calls fetchOverride when there are no added/changed packages to resolve — which keeps
 * this test hermetic and fast.
 */

import { describe, it, expect } from 'vitest';
import { runBounded } from '../../src/runner/index.js';
import type { Bounds } from '../../src/oracles/types.js';

// Longer wallMs than the 'none'-mode sibling test — the 'all' path imports and runs
// every detector in @vetlock/detectors, which is heavier than a no-op closure. Still
// small: the whole pipeline for a zero-diff runs in well under a second.
const BOUNDS: Bounds = { wallMs: 10_000, heapMb: 256, seed: 42 };

// Minimal npm v3 lockfile with one dependency edge. The 'zero diff' pair — same version
// pinned on both sides — means no fetch, no analyze, no detector work over actual
// tarballs. runDiff still exercises the parser + changeset + rollup layers, and if any
// detector emits a static-analysis finding on the manifest itself (e.g. typosquat check
// against 'left-pad'), we observe that too.
const MIN_NPM_LOCK = JSON.stringify(
  {
    name: 'test',
    version: '1.0.0',
    lockfileVersion: 3,
    requires: true,
    packages: {
      '': {
        name: 'test',
        version: '1.0.0',
        dependencies: { 'left-pad': '1.3.0' },
      },
      'node_modules/left-pad': {
        version: '1.3.0',
        resolved: 'https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz',
        integrity: 'sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGUNEc86T1jjZjcTd7A==',
      },
    },
  },
  null,
  2,
);

describe('engine:runDiff — wiring (detector-mode "all")', () => {
  it('accepts detectorMode: "all" and returns a valid outcome on a benign zero-diff', async () => {
    const outcome = await runBounded(
      {
        kind: 'engine:runDiff',
        enginePath: '@vetlock/core',
        oldLockfileText: MIN_NPM_LOCK,
        newLockfileText: MIN_NPM_LOCK,
        oldLockfilePath: 'package-lock.json',
        newLockfilePath: 'package-lock.json',
        detectorMode: 'all',
      },
      BOUNDS,
    );
    // The scenario is well-formed and the wiring is correct → we expect either 'ok'
    // (no findings triggered) or 'fail-safe' (the engine's analysis.failed channel).
    // Anything else (crash, timeout, oom) means the wiring broke.
    expect(['ok', 'fail-safe']).toContain(outcome.kind);
  });

  it('produces findings as an array (may be empty; escalation never fabricates)', async () => {
    const outcome = await runBounded(
      {
        kind: 'engine:runDiff',
        enginePath: '@vetlock/core',
        oldLockfileText: MIN_NPM_LOCK,
        newLockfileText: MIN_NPM_LOCK,
        oldLockfilePath: 'package-lock.json',
        newLockfilePath: 'package-lock.json',
        detectorMode: 'all',
      },
      BOUNDS,
    );
    if (outcome.kind === 'ok' || outcome.kind === 'fail-safe') {
      expect(Array.isArray(outcome.findings)).toBe(true);
    }
  });

  it('propagates seed and reports wallMs on ok', async () => {
    const outcome = await runBounded(
      {
        kind: 'engine:runDiff',
        enginePath: '@vetlock/core',
        oldLockfileText: MIN_NPM_LOCK,
        newLockfileText: MIN_NPM_LOCK,
        oldLockfilePath: 'package-lock.json',
        newLockfilePath: 'package-lock.json',
        detectorMode: 'all',
      },
      BOUNDS,
    );
    if (outcome.kind === 'ok') {
      expect(outcome.seed).toBe(42);
      expect(outcome.wallMs).toBeGreaterThanOrEqual(0);
    }
  });
});
