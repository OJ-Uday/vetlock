/**
 * P1-B — fetch/worker timeout guard (fail-closed).
 * @security-critical
 *
 * Context: the engine already guarded the ANALYZE step (analyzeTarball) with
 * a timeout race (withTimeout / opts.timeoutMs). The FETCH step — resolving a
 * package's tarball via `fetchOverride` (or the default pacote-backed
 * `fetchTarball`) — had NO timeout guard at all. A fetchOverride that never
 * resolves (a hung Promise) would hang the worker-pool loop in `runDiff`
 * forever; a fetchOverride that resolves slowly could stall the whole run
 * past any reasonable bound.
 *
 * Fix (this change, packages/core/src/engine.ts):
 *   - New `EngineOptions.analyzerTimeoutMs` (default 30_000ms) — separate
 *     from the existing `timeoutMs` (which still guards analyze only).
 *   - `analyzeOne` now races the fetch promise against an
 *     `AbortSignal.timeout(analyzerTimeoutMs)` guard via a new
 *     `withFetchTimeout` helper.
 *   - On timeout, the race rejects with a timeout-shaped message
 *     ("fetch <name>@<version> timed out after <ms>ms"). That rejection is
 *     caught by the SAME per-package try/catch in runDiff's worker loop that
 *     already handles any other fetch/analyze error (the REDTEAM S4 fix),
 *     which synthesizes a BLOCK-tier `analysis.failed` finding — so a stalled
 *     fetch can never cause the run to hang forever OR render CLEAN.
 *
 * These tests assert that guard is actually wired (not just documented):
 *   (a) a fetchOverride Promise that never resolves must still let the
 *       engine finish quickly, ending in a BLOCK `analysis.failed` finding
 *       with a timeout-shaped message.
 *   (b) a fetchOverride that throws a timeout-shaped error explicitly (as a
 *       real fetchOverride wired to `fetch()` + `AbortSignal.timeout()`
 *       would, on network stalls) must be caught by the same fail-closed
 *       path — engine behavior must not depend on our specific error string.
 *
 * A third (non-required) control case checks the guard doesn't produce false
 * positives on a normal-speed run — mirrors the idiom in
 * packages/core/test/redteam-S4-L6.test.ts (FakeCache pre-loads a snapshot so
 * the "clean" package never needs to fetch at all).
 */

import { describe, it, expect } from 'vitest';
import type { Finding, PackageSnapshot, SnapshotPair } from '../src/finding.js';
import { runDiff } from '../src/engine.js';
import { SNAPSHOT_FORMAT_VERSION } from '../src/cache.js';

const FIXED_ISO = '2026-07-12T00:00:00.000Z';

// ---------------------------------------------------------------------------
// Shared helpers (mirrors packages/core/test/redteam-S4-L6.test.ts idiom)
// ---------------------------------------------------------------------------

function mkLock(
  root: { name: string; version: string; deps?: Record<string, string> },
  entries: Record<string, { version: string; integrity?: string }>,
) {
  const packages: Record<string, unknown> = {
    '': { name: root.name, version: root.version, dependencies: root.deps ?? {} },
  };
  for (const [key, val] of Object.entries(entries)) {
    const idx = key.lastIndexOf('node_modules/');
    const derivedName = idx === -1 ? key : key.slice(idx + 'node_modules/'.length);
    packages[key] = {
      name: derivedName,
      version: val.version,
      integrity: val.integrity ?? `sha512-${val.version}=`,
    };
  }
  return JSON.stringify({ name: root.name, version: root.version, lockfileVersion: 3, packages });
}

function mkSnap(name: string, version: string): PackageSnapshot {
  return {
    name,
    version,
    integrity: `sha512-${name}-${version}=`,
    manifest: { name, version },
    files: [],
    nativeArtifacts: [],
    formatVersion: SNAPSHOT_FORMAT_VERSION,
    builtAt: FIXED_ISO,
  };
}

// Minimal no-op cache so the engine doesn't try real disk access.
class NullCache {
  readonly dir = '/tmp/null-cache-worker-timeout';
  async get(_k: string): Promise<PackageSnapshot | null> { return null; }
  async put(_k: string, _v: PackageSnapshot): Promise<void> {}
}

const noDetectors = (_pair: SnapshotPair, _pkg: string): Finding[] => [];

// ---------------------------------------------------------------------------
// (a) fetchOverride that hangs indefinitely — AbortSignal.timeout guard
// ---------------------------------------------------------------------------

describe('P1-B (a): fetchOverride never resolves — AbortSignal.timeout guard must fire', () => {
  const oldLock = mkLock(
    { name: 'root', version: '1.0.0', deps: { stalled: '^1' } },
    { 'node_modules/stalled': { version: '1.0.0', integrity: 'sha512-stalled1=' } },
  );
  const newLock = mkLock(
    { name: 'root', version: '1.0.0', deps: { stalled: '^1' } },
    { 'node_modules/stalled': { version: '1.0.1', integrity: 'sha512-stalled2=' } },
  );

  // A Promise that NEVER settles — simulates a fetch that hangs forever
  // (e.g. a registry connection that never responds and never errors).
  const fetchOverride = async (ref: { name: string }): Promise<string> => {
    if (ref.name === 'stalled') {
      return await new Promise<string>(() => { /* never resolves, never rejects */ });
    }
    throw new Error(`unexpected fetch for ${ref.name}`);
  };

  it('engine does not hang — resolves promptly once analyzerTimeoutMs elapses', async () => {
    const start = Date.now();
    const result = await runDiff(oldLock, newLock, {
      runDetectors: noDetectors,
      fetchOverride,
      cache: new NullCache(),
      // Small timeout so the test stays fast; production default is 30_000ms.
      analyzerTimeoutMs: 40,
    });
    const elapsed = Date.now() - start;
    // Generous upper bound — proves we did NOT wait for the hung promise,
    // only for the configured guard.
    expect(elapsed).toBeLessThan(3000);
    expect(result).toBeDefined();
  });

  it('surfaces a BLOCK-tier analysis.failed finding with a timeout-shaped message', async () => {
    const result = await runDiff(oldLock, newLock, {
      runDetectors: noDetectors,
      fetchOverride,
      cache: new NullCache(),
      analyzerTimeoutMs: 40,
    });

    expect(result.verdict).toBe('BLOCK');

    const failed = result.findings.filter((f) => f.detector === 'analysis.failed');
    expect(failed.length, 'must emit at least one analysis.failed finding').toBeGreaterThan(0);

    const stalledFail = failed.find((f) => f.package === 'stalled');
    expect(stalledFail, 'analysis.failed finding must be for the stalled package').toBeDefined();
    expect(stalledFail!.severity).toBe('BLOCK');
    expect(stalledFail!.category).toBe('META');
    // Message must indicate a TIMEOUT specifically — not a generic error —
    // proving the AbortSignal.timeout guard (not some other failure path)
    // is what tripped.
    expect(stalledFail!.message).toMatch(/timed out/i);
    expect(stalledFail!.message).toContain('40ms');
  });

  it('verdict is never CLEAN when the fetch hangs (fail-closed invariant)', async () => {
    const result = await runDiff(oldLock, newLock, {
      runDetectors: noDetectors,
      fetchOverride,
      cache: new NullCache(),
      analyzerTimeoutMs: 40,
    });
    expect(result.verdict).not.toBe('CLEAN');
  });
});

// ---------------------------------------------------------------------------
// (b) fetchOverride that throws a timeout-shaped error explicitly
// ---------------------------------------------------------------------------

describe('P1-B (b): fetchOverride throws a timeout-shaped error explicitly', () => {
  const oldLock = mkLock(
    { name: 'root', version: '1.0.0', deps: { flaky: '^1' } },
    { 'node_modules/flaky': { version: '2.0.0', integrity: 'sha512-flaky1=' } },
  );
  const newLock = mkLock(
    { name: 'root', version: '1.0.0', deps: { flaky: '^1' } },
    { 'node_modules/flaky': { version: '2.0.1', integrity: 'sha512-flaky2=' } },
  );

  // Simulates a REAL fetchOverride implementation that itself uses
  // `fetch(url, { signal: AbortSignal.timeout(ms) })` — on expiry, the
  // Fetch API rejects with a DOMException named 'TimeoutError'. The engine's
  // fail-closed path must not depend on our internal error string; any
  // timeout-shaped rejection from the caller-supplied fetchOverride must be
  // treated the same as our own AbortSignal.timeout guard tripping.
  const fetchOverride = async (ref: { name: string }): Promise<string> => {
    if (ref.name === 'flaky') {
      throw new DOMException('The operation was aborted due to timeout', 'TimeoutError');
    }
    throw new Error(`unexpected fetch for ${ref.name}`);
  };

  it('surfaces a BLOCK-tier analysis.failed finding quoting the timeout error', async () => {
    const result = await runDiff(oldLock, newLock, {
      runDetectors: noDetectors,
      fetchOverride,
      cache: new NullCache(),
    });

    expect(result.verdict).toBe('BLOCK');

    const failed = result.findings.filter((f) => f.detector === 'analysis.failed');
    const flakyFail = failed.find((f) => f.package === 'flaky');
    expect(flakyFail, 'analysis.failed finding must be for the flaky package').toBeDefined();
    expect(flakyFail!.severity).toBe('BLOCK');
    expect(flakyFail!.confidence).toBe('high');
    expect(flakyFail!.message).toMatch(/timeout/i);
    expect(flakyFail!.message).toContain('aborted due to timeout');
  });

  it('the per-package errors array still records the timeout error (backwards compat)', async () => {
    const result = await runDiff(oldLock, newLock, {
      runDetectors: noDetectors,
      fetchOverride,
      cache: new NullCache(),
    });
    const flakyError = result.errors.find((e) => e.package === 'flaky');
    expect(flakyError).toBeDefined();
    expect(flakyError!.error).toMatch(/timeout/i);
  });

  it('verdict is never CLEAN when fetchOverride throws a timeout error (fail-closed invariant)', async () => {
    const result = await runDiff(oldLock, newLock, {
      runDetectors: noDetectors,
      fetchOverride,
      cache: new NullCache(),
    });
    expect(result.verdict).not.toBe('CLEAN');
    expect(result.verdict).not.toBe('WARN');
    expect(result.verdict).not.toBe('INFO');
  });
});

// ---------------------------------------------------------------------------
// (control) the timeout guard must not misfire on a normal-speed run
// ---------------------------------------------------------------------------

describe('P1-B (control): timeout guard does not false-positive on a healthy fetch', () => {
  const oldLock = mkLock(
    { name: 'root', version: '1.0.0', deps: { clean: '^1' } },
    { 'node_modules/clean': { version: '1.0.0', integrity: 'sha512-clean1=' } },
  );
  const newLock = mkLock(
    { name: 'root', version: '1.0.0', deps: { clean: '^1' } },
    { 'node_modules/clean': { version: '1.0.1', integrity: 'sha512-clean2=' } },
  );

  // FakeCache pre-loads snapshots by integrity so `clean` is resolved via the
  // cache-hit path and never needs to call fetchOverride at all — if it ever
  // does, that's a bug (fail the test loudly instead of silently hanging).
  class FakeCache extends NullCache {
    private store = new Map<string, PackageSnapshot>([
      ['sha512-clean1=', mkSnap('clean', '1.0.0')],
      ['sha512-clean2=', mkSnap('clean', '1.0.1')],
    ]);
    override async get(k: string): Promise<PackageSnapshot | null> { return this.store.get(k) ?? null; }
  }

  it('verdict is CLEAN and no analysis.failed finding appears', async () => {
    const fetchOverride = async (ref: { name: string }): Promise<string> => {
      throw new Error(`should not fetch — ${ref.name} must resolve via cache`);
    };
    const result = await runDiff(oldLock, newLock, {
      runDetectors: noDetectors,
      fetchOverride,
      cache: new FakeCache(),
      analyzerTimeoutMs: 40,
    });
    expect(result.findings.some((f) => f.detector === 'analysis.failed')).toBe(false);
    expect(result.verdict).toBe('CLEAN');
  });
});
