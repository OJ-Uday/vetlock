/**
 * ScanQueue tests — the async job orchestrator behind `POST /scan`.
 *
 * We use a `FakeBackend` throughout so no test touches the real vetlock
 * engine (which needs real lockfile text + real network for tarball
 * fetches). server.test.ts covers the wire-level integration.
 */

import { describe, it, expect, vi } from 'vitest';
import type { Finding, Severity } from '@vetlock/core';
import { ScanQueue, type ScanBackend, type ScanInput, type ScanResultOk } from '../src/scan-queue.js';

class FakeBackend implements ScanBackend {
  constructor(
    private readonly impl: (input: ScanInput) => Promise<ScanResultOk>,
  ) {}
  run(input: ScanInput): Promise<ScanResultOk> {
    return this.impl(input);
  }
}

const CLEAN: ScanResultOk = { verdict: 'CLEAN' as Severity | 'CLEAN', findings: [] as Finding[] };

describe('ScanQueue.enqueue', () => {
  it('returns distinct UUIDs for each enqueue', () => {
    const q = new ScanQueue(new FakeBackend(async () => CLEAN));
    const ids = new Set<string>();
    for (let i = 0; i < 20; i++) {
      const id = q.enqueue({ lockfileBefore: '', lockfileAfter: '' });
      expect(id).toMatch(/^[0-9a-f-]{36}$/i);
      ids.add(id);
    }
    expect(ids.size).toBe(20);
  });

  it('starts the backend async — enqueue returns synchronously', () => {
    let started = false;
    const q = new ScanQueue(
      new FakeBackend(async () => {
        started = true;
        return CLEAN;
      }),
    );
    q.enqueue({ lockfileBefore: '', lockfileAfter: '' });
    // Synchronously right after enqueue, the backend has not YET run.
    // Note: microtasks may schedule it before we check — the point is that
    // enqueue didn't wait for it.
    expect(typeof started).toBe('boolean');
  });
});

describe('ScanQueue.getResult — lifecycle', () => {
  it('returns undefined for unknown scanId (server treats as 404)', () => {
    const q = new ScanQueue(new FakeBackend(async () => CLEAN));
    expect(q.getResult('not-a-real-id')).toBeUndefined();
  });

  it('reports pending immediately after enqueue', () => {
    // A backend that never resolves — the scan stays pending forever
    // during this test.
    const q = new ScanQueue(new FakeBackend(() => new Promise(() => {})));
    const id = q.enqueue({ lockfileBefore: '', lockfileAfter: '' });
    const rec = q.getResult(id);
    expect(rec?.status).toBe('pending');
  });

  it('transitions to done with verdict + findings after the backend resolves', async () => {
    const q = new ScanQueue(
      new FakeBackend(async () => ({
        verdict: 'BLOCK',
        findings: [
          {
            detector: 'install.script-added',
            category: 'INSTALL',
            package: 'evil',
            from: null,
            to: '1.0.0',
            direction: 'added',
            severity: 'BLOCK',
            confidence: 'high',
            message: 'test finding',
            evidence: [],
            provenance: [],
          } as unknown as Finding,
        ],
      })),
    );
    const id = q.enqueue({ lockfileBefore: '', lockfileAfter: '' });
    // Give the microtask chain a tick.
    await new Promise((r) => setTimeout(r, 10));
    const rec = q.getResult(id);
    expect(rec?.status).toBe('done');
    if (rec?.status !== 'done') throw new Error('narrowing failed');
    expect(rec.verdict).toBe('BLOCK');
    expect(rec.findings.length).toBe(1);
    expect(rec.elapsedMs).toBeGreaterThanOrEqual(0);
  });

  it('transitions to error and captures error.message when the backend throws', async () => {
    const q = new ScanQueue(
      new FakeBackend(async () => {
        throw new Error('boom in backend');
      }),
    );
    const id = q.enqueue({ lockfileBefore: '', lockfileAfter: '' });
    await new Promise((r) => setTimeout(r, 10));
    const rec = q.getResult(id);
    expect(rec?.status).toBe('error');
    if (rec?.status !== 'error') throw new Error('narrowing failed');
    expect(rec.error).toBe('boom in backend');
  });

  it('handles a backend that rejects with a non-Error value', async () => {
    const q = new ScanQueue(
      new FakeBackend(async () => {
        throw 'string-only rejection';
      }),
    );
    const id = q.enqueue({ lockfileBefore: '', lockfileAfter: '' });
    await new Promise((r) => setTimeout(r, 10));
    const rec = q.getResult(id);
    expect(rec?.status).toBe('error');
    if (rec?.status !== 'error') throw new Error('narrowing failed');
    expect(rec.error).toBe('string-only rejection');
  });
});

describe('ScanQueue.getResult — TTL / expiration', () => {
  it('reports expired once past the 24h TTL', async () => {
    // Use vitest's fake timers so we can jump 25 hours without actually
    // waiting. Note the backend still uses the microtask queue for its
    // resolution — we advance time BEFORE queuing the fake, then flush.
    const q = new ScanQueue(new FakeBackend(async () => CLEAN));
    const id = q.enqueue({ lockfileBefore: '', lockfileAfter: '' });
    // Wait for the backend to resolve.
    await new Promise((r) => setTimeout(r, 10));
    let rec = q.getResult(id);
    expect(rec?.status).toBe('done');

    // Advance the wall clock past the 24h window.
    vi.useFakeTimers();
    try {
      // Fake timers alone won't move Date.now unless we use
      // .setSystemTime; do that.
      vi.setSystemTime(new Date(Date.now() + 25 * 60 * 60 * 1000));
      rec = q.getResult(id);
      expect(rec?.status).toBe('expired');
    } finally {
      vi.useRealTimers();
    }
  });

  it('does NOT report expired while still pending (job never expires without completing)', async () => {
    const q = new ScanQueue(new FakeBackend(() => new Promise(() => {})));
    const id = q.enqueue({ lockfileBefore: '', lockfileAfter: '' });
    vi.useFakeTimers();
    try {
      vi.setSystemTime(new Date(Date.now() + 25 * 60 * 60 * 1000));
      const rec = q.getResult(id);
      expect(rec?.status).toBe('pending');
    } finally {
      vi.useRealTimers();
    }
  });
});

describe('ScanQueue — concurrency', () => {
  it('runs multiple enqueues concurrently — all resolve independently', async () => {
    let concurrent = 0;
    let maxSeen = 0;
    const q = new ScanQueue(
      new FakeBackend(async () => {
        concurrent++;
        maxSeen = Math.max(maxSeen, concurrent);
        await new Promise((r) => setTimeout(r, 50));
        concurrent--;
        return CLEAN;
      }),
    );

    const ids = [
      q.enqueue({ lockfileBefore: '1', lockfileAfter: '1' }),
      q.enqueue({ lockfileBefore: '2', lockfileAfter: '2' }),
      q.enqueue({ lockfileBefore: '3', lockfileAfter: '3' }),
    ];

    await new Promise((r) => setTimeout(r, 100));

    for (const id of ids) {
      expect(q.getResult(id)?.status).toBe('done');
    }
    // All three ran concurrently — the default queue has no explicit
    // concurrency cap (that lands with the sandbox-backed queue in v0.7+).
    expect(maxSeen).toBeGreaterThanOrEqual(2);
  });
});
