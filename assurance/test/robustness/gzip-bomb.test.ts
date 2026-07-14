/**
 * gzip-bomb robustness tests.
 *
 * Feeds each hostile gzip mode through @vetlock/core's `analyzeTarball` and asserts the
 * scanner handles it without unbounded memory growth, native aborts, or hangs.
 *
 * MODES:
 *  - high-ratio: a small gzip decompressing to many MiB. The extractor's per-entry cap
 *    (default 50 MiB) and total cap (default 500 MiB) must contain it.
 *  - invalid-header: malformed gzip stream. zlib must throw a plain Error the scanner
 *    surfaces cleanly (no native abort).
 *
 * Every fixture is <100 KB on disk. High-ratio inputs test what happens when a naive
 * scanner would try to hold the CLAIMED decompressed size in memory; the extractor's
 * cap-based approach means it fails fast on the first cap trip.
 *
 * TASK NOTE: assurance/src/robustness/index.ts is owned by Wave 2 — we import the
 * generator directly by file path here, not via the barrel.
 */

import { describe, it, expect, afterAll } from 'vitest';
import { promises as fs } from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as crypto from 'node:crypto';
import { analyzeTarball, UnsafeArchiveError } from '@vetlock/core';
import { gzipBomb, type GzipBombInput } from '../../src/robustness/gzip-bomb.js';

const tmpBase = path.join(os.tmpdir(), `vetlock-assurance-gzip-bomb-${crypto.randomBytes(4).toString('hex')}`);

afterAll(async () => {
  await fs.rm(tmpBase, { recursive: true, force: true });
});

async function materialize(input: GzipBombInput): Promise<string> {
  await fs.mkdir(tmpBase, { recursive: true });
  const p = path.join(tmpBase, `${crypto.randomBytes(4).toString('hex')}-${input.filename}`);
  await fs.writeFile(p, input.bytes);
  return p;
}

/** Same bounded wrapper as tar-bomb.test.ts — analyzeTarball with a wallMs cap. */
async function analyzeBounded(
  tgzPath: string,
  wallMs: number,
): Promise<
  | { status: 'ok' }
  | { status: 'rejected'; error: Error }
  | { status: 'timeout' }
> {
  let timerHandle: NodeJS.Timeout | undefined;
  const timeoutPromise = new Promise<{ status: 'timeout' }>((resolve) => {
    timerHandle = setTimeout(() => resolve({ status: 'timeout' }), wallMs);
  });
  const analyzePromise = analyzeTarball(tgzPath, {
    baseTmpDir: path.join(tmpBase, 'extract'),
  }).then(
    (): { status: 'ok' } => ({ status: 'ok' }),
    (err: unknown): { status: 'rejected'; error: Error } => ({
      status: 'rejected',
      error: err instanceof Error ? err : new Error(String(err)),
    }),
  );
  try {
    return await Promise.race([analyzePromise, timeoutPromise]);
  } finally {
    if (timerHandle) clearTimeout(timerHandle);
  }
}

const WALL_MS = 15_000; // High-ratio streams take longer to walk than tar-bomb — allow
                        // headroom. A genuine hang would blow this cap.

// ------------------------------------------------------------------------------------------
// mode: high-ratio
// ------------------------------------------------------------------------------------------

describe('gzip-bomb: high-ratio (small gzip, large decompressed size)', () => {
  it('baseline (5 MiB decompressed): extractor tolerates it — under all caps', async () => {
    const input = gzipBomb.generate(1, { mode: 'high-ratio', scale: 'baseline' });
    // Fixture on disk must be tiny (all-zeros compresses to ~100 B regardless of size).
    expect(input.bytes.length).toBeLessThan(250_000);
    expect(input.decompressedBytesClaim).toBe(5 * 1024 * 1024);
    const tgz = await materialize(input);
    const outcome = await analyzeBounded(tgz, WALL_MS);
    // 5 MiB single entry — under 50 MiB per-entry cap and 500 MiB total cap. Extractor
    // should complete successfully.
    expect(outcome.status).toBe('ok');
  }, 20_000);

  it('stress (100 MiB decompressed): MUST reject with UnsafeArchiveError (entry-too-large)', async () => {
    const input = gzipBomb.generate(1, { mode: 'high-ratio', scale: 'stress' });
    expect(input.bytes.length).toBeLessThan(250_000);
    expect(input.decompressedBytesClaim).toBe(100 * 1024 * 1024);
    const tgz = await materialize(input);
    const outcome = await analyzeBounded(tgz, WALL_MS);
    // 100 MiB decompressed inside a single entry → per-entry cap (50 MiB) fires first.
    expect(outcome.status).toBe('rejected');
    if (outcome.status === 'rejected') {
      expect(outcome.error).toBeInstanceOf(UnsafeArchiveError);
      if (outcome.error instanceof UnsafeArchiveError) {
        // Could be 'entry-too-large' (per-entry cap) or 'total-too-large' (total cap) —
        // both are correct refusals. `entry-too-large` should fire first at 50 MiB.
        expect(['entry-too-large', 'total-too-large']).toContain(outcome.error.kind);
      }
    }
  }, 30_000);
});

// ------------------------------------------------------------------------------------------
// mode: invalid-header
// ------------------------------------------------------------------------------------------

describe('gzip-bomb: invalid-header (malformed gzip stream)', () => {
  it('baseline (bogus header bytes): MUST reject with a clean Error (no native abort)', async () => {
    const input = gzipBomb.generate(1, { mode: 'invalid-header', scale: 'baseline' });
    // Fixture is tiny (~50 B).
    expect(input.bytes.length).toBeLessThan(1_000);
    const tgz = await materialize(input);
    const outcome = await analyzeBounded(tgz, WALL_MS);
    // zlib rejects immediately with an Error — usually 'incorrect header check' or similar.
    // The analyzer wraps this so we see an Error (not an UnsafeArchiveError specifically —
    // that's for entries INSIDE a valid tar; header-level failures come from zlib).
    expect(outcome.status).toBe('rejected');
    if (outcome.status === 'rejected') {
      expect(outcome.error).toBeInstanceOf(Error);
      // Assert the error is a normal Error-shape (has name + message), not a raw abort.
      expect(typeof outcome.error.name).toBe('string');
      expect(typeof outcome.error.message).toBe('string');
    }
  }, 20_000);

  it('stress (truncated valid gzip): MUST reject with a clean Error mid-stream', async () => {
    const input = gzipBomb.generate(1, { mode: 'invalid-header', scale: 'stress' });
    expect(input.bytes.length).toBeLessThan(1_000);
    const tgz = await materialize(input);
    const outcome = await analyzeBounded(tgz, WALL_MS);
    // Truncated stream fails partway through decompression — different zlib code path.
    // The extractor must still surface a clean Error.
    expect(outcome.status).toBe('rejected');
    if (outcome.status === 'rejected') {
      expect(outcome.error).toBeInstanceOf(Error);
      expect(typeof outcome.error.name).toBe('string');
      expect(typeof outcome.error.message).toBe('string');
    }
  }, 20_000);
});
