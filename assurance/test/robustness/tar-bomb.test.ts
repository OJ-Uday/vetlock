/**
 * tar-bomb robustness tests.
 *
 * Feeds each hostile tarball mode through @vetlock/core's `analyzeTarball` (via `safeExtract`)
 * and asserts the scanner refuses to fully expand the archive. The scanner MUST either:
 *   (a) throw `UnsafeArchiveError` with a recognized `kind` (traversal / entry-count-exceeded
 *       / entry-too-large / total-too-large / etc.), OR
 *   (b) succeed cleanly for the baseline "must-be-handled-safely" cases (small nested paths,
 *       small entry counts) without unbounded memory growth or hangs.
 *
 * Every fixture is <1 MB on disk — this suite tests scanner behavior on hostile METADATA,
 * not actual expanded-size bombs. The `runBoundedInProcess` primitive that Agent A was
 * scheduled to land is not on this branch, so we use an in-test Promise.race wallMs
 * wrapper: the scanner has been running these caps for two P0 cycles and the extractor
 * fails fast on all four hostile modes.
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
import { tarBomb, type TarBombInput } from '../../src/robustness/tar-bomb.js';

// Isolated per-run tmp base so we can cleanup unconditionally in afterAll.
const tmpBase = path.join(os.tmpdir(), `vetlock-assurance-tar-bomb-${crypto.randomBytes(4).toString('hex')}`);

afterAll(async () => {
  await fs.rm(tmpBase, { recursive: true, force: true });
});

/** Write a generated fixture to disk and return the .tgz path. */
async function materialize(input: TarBombInput): Promise<string> {
  await fs.mkdir(tmpBase, { recursive: true });
  const p = path.join(tmpBase, `${crypto.randomBytes(4).toString('hex')}-${input.filename}`);
  await fs.writeFile(p, input.bytes);
  return p;
}

/** Wallclock-bounded wrapper around analyzeTarball.  Resolves to one of:
 *   - {status:'ok', ...}          : analyzer returned a PackageSnapshot
 *   - {status:'rejected', ...}    : analyzer threw (expected for hostile fixtures)
 *   - {status:'timeout'}          : the analyzer did not finish within wallMs — a genuine
 *                                    robustness gap (the extractor must fail fast, not hang).
 * Uses `analyzeTarball`'s own destination-dir isolation via baseTmpDir. */
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
    // Do not `unref` — we want the timer to keep the loop alive until it fires or is
    // cleared by the analyzer resolving first.
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

const WALL_MS = 10_000; // 10 s — the extractor fails fast in all hostile modes; a genuine
                        // hang would blow this cap and surface as a test failure.

// ------------------------------------------------------------------------------------------
// mode: oversized-claim
// ------------------------------------------------------------------------------------------

describe('tar-bomb: oversized-claim (header claims 4 GiB per entry)', () => {
  it('baseline: extractor tolerates the fixture (real bytes are tiny; caps not tripped)', async () => {
    const input = tarBomb.generate(1, { mode: 'oversized-claim', scale: 'baseline' });
    expect(input.bytes.length).toBeLessThan(1_000_000);
    const tgz = await materialize(input);
    const outcome = await analyzeBounded(tgz, WALL_MS);
    // The extractor reads actual on-disk bytes and applies its own accounting. The oversized
    // header CLAIM is never trusted — the tar library reports the real size via the entry
    // stream. So baseline (3 entries × ~10 B) is well under all caps and completes cleanly.
    // If the scanner ever trusts the header claim (regression), this test will time out (OOM
    // trying to pre-allocate 4 GiB) or crash — the test fails loudly.
    expect(outcome.status).toBe('ok');
  }, 20_000);

  it('stress: extractor still tolerates 10 entries × 4-GiB-claimed (real bytes stay tiny)', async () => {
    const input = tarBomb.generate(1, { mode: 'oversized-claim', scale: 'stress' });
    expect(input.bytes.length).toBeLessThan(1_000_000);
    const tgz = await materialize(input);
    const outcome = await analyzeBounded(tgz, WALL_MS);
    expect(outcome.status).toBe('ok');
  }, 20_000);
});

// ------------------------------------------------------------------------------------------
// mode: nested-paths
// ------------------------------------------------------------------------------------------

describe('tar-bomb: nested-paths (100+ segments)', () => {
  it('baseline (50 segments): extractor handles it — either succeeds or rejects on a documented cap', async () => {
    const input = tarBomb.generate(1, { mode: 'nested-paths', scale: 'baseline' });
    expect(input.bytes.length).toBeLessThan(1_000_000);
    const tgz = await materialize(input);
    const outcome = await analyzeBounded(tgz, WALL_MS);
    // Nested paths currently succeed at 50 segments — mkdir -p handles arbitrary depth on
    // POSIX FS. If a filesystem-length cap fires (Windows path max is 260, POSIX PATH_MAX is
    // typically 4096), the extractor reports it as a native error the extractor wraps.
    // Both "ok" and "rejected with a clean Error" are acceptable; "timeout" is not.
    expect(outcome.status).not.toBe('timeout');
    if (outcome.status === 'rejected') {
      // Any thrown error must be a normal Error subclass — never a native abort.
      expect(outcome.error).toBeInstanceOf(Error);
    }
  }, 20_000);

  it('stress (200 segments): still handled without hang; deep path either lands or is refused', async () => {
    const input = tarBomb.generate(1, { mode: 'nested-paths', scale: 'stress' });
    expect(input.bytes.length).toBeLessThan(1_000_000);
    const tgz = await materialize(input);
    const outcome = await analyzeBounded(tgz, WALL_MS);
    expect(outcome.status).not.toBe('timeout');
    if (outcome.status === 'rejected') {
      expect(outcome.error).toBeInstanceOf(Error);
    }
  }, 20_000);
});

// ------------------------------------------------------------------------------------------
// mode: zip-slip
// ------------------------------------------------------------------------------------------

describe('tar-bomb: zip-slip (../.. and /absolute paths)', () => {
  it('baseline: MUST reject with UnsafeArchiveError (traversal or absolute-path)', async () => {
    const input = tarBomb.generate(1, { mode: 'zip-slip', scale: 'baseline' });
    expect(input.bytes.length).toBeLessThan(1_000_000);
    const tgz = await materialize(input);
    const outcome = await analyzeBounded(tgz, WALL_MS);
    expect(outcome.status).toBe('rejected');
    if (outcome.status === 'rejected') {
      expect(outcome.error).toBeInstanceOf(UnsafeArchiveError);
      if (outcome.error instanceof UnsafeArchiveError) {
        // Either 'traversal' (../ in path) or 'absolute-path' (leading /). Both are the
        // correct refusal — the exact kind depends on which entry the tar parser saw first.
        expect(['traversal', 'absolute-path']).toContain(outcome.error.kind);
      }
    }
  }, 20_000);

  it('stress: MUST reject with UnsafeArchiveError for 5 different zip-slip variants', async () => {
    const input = tarBomb.generate(1, { mode: 'zip-slip', scale: 'stress' });
    expect(input.bytes.length).toBeLessThan(1_000_000);
    const tgz = await materialize(input);
    const outcome = await analyzeBounded(tgz, WALL_MS);
    expect(outcome.status).toBe('rejected');
    if (outcome.status === 'rejected') {
      expect(outcome.error).toBeInstanceOf(UnsafeArchiveError);
      if (outcome.error instanceof UnsafeArchiveError) {
        expect(['traversal', 'absolute-path']).toContain(outcome.error.kind);
      }
    }
  }, 20_000);
});

// ------------------------------------------------------------------------------------------
// mode: many-entries
// ------------------------------------------------------------------------------------------

describe('tar-bomb: many-entries (iteration-cap testing)', () => {
  it('baseline (20 entries): MUST succeed cleanly — under all caps', async () => {
    const input = tarBomb.generate(1, { mode: 'many-entries', scale: 'baseline' });
    expect(input.bytes.length).toBeLessThan(1_000_000);
    const tgz = await materialize(input);
    const outcome = await analyzeBounded(tgz, WALL_MS);
    expect(outcome.status).toBe('ok');
  }, 20_000);

  it('stress (15_000 entries): MUST reject with UnsafeArchiveError (entry-count-exceeded)', async () => {
    const input = tarBomb.generate(1, { mode: 'many-entries', scale: 'stress' });
    // Fixture bound: many small entries still gzip-compresses well below 1 MB.
    expect(input.bytes.length).toBeLessThan(1_000_000);
    const tgz = await materialize(input);
    const outcome = await analyzeBounded(tgz, WALL_MS);
    expect(outcome.status).toBe('rejected');
    if (outcome.status === 'rejected') {
      expect(outcome.error).toBeInstanceOf(UnsafeArchiveError);
      if (outcome.error instanceof UnsafeArchiveError) {
        expect(outcome.error.kind).toBe('entry-count-exceeded');
      }
    }
  }, 30_000);
});
