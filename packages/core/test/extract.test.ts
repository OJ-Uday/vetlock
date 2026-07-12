import { describe, it, expect, afterAll } from 'vitest';
import { promises as fs } from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { safeExtract, UnsafeArchiveError, DEFAULT_LIMITS } from '../src/extract.js';
import { writeTempTgz } from './tgz-builder.js';

const tmpBase = path.join(os.tmpdir(), 'vetlock-extract-tests');
afterAll(async () => {
  await fs.rm(tmpBase, { recursive: true, force: true });
});

describe('safeExtract — zip-slip / traversal', () => {
  it('rejects an absolute-path entry', async () => {
    const p = await writeTempTgz([
      { name: 'package/normal.js', content: Buffer.from('x=1') },
      { name: '/etc/passwd', content: Buffer.from('root:x:0:0') },
    ]);
    await expect(safeExtract(p, { baseTmpDir: tmpBase })).rejects.toBeInstanceOf(
      UnsafeArchiveError,
    );
  });

  it("rejects a '..' traversal entry", async () => {
    const p = await writeTempTgz([
      { name: 'package/../../../evil.js', content: Buffer.from('evil') },
    ]);
    await expect(safeExtract(p, { baseTmpDir: tmpBase })).rejects.toBeInstanceOf(
      UnsafeArchiveError,
    );
  });
});

describe('safeExtract — link entries', () => {
  it('rejects a symlink entry', async () => {
    const p = await writeTempTgz([
      { name: 'package/link', type: 'symlink', linkName: '/etc/passwd' },
    ]);
    await expect(safeExtract(p, { baseTmpDir: tmpBase })).rejects.toBeInstanceOf(
      UnsafeArchiveError,
    );
  });

  it('rejects a hardlink entry', async () => {
    const p = await writeTempTgz([
      { name: 'package/link', type: 'hardlink', linkName: 'package/normal.js' },
    ]);
    await expect(safeExtract(p, { baseTmpDir: tmpBase })).rejects.toBeInstanceOf(
      UnsafeArchiveError,
    );
  });
});

describe('safeExtract — tarbomb caps', () => {
  it('rejects an entry that exceeds per-entry byte cap', async () => {
    const oversized = Buffer.alloc(10 * 1024, 'A'); // 10 KiB
    const p = await writeTempTgz([
      { name: 'package/big.bin', content: oversized },
    ]);
    await expect(
      safeExtract(p, {
        baseTmpDir: tmpBase,
        limits: { ...DEFAULT_LIMITS, maxEntryBytes: 1024 },
      }),
    ).rejects.toBeInstanceOf(UnsafeArchiveError);
  });

  it('rejects when total exceeds cap across many files', async () => {
    const chunk = Buffer.alloc(1000, 'B');
    const entries = Array.from({ length: 20 }, (_, i) => ({
      name: `package/f${i}.bin`,
      content: chunk,
    }));
    await expect(
      safeExtract(await writeTempTgz(entries), {
        baseTmpDir: tmpBase,
        limits: { ...DEFAULT_LIMITS, maxTotalBytes: 5000 },
      }),
    ).rejects.toBeInstanceOf(UnsafeArchiveError);
  });

  it('rejects when file count exceeds cap', async () => {
    const entries = Array.from({ length: 30 }, (_, i) => ({
      name: `package/f${i}.js`,
      content: Buffer.from('x'),
    }));
    await expect(
      safeExtract(await writeTempTgz(entries), {
        baseTmpDir: tmpBase,
        limits: { ...DEFAULT_LIMITS, maxEntries: 10 },
      }),
    ).rejects.toBeInstanceOf(UnsafeArchiveError);
  });
});

describe('safeExtract — cleanup and success', () => {
  it('extracts a valid tarball and cleans up on demand', async () => {
    const p = await writeTempTgz([
      { name: 'package/a.js', content: Buffer.from('const a = 1;') },
      { name: 'package/b.js', content: Buffer.from('const b = 2;') },
    ]);
    const result = await safeExtract(p, { baseTmpDir: tmpBase });
    // Files exist under destDir
    const a = await fs.readFile(path.join(result.destDir, 'a.js'), 'utf8');
    expect(a).toBe('const a = 1;');
    expect(result.entries.length).toBe(2);
    expect(result.entries[0]!.sha256).toMatch(/^[0-9a-f]{64}$/);
    // Cleanup removes destDir
    await result.cleanup();
    await expect(fs.access(result.destDir)).rejects.toThrow();
  });

  it('cleans up destDir on throw', async () => {
    const p = await writeTempTgz([
      { name: '/etc/passwd', content: Buffer.from('bad') },
    ]);
    let didThrow = false;
    let destDirCaptured: string | null = null;
    try {
      await safeExtract(p, { baseTmpDir: tmpBase });
    } catch (err) {
      didThrow = true;
      // We can't get destDir from a thrown error easily — verify by listing
      // baseTmpDir and confirming it's empty of stale runs.
      if (err instanceof UnsafeArchiveError) {
        // ok
      }
    }
    expect(didThrow).toBe(true);
    // No stray dirs left behind (best effort).
    const entries = await fs.readdir(tmpBase).catch(() => []);
    for (const e of entries) {
      const st = await fs.stat(path.join(tmpBase, e));
      // A leftover from THIS test would be < 5 s old.
      if (Date.now() - st.mtimeMs < 5000) {
        // We failed to clean up.
        destDirCaptured = path.join(tmpBase, e);
      }
    }
    expect(destDirCaptured).toBeNull();
  });
});
