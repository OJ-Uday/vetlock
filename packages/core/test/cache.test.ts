import { describe, it, expect, afterAll } from 'vitest';
import { promises as fs } from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { makeCache, SNAPSHOT_FORMAT_VERSION } from '../src/cache.js';
import type { PackageSnapshot } from '../src/finding.js';

const dir = path.join(os.tmpdir(), 'vetlock-cache-tests', String(Date.now()));
afterAll(async () => {
  await fs.rm(path.dirname(dir), { recursive: true, force: true });
});

function fakeSnap(name: string, version: string): PackageSnapshot {
  return {
    name,
    version,
    integrity: 'sha512-fake',
    manifest: { name, version },
    files: [],
    formatVersion: SNAPSHOT_FORMAT_VERSION,
    builtAt: '2026-07-12T00:00:00.000Z',
  };
}

describe('SnapshotCache', () => {
  it('roundtrips a snapshot by integrity key', async () => {
    const cache = makeCache(dir);
    const key = 'sha512-abcd/efgh=';
    expect(await cache.get(key)).toBeNull();
    await cache.put(key, fakeSnap('foo', '1.0.0'));
    const got = await cache.get(key);
    expect(got?.name).toBe('foo');
    expect(got?.version).toBe('1.0.0');
  });

  it('returns null on format-version mismatch', async () => {
    // With the S1 HMAC envelope, put() always writes the current
    // SNAPSHOT_FORMAT_VERSION. To simulate a stale format, we write a legit
    // entry then rewrite the envelope's formatVersion on disk.
    const cache = makeCache(dir);
    const key = 'sha512-old-format';
    await cache.put(key, fakeSnap('foo', '1.0.0'));
    const safeKey = key.replace(/[^A-Za-z0-9._-]/g, '_');
    const entryPath = `${dir}/${safeKey}.json`;
    const envelope = JSON.parse(await fs.readFile(entryPath, 'utf8'));
    envelope.formatVersion = 0;
    await fs.writeFile(entryPath, JSON.stringify(envelope));
    // HMAC no longer matches (formatVersion is part of the HMAC input) so this
    // should return null via the HMAC-mismatch path, which is equivalent to
    // the format-version-mismatch path from the caller's perspective.
    expect(await cache.get(key)).toBeNull();
  });

  it('is content-addressed — two keys produce two files', async () => {
    const cache = makeCache(dir);
    await cache.put('sha512-A', fakeSnap('a', '1.0.0'));
    await cache.put('sha512-B', fakeSnap('b', '1.0.0'));
    const files = await fs.readdir(dir);
    expect(files.filter((f) => f.endsWith('.json')).length).toBeGreaterThanOrEqual(2);
  });
});
