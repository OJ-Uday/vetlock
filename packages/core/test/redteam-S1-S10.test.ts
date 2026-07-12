/**
 * Regression tests for red-team confirmed exploits S1 and S10.
 * @security-critical
 *
 * S1 — Cache poisoning via attacker-supplied integrity as cache-lookup key.
 *      Fix: HMAC-authenticate every cache entry against a per-install key.
 * S10 — Integrity tripwire suppressed when either old or new integrity was blank.
 *      Fix: fire on any transition when newIntegrity is present and differs.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { promises as fs } from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as crypto from 'node:crypto';
import { makeCache, SNAPSHOT_FORMAT_VERSION } from '../src/cache.js';
import { computeChangeset } from '../src/changeset.js';
import { parseLockfile } from '../src/lockfile.js';
import type { PackageSnapshot } from '../src/finding.js';

const FIXED_ISO = '2026-07-12T00:00:00.000Z';

function fakeSnap(over: Partial<PackageSnapshot> = {}): PackageSnapshot {
  return {
    name: over.name ?? 'chalk',
    version: over.version ?? '5.3.1',
    integrity: over.integrity ?? 'sha512-fake',
    manifest: over.manifest ?? { name: over.name ?? 'chalk', version: over.version ?? '5.3.1' },
    files: over.files ?? [],
    nativeArtifacts: over.nativeArtifacts ?? [],
    formatVersion: SNAPSHOT_FORMAT_VERSION,
    builtAt: FIXED_ISO,
  };
}

describe('REDTEAM S1: cache poisoning defense (HMAC-authenticated entries)', () => {
  let tmpDir: string;

  beforeEach(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'vetlock-cache-test-'));
  });
  afterEach(async () => {
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  it('legitimate put/get roundtrip works (positive control)', async () => {
    const cache = makeCache(`${tmpDir}/analysis`);
    const snap = fakeSnap();
    await cache.put('sha512-fake', snap);
    const got = await cache.get('sha512-fake');
    expect(got).not.toBeNull();
    expect(got!.name).toBe('chalk');
  });

  it('rejects a foreign-planted snapshot that lacks the HMAC envelope', async () => {
    const cache = makeCache(`${tmpDir}/analysis`);
    const dir = `${tmpDir}/analysis`;
    await fs.mkdir(dir, { recursive: true });
    const safeKey = 'sha512-attacker'.replace(/[^A-Za-z0-9._-]/g, '_');
    const attackerSnap = fakeSnap({ integrity: 'sha512-attacker' });
    await fs.writeFile(`${dir}/${safeKey}.json`, JSON.stringify(attackerSnap));
    const got = await cache.get('sha512-attacker');
    expect(got).toBeNull();
  });

  it('rejects a foreign-planted entry with a fabricated (wrong-key) HMAC', async () => {
    const cache = makeCache(`${tmpDir}/analysis`);
    await cache.put('sha512-legit', fakeSnap({ integrity: 'sha512-legit' }));

    const dir = `${tmpDir}/analysis`;
    const safeKey = 'sha512-attacker'.replace(/[^A-Za-z0-9._-]/g, '_');
    const attackerSnap = fakeSnap({ integrity: 'sha512-attacker' });
    const attackerKey = crypto.randomBytes(32);
    const h = crypto.createHmac('sha256', attackerKey);
    h.update(`v2\n${SNAPSHOT_FORMAT_VERSION}\nsha512-attacker\n`);
    h.update(JSON.stringify(attackerSnap, (_, v) => {
      if (v && typeof v === 'object' && !Array.isArray(v)) {
        return Object.fromEntries(Object.keys(v).sort().map((k) => [k, (v as Record<string, unknown>)[k]]));
      }
      return v;
    }));
    const forged = h.digest('hex');

    const envelope = {
      __vetlock_cache_v: 2,
      integrity: 'sha512-attacker',
      formatVersion: SNAPSHOT_FORMAT_VERSION,
      snapshot: attackerSnap,
      hmac: forged,
    };
    await fs.writeFile(`${dir}/${safeKey}.json`, JSON.stringify(envelope));

    const got = await cache.get('sha512-attacker');
    expect(got).toBeNull();
  });

  it('rejects a tampered snapshot even if envelope has our correct HMAC field length', async () => {
    const cache = makeCache(`${tmpDir}/analysis`);
    await cache.put('sha512-target', fakeSnap({ integrity: 'sha512-target' }));

    const dir = `${tmpDir}/analysis`;
    const safeKey = 'sha512-target'.replace(/[^A-Za-z0-9._-]/g, '_');
    const raw = await fs.readFile(`${dir}/${safeKey}.json`, 'utf8');
    const envelope = JSON.parse(raw);
    envelope.snapshot.name = 'attacker-controlled';
    await fs.writeFile(`${dir}/${safeKey}.json`, JSON.stringify(envelope));

    const got = await cache.get('sha512-target');
    expect(got).toBeNull();
  });

  it('HMAC key file has restrictive permissions (owner-only read/write)', async () => {
    const cache = makeCache(`${tmpDir}/analysis`);
    await cache.put('sha512-x', fakeSnap({ integrity: 'sha512-x' }));
    const keyFile = path.join(tmpDir, 'hmac.key');
    const stat = await fs.stat(keyFile);
    if (process.platform !== 'win32') {
      expect(stat.mode & 0o077).toBe(0);
    }
  });
});

describe('REDTEAM S10: integrity tripwire fires when old integrity is blank', () => {
  function mkLock(entries: Record<string, { version: string; integrity?: string }>) {
    const packages: Record<string, unknown> = {
      '': { name: 'my-app', version: '1.0.0', dependencies: {} },
    };
    for (const [key, val] of Object.entries(entries)) {
      const idx = key.lastIndexOf('node_modules/');
      const name = idx === -1 ? key : key.slice(idx + 'node_modules/'.length);
      packages[key] = {
        name,
        version: val.version,
        integrity: val.integrity ?? undefined,
      };
    }
    return { name: 'my-app', version: '1.0.0', lockfileVersion: 3, packages };
  }

  it('fires integrity-changed when oldIntegrity was blank and newIntegrity is populated (S10 fixture)', () => {
    const oldG = parseLockfile(mkLock({
      'node_modules/chalk': { version: '5.3.0' /* integrity DELIBERATELY MISSING */ },
    }));
    const newG = parseLockfile(mkLock({
      'node_modules/chalk': { version: '5.3.0', integrity: 'sha512-attackerControlled' },
    }));
    const changes = computeChangeset(oldG, newG);
    const intg = changes.find((c) => c.kind === 'integrity-changed');
    expect(intg, 'integrity-changed must fire when oldIntegrity was blank').toBeDefined();
    expect(intg!.name).toBe('chalk');
    expect(intg!.oldIntegrity).toBe('');
    expect(intg!.newIntegrity).toBe('sha512-attackerControlled');
  });

  it('still fires when both integrities present but differ (pre-existing behavior preserved)', () => {
    const oldG = parseLockfile(mkLock({
      'node_modules/chalk': { version: '5.3.0', integrity: 'sha512-original' },
    }));
    const newG = parseLockfile(mkLock({
      'node_modules/chalk': { version: '5.3.0', integrity: 'sha512-tampered' },
    }));
    const changes = computeChangeset(oldG, newG);
    const intg = changes.find((c) => c.kind === 'integrity-changed');
    expect(intg).toBeDefined();
    expect(intg!.oldIntegrity).toBe('sha512-original');
  });

  it('does NOT fire when integrities match exactly (no false positives)', () => {
    const oldG = parseLockfile(mkLock({
      'node_modules/chalk': { version: '5.3.0', integrity: 'sha512-x' },
    }));
    const newG = parseLockfile(mkLock({
      'node_modules/chalk': { version: '5.3.0', integrity: 'sha512-x' },
    }));
    const changes = computeChangeset(oldG, newG);
    expect(changes.find((c) => c.kind === 'integrity-changed')).toBeUndefined();
  });

  it('does NOT fire when new integrity is blank (nothing to compare against)', () => {
    const oldG = parseLockfile(mkLock({
      'node_modules/chalk': { version: '5.3.0', integrity: 'sha512-x' },
    }));
    const newG = parseLockfile(mkLock({
      'node_modules/chalk': { version: '5.3.0' /* new integrity blank */ },
    }));
    const changes = computeChangeset(oldG, newG);
    expect(changes.find((c) => c.kind === 'integrity-changed')).toBeUndefined();
  });
});
