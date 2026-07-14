/**
 * P1-A · Lockfile-pnpm end-to-end diff test.
 *
 * The packet's F1 fix says: pnpm-lock.yaml and yarn.lock inputs must NOT crash
 * runDiff via JSON.parse. This test exercises that end-to-end — parse a real
 * pnpm-lock.yaml pair through the runDiff pipeline with a fake cache, and
 * assert the engine surfaces the expected version-change finding.
 *
 * If this test crashes with a SyntaxError from JSON.parse, F1 has regressed.
 * If it fails to detect the version change, the pnpm parser is not returning
 * a graph shape runDiff can consume.
 */

import { describe, it, expect } from 'vitest';
import type { Finding, PackageSnapshot, SnapshotPair } from '../src/finding.js';
import { runDiff } from '../src/engine.js';
import { SNAPSHOT_FORMAT_VERSION } from '../src/cache.js';

const FIXED_ISO = '2026-07-13T00:00:00.000Z';

function mkSnap(name: string, version: string, integrity: string): PackageSnapshot {
  return {
    name,
    version,
    integrity,
    manifest: { name, version },
    files: [],
    formatVersion: SNAPSHOT_FORMAT_VERSION,
    builtAt: FIXED_ISO,
  };
}

class FakeCache {
  public analyzed = new Set<string>();
  constructor(public store: Map<string, PackageSnapshot>) {}
  readonly dir = '/tmp/fake-cache';
  async get(integrity: string) {
    return this.store.get(integrity) ?? null;
  }
  async put(integrity: string, snap: PackageSnapshot) {
    this.store.set(integrity, snap);
    this.analyzed.add(`${snap.name}@${snap.version}`);
  }
}

// Real-shape pnpm-lock.yaml v9 (the shape pnpm 9.x emits).
const PNPM_LOCK_BEFORE = `lockfileVersion: '9.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

importers:
  .:
    dependencies:
      lodash:
        specifier: ^4.17.20
        version: 4.17.20

packages:
  lodash@4.17.20:
    resolution:
      integrity: sha512-PlhdFcillOINfeV7Ni6oF1TAEayyZBoZ8bcshTHqOYJYlrqzRK5hagpagky5o4HfCzzd1TRkXPMFq6cKk9rGmA==
    engines:
      node: '>=4.0.0'

snapshots:
  lodash@4.17.20: {}
`;

const PNPM_LOCK_AFTER = `lockfileVersion: '9.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

importers:
  .:
    dependencies:
      lodash:
        specifier: ^4.17.20
        version: 4.17.21

packages:
  lodash@4.17.21:
    resolution:
      integrity: sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg==
    engines:
      node: '>=4.0.0'

snapshots:
  lodash@4.17.21: {}
`;

describe('pnpm-lock.yaml → runDiff end-to-end (P1-A · F1 regression guard)', () => {
  it('parses pnpm YAML without a JSON.parse crash and surfaces the version-change', async () => {
    // Pre-populate the cache with both integrity hashes so the engine doesn't
    // try to fetch tarballs from the network — this is a unit test of the
    // parse+diff path, not the fetch path.
    const oldIntegrity =
      'sha512-PlhdFcillOINfeV7Ni6oF1TAEayyZBoZ8bcshTHqOYJYlrqzRK5hagpagky5o4HfCzzd1TRkXPMFq6cKk9rGmA==';
    const newIntegrity =
      'sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg==';
    const cache = new FakeCache(new Map([
      [oldIntegrity, mkSnap('lodash', '4.17.20', oldIntegrity)],
      [newIntegrity, mkSnap('lodash', '4.17.21', newIntegrity)],
    ]));

    const runDetectors = (pair: SnapshotPair, pkg: string): Finding[] => {
      if (pair.old && pair.new && pair.old.version !== pair.new.version) {
        return [
          {
            detector: 'test.version-changed',
            category: 'META',
            package: pkg,
            from: pair.old.version,
            to: pair.new.version,
            direction: 'changed',
            severity: 'INFO',
            confidence: 'high',
            message: `${pair.old.version} → ${pair.new.version}`,
            evidence: [{ file: 'package.json', line: 1, snippet: pkg }],
            provenance: [],
          },
        ];
      }
      return [];
    };

    const result = await runDiff(PNPM_LOCK_BEFORE, PNPM_LOCK_AFTER, {
      runDetectors,
      cache,
      oldLockfilePath: 'pnpm-lock.yaml',
      newLockfilePath: 'pnpm-lock.yaml',
    });

    // The engine must have found the version change without crashing.
    expect(result.findings.some(f => f.package === 'lodash' && f.detector === 'test.version-changed')).toBe(true);
    const change = result.findings.find(f => f.detector === 'test.version-changed')!;
    expect(change.from).toBe('4.17.20');
    expect(change.to).toBe('4.17.21');
  });

  it('detects the pnpm-lock format from filename hint alone (no content sniffing needed)', async () => {
    // Same YAML content but the caller MUST pass the filename hint for us to
    // dispatch to the pnpm parser. Verifying the F1 dispatcher contract.
    const cache = new FakeCache(new Map([
      ['sha512-PlhdFcillOINfeV7Ni6oF1TAEayyZBoZ8bcshTHqOYJYlrqzRK5hagpagky5o4HfCzzd1TRkXPMFq6cKk9rGmA==', mkSnap('lodash', '4.17.20', 'sha512-PlhdFcillOINfeV7Ni6oF1TAEayyZBoZ8bcshTHqOYJYlrqzRK5hagpagky5o4HfCzzd1TRkXPMFq6cKk9rGmA==')],
      ['sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg==', mkSnap('lodash', '4.17.21', 'sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg==')],
    ]));
    const noDetectors = () => [];
    // No throw — dispatcher must handle YAML without falling back to JSON.parse.
    await expect(runDiff(PNPM_LOCK_BEFORE, PNPM_LOCK_AFTER, {
      runDetectors: noDetectors,
      cache,
      oldLockfilePath: 'pnpm-lock.yaml',
      newLockfilePath: 'pnpm-lock.yaml',
    })).resolves.toBeDefined();
  });

  it('parses pnpm-lock v6 leading-slash key format alongside v9', async () => {
    // pnpm 6-8 emit '/lodash/4.17.20' as the package key; v9 dropped the leading slash.
    // Both must work through runDiff.
    const pnpmV6Before = `lockfileVersion: '6.0'

importers:
  .:
    dependencies:
      lodash:
        specifier: ^4.17.20
        version: 4.17.20

packages:

  /lodash@4.17.20:
    resolution:
      integrity: sha512-PlhdFcillOINfeV7Ni6oF1TAEayyZBoZ8bcshTHqOYJYlrqzRK5hagpagky5o4HfCzzd1TRkXPMFq6cKk9rGmA==
    engines:
      node: '>=4.0.0'
`;
    const pnpmV6After = pnpmV6Before
      .replaceAll('4.17.20', '4.17.21')
      .replace(
        'sha512-PlhdFcillOINfeV7Ni6oF1TAEayyZBoZ8bcshTHqOYJYlrqzRK5hagpagky5o4HfCzzd1TRkXPMFq6cKk9rGmA==',
        'sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg==',
      );
    const cache = new FakeCache(new Map([
      ['sha512-PlhdFcillOINfeV7Ni6oF1TAEayyZBoZ8bcshTHqOYJYlrqzRK5hagpagky5o4HfCzzd1TRkXPMFq6cKk9rGmA==', mkSnap('lodash', '4.17.20', 'sha512-PlhdFcillOINfeV7Ni6oF1TAEayyZBoZ8bcshTHqOYJYlrqzRK5hagpagky5o4HfCzzd1TRkXPMFq6cKk9rGmA==')],
      ['sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg==', mkSnap('lodash', '4.17.21', 'sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg==')],
    ]));

    const runDetectors = (pair: SnapshotPair, pkg: string): Finding[] => {
      if (pair.old && pair.new && pair.old.version !== pair.new.version) {
        return [{
          detector: 'test.version-changed',
          category: 'META',
          package: pkg,
          from: pair.old.version,
          to: pair.new.version,
          direction: 'changed',
          severity: 'INFO',
          confidence: 'high',
          message: `${pair.old.version} → ${pair.new.version}`,
          evidence: [{ file: 'package.json', line: 1, snippet: pkg }],
          provenance: [],
        }];
      }
      return [];
    };

    const result = await runDiff(pnpmV6Before, pnpmV6After, {
      runDetectors,
      cache,
      oldLockfilePath: 'pnpm-lock.yaml',
      newLockfilePath: 'pnpm-lock.yaml',
    });
    expect(result.findings.some(f => f.detector === 'test.version-changed')).toBe(true);
  });

  it('adds a new transitive pnpm dep and treats it as ADDED (event-stream-style shape)', async () => {
    // event-stream's flatmap-stream case, but in pnpm shape: a same-version-but-
    // now-with-new-transitive lockfile. The engine must fully-scan the new node.
    const before = `lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      es:
        specifier: ^1.0.0
        version: 1.0.0
packages:
  es@1.0.0:
    resolution: {integrity: sha512-esOldXX=}
snapshots:
  es@1.0.0: {}
`;
    const after = `lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      es:
        specifier: ^1.0.0
        version: 1.0.0
packages:
  es@1.0.0:
    resolution: {integrity: sha512-esOldXX=}
    dependencies:
      evil: 0.1.1
  evil@0.1.1:
    resolution: {integrity: sha512-evilNewXX=}
snapshots:
  es@1.0.0:
    dependencies:
      evil: 0.1.1
  evil@0.1.1: {}
`;
    const cache = new FakeCache(new Map([
      ['sha512-esOldXX=', mkSnap('es', '1.0.0', 'sha512-esOldXX=')],
      ['sha512-evilNewXX=', mkSnap('evil', '0.1.1', 'sha512-evilNewXX=')],
    ]));
    const seen: Array<{ pkg: string; direction: 'added' | 'changed' | 'removed' | 'same' }> = [];
    const runDetectors = (pair: SnapshotPair, pkg: string): Finding[] => {
      const dir = pair.old === null && pair.new
        ? 'added' as const
        : pair.new === null && pair.old
        ? 'removed' as const
        : (pair.old && pair.new && pair.old.version !== pair.new.version)
          ? 'changed' as const
          : 'same' as const;
      seen.push({ pkg, direction: dir });
      if (dir === 'added') {
        return [{
          detector: 'test.added',
          category: 'DEPS',
          package: pkg,
          from: null,
          to: pair.new!.version,
          direction: 'added',
          severity: 'WARN',
          confidence: 'high',
          message: 'new transitive',
          evidence: [{ file: 'package.json', line: 1, snippet: pkg }],
          provenance: [],
        }];
      }
      return [];
    };
    const result = await runDiff(before, after, {
      runDetectors,
      cache,
      oldLockfilePath: 'pnpm-lock.yaml',
      newLockfilePath: 'pnpm-lock.yaml',
    });
    // 'evil' was seen as ADDED, and it surfaces in the findings.
    expect(seen.some(s => s.pkg === 'evil' && s.direction === 'added')).toBe(true);
    expect(result.findings.some(f => f.package === 'evil' && f.direction === 'added')).toBe(true);
  });
});
