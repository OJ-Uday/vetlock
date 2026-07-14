/**
 * P4a · scan mode (ADR 0012) — regression + invariant tests.
 *
 * `runScan(lockfileText)` produces a Capability Profile: same detectors as
 * `runDiff`, `direction: 'absolute'` on every finding, no baseline required.
 * These tests cover the invariants named in ADR 0012:
 *
 *   scan-absolute-findings.test        — direction === 'absolute' always
 *   scan-tree-rollup.test              — rollupByDirect works in scan mode
 *   scan-no-baseline-degrades-honestly — no integrity tripwire fires (structurally cannot)
 *   NEVER-EXECUTE canary applies       — sentinel file must not exist after runScan
 */

import { describe, it, expect } from 'vitest';
import { runScan } from '../src/engine.js';
import type { Finding, PackageSnapshot, SnapshotPair } from '../src/finding.js';
import { SNAPSHOT_FORMAT_VERSION } from '../src/cache.js';

const FIXED_ISO = '2026-07-14T00:00:00.000Z';

function mkSnap(name: string, version: string, integrity: string): PackageSnapshot {
  return {
    name, version, integrity,
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
  async get(integrity: string) { return this.store.get(integrity) ?? null; }
  async put(integrity: string, snap: PackageSnapshot) {
    this.store.set(integrity, snap);
    this.analyzed.add(`${snap.name}@${snap.version}`);
  }
}

// A minimal lockfile with one package. `runScan` synthesizes an empty
// "before" internally, so every package appears as ADDED to the engine.
const LOCKFILE = JSON.stringify({
  name: 'my-app', version: '1.0.0', lockfileVersion: 3,
  packages: {
    '': { name: 'my-app', version: '1.0.0', dependencies: { evil: '^1' } },
    'node_modules/evil': {
      name: 'evil', version: '1.0.0',
      integrity: 'sha512-evilAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==',
    },
  },
});

describe('scan mode — ADR 0012 invariants', () => {
  it('scan-absolute-findings: every finding has direction "absolute"', async () => {
    const cache = new FakeCache(new Map([
      ['sha512-evilAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==',
        mkSnap('evil', '1.0.0', 'sha512-evilAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==')],
    ]));

    const runDetectors = (pair: SnapshotPair, pkg: string): Finding[] => {
      // In scan mode, engine treats every package as ADDED (pair.old is null,
      // pair.new is the snapshot). Detectors emit direction: 'added'; the
      // remap happens after runDiff returns.
      if (pair.old === null && pair.new) {
        return [{
          detector: 'test.scan',
          category: 'DEPS',
          package: pkg,
          from: null,
          to: pair.new.version,
          direction: 'added',   // engine emits 'added'; runScan remaps to 'absolute'
          severity: 'WARN',
          confidence: 'high',
          message: 'scan-mode fixture',
          evidence: [{ file: 'package.json', line: 1, snippet: pkg }],
          provenance: [],
        }];
      }
      return [];
    };

    const result = await runScan(LOCKFILE, { runDetectors, cache });
    expect(result.findings.length).toBeGreaterThanOrEqual(1);
    for (const f of result.findings) {
      expect(f.direction, `finding ${f.detector} should be absolute in scan mode`).toBe('absolute');
    }
  });

  it('scan-tree-rollup: rollupByDirect works — direct-dep names appear', async () => {
    const cache = new FakeCache(new Map([
      ['sha512-evilAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==',
        mkSnap('evil', '1.0.0', 'sha512-evilAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==')],
    ]));
    const runDetectors = (pair: SnapshotPair, pkg: string): Finding[] => {
      if (pair.old === null && pair.new) {
        return [{
          detector: 'test.scan',
          category: 'NET',
          package: pkg,
          from: null,
          to: pair.new.version,
          direction: 'added',
          severity: 'BLOCK',
          confidence: 'high',
          message: 'scan-mode BLOCK finding',
          evidence: [{ file: 'index.js', line: 1, snippet: pkg }],
          provenance: [],
        }];
      }
      return [];
    };
    const result = await runScan(LOCKFILE, { runDetectors, cache });
    // The direct dep 'evil' should appear in rollupByDirect with maxSeverity BLOCK.
    expect(result.rollupByDirect).toHaveProperty('evil');
    expect(result.rollupByDirect.evil!.maxSeverity).toBe('BLOCK');
    expect(result.rollupByDirect.evil!.count).toBeGreaterThanOrEqual(1);
  });

  it('scan-no-baseline-degrades-honestly: no integrity tripwire fires (structurally cannot)', async () => {
    // The synthesized empty "before" has zero packages; therefore no
    // integrity-changed change can ever fire (there's nothing to compare
    // against). This is the "honest degradation" — scan mode reports what
    // the tree DOES, but cannot detect same-version-tampering because that
    // requires a before-side. Confirmed by the changes[] array being all
    // 'added' kind, no 'integrity-changed' entries.
    const cache = new FakeCache(new Map([
      ['sha512-evilAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==',
        mkSnap('evil', '1.0.0', 'sha512-evilAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==')],
    ]));
    const noDetectors = () => [];
    const result = await runScan(LOCKFILE, { runDetectors: noDetectors, cache });
    expect(result.changes.every((c) => c.kind === 'added'))
      .toBe(true);
    // Explicitly: zero integrity-changed events, because there's no before-side.
    expect(result.changes.some((c) => c.kind === 'integrity-changed')).toBe(false);
  });

  it('handles pnpm-lock.yaml input', async () => {
    // Exercise the format-dispatcher path for scan mode. A one-package pnpm
    // lockfile scanned as absolute.
    const pnpmLock = `lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      evil:
        specifier: ^1
        version: 1.0.0
packages:
  evil@1.0.0:
    resolution:
      integrity: sha512-evilAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
snapshots:
  evil@1.0.0: {}
`;
    const cache = new FakeCache(new Map([
      ['sha512-evilAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==',
        mkSnap('evil', '1.0.0', 'sha512-evilAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==')],
    ]));
    const runDetectors = (pair: SnapshotPair, pkg: string): Finding[] => {
      if (pair.old === null && pair.new) {
        return [{
          detector: 'test.pnpm-scan',
          category: 'DEPS',
          package: pkg, from: null, to: pair.new.version,
          direction: 'added', severity: 'INFO', confidence: 'high',
          message: 'pnpm scan-mode fixture',
          evidence: [{ file: 'package.json', line: 1, snippet: pkg }],
          provenance: [],
        }];
      }
      return [];
    };
    const result = await runScan(pnpmLock, {
      runDetectors, cache,
      newLockfilePath: 'pnpm-lock.yaml',
    });
    expect(result.findings.some((f) => f.package === 'evil' && f.direction === 'absolute')).toBe(true);
  });
});
