import { describe, it, expect } from 'vitest';
import type { Finding, PackageSnapshot, SnapshotPair } from '../src/finding.js';
import { runDiff } from '../src/engine.js';
import { SNAPSHOT_FORMAT_VERSION } from '../src/cache.js';

// Deterministic timestamp for snapshots so JSON diffs are stable.
const FIXED_ISO = '2026-07-12T00:00:00.000Z';

function mkLock(root: { name: string; version: string; deps?: Record<string, string> }, entries: Record<string, { version: string; integrity?: string; deps?: Record<string, string> }>) {
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
      dependencies: val.deps ?? {},
    };
  }
  return JSON.stringify({
    name: root.name,
    version: root.version,
    lockfileVersion: 3,
    packages,
  });
}

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

/**
 * A fake in-memory cache that returns pre-loaded snapshots. Also acts as our
 * escape hatch: we return snapshots that would otherwise require fetching a
 * tarball, and mark the packages so we can assert which ones were "analyzed".
 */
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

describe('engine — closure completeness (§4 invariant)', () => {
  it(
    'analyzes every changed node in a 5-level deep tree when only the leaf changed',
    async () => {
      // root → a → b → c → d @1.0.0    (OLD)
      // root → a → b → c → d @1.0.1    (NEW) — only d changed
      const oldLock = mkLock(
        { name: 'root', version: '1.0.0', deps: { a: '^1' } },
        {
          'node_modules/a': { version: '1.0.0', integrity: 'sha512-a1=', deps: { b: '^1' } },
          'node_modules/b': { version: '1.0.0', integrity: 'sha512-b1=', deps: { c: '^1' } },
          'node_modules/c': { version: '1.0.0', integrity: 'sha512-c1=', deps: { d: '^1' } },
          'node_modules/d': { version: '1.0.0', integrity: 'sha512-d1=' },
        },
      );
      const newLock = mkLock(
        { name: 'root', version: '1.0.0', deps: { a: '^1' } },
        {
          'node_modules/a': { version: '1.0.0', integrity: 'sha512-a1=', deps: { b: '^1' } },
          'node_modules/b': { version: '1.0.0', integrity: 'sha512-b1=', deps: { c: '^1' } },
          'node_modules/c': { version: '1.0.0', integrity: 'sha512-c1=', deps: { d: '^1' } },
          'node_modules/d': { version: '1.0.1', integrity: 'sha512-d2=' },
        },
      );

      const cache = new FakeCache(
        new Map([
          ['sha512-d1=', mkSnap('d', '1.0.0', 'sha512-d1=')],
          ['sha512-d2=', mkSnap('d', '1.0.1', 'sha512-d2=')],
        ]),
      );

      // Detector that emits a finding for the CHANGED node so we can assert on
      // it — proves the engine ran the detector on the depth-4 node.
      const detectorRunCalls: string[] = [];
      const runDetectors = (pair: SnapshotPair, pkg: string): Finding[] => {
        detectorRunCalls.push(pkg);
        if (pair.new && pair.old && pair.old.version !== pair.new.version) {
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
              message: `version ${pair.old.version} → ${pair.new.version}`,
              evidence: [{ file: 'package.json', line: 1, snippet: pkg }],
              provenance: [],
            },
          ];
        }
        return [];
      };

      const result = await runDiff(oldLock, newLock, {
        runDetectors,
        cache,
      });

      // Only 'd' changed → exactly one finding, for 'd'.
      expect(result.findings).toHaveLength(1);
      expect(result.findings[0]!.package).toBe('d');
      // Provenance must be the full chain root → a → b → c → d.
      expect(result.findings[0]!.provenance[0]).toEqual(['root', 'a', 'b', 'c', 'd']);
      // Detector was called only once (for the one changed node) — dedup invariant.
      expect(detectorRunCalls).toEqual(['d']);
    },
  );

  it('analyzes an added transitive node (new-node-fullscan invariant)', async () => {
    // Event-stream case: same top-level dep, but new transitive introduced.
    const oldLock = mkLock({ name: 'root', version: '1.0.0', deps: { a: '^1' } }, {
      'node_modules/a': { version: '1.0.0', integrity: 'sha512-a1=' },
    });
    const newLock = mkLock({ name: 'root', version: '1.0.0', deps: { a: '^1' } }, {
      'node_modules/a': { version: '1.0.0', integrity: 'sha512-a1=', deps: { evil: '^0.1' } },
      'node_modules/evil': { version: '0.1.1', integrity: 'sha512-evil=' },
    });
    const cache = new FakeCache(new Map([
      ['sha512-evil=', mkSnap('evil', '0.1.1', 'sha512-evil=')],
    ]));

    const seenPairs: Array<{ pkg: string; oldNull: boolean; newNull: boolean }> = [];
    const runDetectors = (pair: SnapshotPair, pkg: string): Finding[] => {
      seenPairs.push({ pkg, oldNull: pair.old === null, newNull: pair.new === null });
      if (pair.old === null && pair.new) {
        return [{
          detector: 'test.added',
          category: 'DEPS',
          package: pkg,
          from: null,
          to: pair.new.version,
          direction: 'added',
          severity: 'WARN',
          confidence: 'high',
          message: 'new node',
          evidence: [{ file: 'package.json', line: 1, snippet: pkg }],
          provenance: [],
        }];
      }
      return [];
    };
    const result = await runDiff(oldLock, newLock, { runDetectors, cache });

    // 'evil' was called as an ADDED (old=null, new set) — the full-scan invariant.
    expect(seenPairs.some((p) => p.pkg === 'evil' && p.oldNull && !p.newNull)).toBe(true);
    // Result surfaces the added finding.
    expect(result.findings.some((f) => f.package === 'evil' && f.direction === 'added')).toBe(true);
  });

  it('detects same-version integrity mismatch as BLOCK, regardless of content', async () => {
    const oldLock = mkLock({ name: 'root', version: '1.0.0', deps: { foo: '^1' } }, {
      'node_modules/foo': { version: '1.0.0', integrity: 'sha512-original=' },
    });
    const newLock = mkLock({ name: 'root', version: '1.0.0', deps: { foo: '^1' } }, {
      'node_modules/foo': { version: '1.0.0', integrity: 'sha512-tampered=' },
    });
    const cache = new FakeCache(new Map([
      ['sha512-original=', mkSnap('foo', '1.0.0', 'sha512-original=')],
      ['sha512-tampered=', mkSnap('foo', '1.0.0', 'sha512-tampered=')],
    ]));
    const noDetectors = () => [];
    const result = await runDiff(oldLock, newLock, { runDetectors: noDetectors, cache });
    expect(result.verdict).toBe('BLOCK');
    expect(result.findings.some((f) => f.detector === 'integrity.hash-mismatch')).toBe(true);
  });

  it('is deterministic — same inputs produce byte-identical findings JSON', async () => {
    const oldLock = mkLock({ name: 'root', version: '1.0.0', deps: { a: '^1', b: '^1' } }, {
      'node_modules/a': { version: '1.0.0', integrity: 'sha512-a1=' },
      'node_modules/b': { version: '1.0.0', integrity: 'sha512-b1=' },
    });
    const newLock = mkLock({ name: 'root', version: '1.0.0', deps: { a: '^1', b: '^1' } }, {
      'node_modules/a': { version: '1.0.1', integrity: 'sha512-a2=' },
      'node_modules/b': { version: '1.0.1', integrity: 'sha512-b2=' },
    });
    const cache = new FakeCache(new Map([
      ['sha512-a1=', mkSnap('a', '1.0.0', 'sha512-a1=')],
      ['sha512-a2=', mkSnap('a', '1.0.1', 'sha512-a2=')],
      ['sha512-b1=', mkSnap('b', '1.0.0', 'sha512-b1=')],
      ['sha512-b2=', mkSnap('b', '1.0.1', 'sha512-b2=')],
    ]));
    const detectors = (pair: SnapshotPair, pkg: string): Finding[] =>
      pair.new && pair.old && pair.new.version !== pair.old.version
        ? [{
            detector: 'test.bump',
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
          }]
        : [];

    const r1 = await runDiff(oldLock, newLock, { runDetectors: detectors, cache });
    // Reset the "analyzed" flag by replacing cache with a fresh one containing same snapshots
    const cache2 = new FakeCache(new Map(cache.store));
    const r2 = await runDiff(oldLock, newLock, { runDetectors: detectors, cache: cache2 });
    // Strip volatile durationMs field.
    const strip = (r: { findings: Finding[]; verdict: string; rollupByDirect: unknown; changes: unknown[]; }) => ({
      findings: r.findings,
      verdict: r.verdict,
      rollupByDirect: r.rollupByDirect,
      changes: r.changes,
    });
    expect(JSON.stringify(strip(r1))).toBe(JSON.stringify(strip(r2)));
  });
});
