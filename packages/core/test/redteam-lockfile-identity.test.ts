/**
 * Regression tests for red-team confirmed exploits F1, F2, F6, N5, S9 (lockfile identity).
 * @security-critical
 *
 * F1 — pnpm-lock.yaml causes crash on any engine run. The engine previously called
 *      JSON.parse unconditionally; now it dispatches via parseLockfileText.
 *      Fix: runDiff accepts oldLockfilePath / newLockfilePath hints so non-JSON
 *      lockfiles are parsed correctly.
 *
 * F2 — `"link": true` on a lockfile entry makes vetlock skip the package entirely.
 *      The fix records link entries in LockGraph.workspaceLinks and the engine emits
 *      a `deps.workspace-shadowing` WARN (or BLOCK for top-npm-names) finding.
 *
 * F6 — yarn berry `npm:` alias — engine emits `deps.aliased-name` WARN when a
 *      declared package name differs from the actually installed package.
 *
 * N5 — git+ / github: resolved URLs — engine emits `deps.non-registry-source` WARN.
 *      vetlock would analyze the registry tarball instead of the actual git content.
 *
 * S9 — file: absolute path newly-added resolved URLs — engine emits `deps.local-source` INFO.
 *      An attacker can point at any local .tgz; INFO (not WARN) so corpus tests tolerate it.
 */

import { describe, it, expect } from 'vitest';
import type { Finding, PackageSnapshot, SnapshotPair } from '../src/finding.js';
import { runDiff } from '../src/engine.js';
import { parseLockfileText } from '../src/lockfile-any.js';
import { parseLockfile } from '../src/lockfile.js';
import { SNAPSHOT_FORMAT_VERSION } from '../src/cache.js';

const FIXED_ISO = '2026-07-12T00:00:00.000Z';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function mkNpmLock(
  root: { name: string; version: string; deps?: Record<string, string> },
  entries: Record<string, {
    version: string;
    integrity?: string;
    resolved?: string;
    link?: boolean;
  }>,
): string {
  const packages: Record<string, unknown> = {
    '': { name: root.name, version: root.version, dependencies: root.deps ?? {} },
  };
  for (const [key, val] of Object.entries(entries)) {
    const idx = key.lastIndexOf('node_modules/');
    const derivedName = idx === -1 ? key : key.slice(idx + 'node_modules/'.length);
    const entry: Record<string, unknown> = {
      name: derivedName,
      version: val.version,
    };
    if (val.integrity) entry.integrity = val.integrity;
    if (val.resolved) entry.resolved = val.resolved;
    if (val.link) entry.link = true;
    packages[key] = entry;
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

class NullCache {
  readonly dir = '/tmp/null-cache';
  async get(_k: string) { return null; }
  async put(_k: string, _v: PackageSnapshot) {}
}

const noDetectors = (_pair: SnapshotPair, _pkg: string): Finding[] => [];
const emptyLock = mkNpmLock({ name: 'root', version: '1.0.0', deps: {} }, {});

// ---------------------------------------------------------------------------
// F1: pnpm-lock.yaml does NOT crash the engine
// ---------------------------------------------------------------------------

const PNPM_LOCK = `\
lockfileVersion: '9.0'
importers:
  '.':
    dependencies:
      malicious-pkg:
        specifier: 1.0.0
        version: 1.0.0
packages:
  malicious-pkg@1.0.0:
    resolution:
      integrity: sha512-XXXXXXXXXX==
`;

describe('REDTEAM F1: pnpm-lock.yaml does not crash the engine', () => {
  it('parseLockfileText correctly identifies pnpm format from filename', () => {
    const result = parseLockfileText(PNPM_LOCK, 'pnpm-lock.yaml');
    expect(result.kind).toBe('pnpm');
  });

  it('runDiff with pnpm-lock.yaml lockfiles returns a result (no crash)', async () => {
    const result = await runDiff(PNPM_LOCK, PNPM_LOCK, {
      runDetectors: noDetectors,
      oldLockfilePath: 'pnpm-lock.yaml',
      newLockfilePath: 'pnpm-lock.yaml',
      cache: new NullCache(),
      fetchOverride: async () => { throw new Error('should not fetch identical lockfiles'); },
    });
    expect(result.verdict).toBe('CLEAN');
    expect(result.changes).toHaveLength(0);
  });

  it('runDiff with a pnpm lockfile that has a new package detects the change', async () => {
    const before = `lockfileVersion: '9.0'\nimporters:\n  '.':\n    dependencies: {}\npackages: {}\n`;
    const after = PNPM_LOCK;
    const result = await runDiff(before, after, {
      runDetectors: noDetectors,
      oldLockfilePath: 'pnpm-lock.yaml',
      newLockfilePath: 'pnpm-lock.yaml',
      cache: new NullCache(),
      fetchOverride: async () => { throw new Error('offline test — no fetch allowed'); },
    });
    expect(result.verdict).toBe('BLOCK');
    expect(result.changes.some((c) => c.name === 'malicious-pkg')).toBe(true);
  });

  it('pnpm LockGraph includes workspaceLinks and npmAliases arrays', () => {
    const result = parseLockfileText(PNPM_LOCK, 'pnpm-lock.yaml');
    expect(Array.isArray(result.graph.workspaceLinks)).toBe(true);
    expect(Array.isArray(result.graph.npmAliases)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// F2: link:true entries appear in LockGraph.workspaceLinks and engine emits finding
// ---------------------------------------------------------------------------

describe('REDTEAM F2: workspace link entries recorded + finding emitted', () => {
  const afterWithLink = mkNpmLock(
    { name: 'my-app', version: '1.0.0', deps: { malicious: '^1.0.0' } },
    {
      'node_modules/malicious': {
        version: '1.0.0',
        integrity: 'sha512-badbadbadbadbadbadbadbadbad==',
        resolved: 'https://attacker.example/malicious-1.0.0.tgz',
        link: true,
      },
    },
  );

  it('LockGraph.workspaceLinks is populated for link:true entries', () => {
    const parsed = JSON.parse(afterWithLink);
    const graph = parseLockfile(parsed);
    expect(graph.workspaceLinks).toHaveLength(1);
    expect(graph.workspaceLinks[0]?.name).toBe('malicious');
  });

  it('LockGraph.npmAliases is empty for npm lockfiles', () => {
    const parsed = JSON.parse(afterWithLink);
    const graph = parseLockfile(parsed);
    expect(graph.npmAliases).toHaveLength(0);
  });

  it('link:true entries are NOT in LockGraph.nodes', () => {
    const parsed = JSON.parse(afterWithLink);
    const graph = parseLockfile(parsed);
    const hasInNodes = [...graph.nodes.values()].some((n) => n.name === 'malicious');
    expect(hasInNodes).toBe(false);
  });

  it('engine emits deps.workspace-shadowing WARN for link:true entry', async () => {
    const result = await runDiff(emptyLock, afterWithLink, {
      runDetectors: noDetectors,
      cache: new NullCache(),
      fetchOverride: async () => { throw new Error('link entries should not be fetched'); },
    });
    const shadowing = result.findings.filter((f) => f.detector === 'deps.workspace-shadowing');
    expect(shadowing.length).toBeGreaterThan(0);
    expect(shadowing[0]?.severity).toBe('WARN');
    expect(shadowing[0]?.package).toBe('malicious');
    expect(shadowing[0]?.category).toBe('DEPS');
  });

  it('engine escalates to BLOCK when workspace link name is a top-npm-name', async () => {
    const afterAxiosLink = mkNpmLock(
      { name: 'my-app', version: '1.0.0', deps: { axios: '^1.0.0' } },
      {
        'node_modules/axios': {
          version: '1.0.0',
          integrity: 'sha512-fakeAxios==',
          resolved: 'https://attacker.example/evil-1.0.0.tgz',
          link: true,
        },
      },
    );
    const topNpmNames = new Set(['axios', 'chalk', 'react', 'lodash']);
    const result = await runDiff(emptyLock, afterAxiosLink, {
      runDetectors: noDetectors,
      cache: new NullCache(),
      topNpmNames,
      fetchOverride: async () => { throw new Error('link entries should not be fetched'); },
    });
    const shadowing = result.findings.filter((f) => f.detector === 'deps.workspace-shadowing');
    expect(shadowing.length).toBeGreaterThan(0);
    expect(shadowing[0]?.severity).toBe('BLOCK');
    expect(result.verdict).toBe('BLOCK');
  });

  it('verdict is non-CLEAN when workspace-shadowing finding is emitted', async () => {
    const result = await runDiff(emptyLock, afterWithLink, {
      runDetectors: noDetectors,
      cache: new NullCache(),
      fetchOverride: async () => { throw new Error('should not fetch'); },
    });
    expect(result.verdict).not.toBe('CLEAN');
  });

  it('normal entries without link:true are NOT affected (no regression)', () => {
    const normalLock = mkNpmLock(
      { name: 'app', version: '1.0.0', deps: { foo: '^1.0.0' } },
      { 'node_modules/foo': { version: '1.0.0', integrity: 'sha512-foo=' } },
    );
    const parsed = JSON.parse(normalLock);
    const graph = parseLockfile(parsed);
    expect(graph.workspaceLinks).toHaveLength(0);
    expect([...graph.nodes.keys()]).toContain('node_modules/foo');
  });
});

// ---------------------------------------------------------------------------
// F6: yarn npm: alias → deps.aliased-name finding
// ---------------------------------------------------------------------------

describe('REDTEAM F6: deps.aliased-name finding for yarn npm: alias', () => {
  // Yarn berry lockfile where 'chalk' is aliased to 'evil-payload@1.0.0'
  const YARN_ALIAS_LOCK = `\
__metadata:
  version: 6
  cacheKey: 10

'chalk@npm:evil-payload@1.0.0':
  version: 1.0.0
  resolution: 'evil-payload@npm:1.0.0'
  integrity: sha512-attackerControlledHash==
  dependencies: {}
`;

  it('emits deps.aliased-name WARN when yarn npm: alias differs from declared name', async () => {
    const emptyYarnLock = '__metadata:\n  version: 6\n  cacheKey: 10\n';
    const result = await runDiff(emptyYarnLock, YARN_ALIAS_LOCK, {
      runDetectors: noDetectors,
      cache: new NullCache(),
      oldLockfilePath: 'yarn.lock',
      newLockfilePath: 'yarn.lock',
      fetchOverride: async () => { throw new Error('offline — no fetch'); },
    });
    const aliased = result.findings.filter((f) => f.detector === 'deps.aliased-name');
    expect(aliased.length).toBeGreaterThan(0);
    const f = aliased[0]!;
    expect(f.severity).toBe('WARN');
    expect(f.category).toBe('DEPS');
    expect(f.package).toBe('chalk');
    expect(f.message).toContain('evil-payload');
    expect(f.evidence[0]?.snippet).toContain('npm:evil-payload');
  });

  it('does not emit deps.aliased-name for normal yarn packages (no npm: alias)', async () => {
    const YARN_NORMAL = `\
__metadata:
  version: 6
  cacheKey: 10

'lodash@npm:^4.17.0':
  version: 4.17.21
  resolution: 'lodash@npm:4.17.21'
  integrity: sha512-realLodash==
  dependencies: {}
`;
    const emptyYarnLock = '__metadata:\n  version: 6\n  cacheKey: 10\n';
    const result = await runDiff(emptyYarnLock, YARN_NORMAL, {
      runDetectors: noDetectors,
      cache: new NullCache(),
      oldLockfilePath: 'yarn.lock',
      newLockfilePath: 'yarn.lock',
      fetchOverride: async () => { throw new Error('offline'); },
    });
    const aliased = result.findings.filter((f) => f.detector === 'deps.aliased-name');
    expect(aliased).toHaveLength(0);
  });

  it('verdict is WARN or BLOCK when an alias finding is emitted', async () => {
    const emptyYarnLock = '__metadata:\n  version: 6\n  cacheKey: 10\n';
    const result = await runDiff(emptyYarnLock, YARN_ALIAS_LOCK, {
      runDetectors: noDetectors,
      cache: new NullCache(),
      oldLockfilePath: 'yarn.lock',
      newLockfilePath: 'yarn.lock',
      fetchOverride: async () => { throw new Error('offline'); },
    });
    expect(['WARN', 'BLOCK']).toContain(result.verdict);
  });

  it('LockGraph.npmAliases is populated by the yarn parser for npm: alias entries', () => {
    const result = parseLockfileText(YARN_ALIAS_LOCK, 'yarn.lock');
    expect(result.graph.npmAliases.length).toBeGreaterThan(0);
    const alias = result.graph.npmAliases[0]!;
    expect(alias.declaredName).toBe('chalk');
    expect(alias.realName).toBe('evil-payload');
  });
});

// ---------------------------------------------------------------------------
// N5: git+ resolved URLs → deps.non-registry-source finding
// ---------------------------------------------------------------------------

describe('REDTEAM N5: deps.non-registry-source finding for git+ resolved URLs', () => {
  const afterGitResolved = mkNpmLock(
    { name: 'root', version: '1.0.0', deps: { 'chart-js-fork': '1.0.0' } },
    {
      'node_modules/chart-js-fork': {
        version: '1.0.0',
        integrity: 'sha512-GIT_MALICIOUS_HASH==',
        resolved: 'git+ssh://git@github.com/attacker/chart-js-fork.git#deadbeef1234',
      },
    },
  );

  it('emits deps.non-registry-source WARN for git+ resolved URL', async () => {
    const result = await runDiff(emptyLock, afterGitResolved, {
      runDetectors: noDetectors,
      cache: new NullCache(),
      fetchOverride: async () => { throw new Error('offline — git URL not fetched'); },
    });
    const nonReg = result.findings.filter((f) => f.detector === 'deps.non-registry-source');
    expect(nonReg.length).toBeGreaterThan(0);
    const f = nonReg[0]!;
    expect(f.severity).toBe('WARN');
    expect(f.category).toBe('DEPS');
    expect(f.package).toBe('chart-js-fork');
    expect(f.message).toContain('git+ssh://');
    expect(f.evidence[0]?.snippet).toContain('resolved:');
  });

  it('emits deps.non-registry-source WARN for github: shorthand resolved URL', async () => {
    const afterGithub = mkNpmLock(
      { name: 'root', version: '1.0.0', deps: { 'my-fork': '1.0.0' } },
      {
        'node_modules/my-fork': {
          version: '1.0.0',
          integrity: 'sha512-GITHUB_HASH==',
          resolved: 'github:attacker/my-fork#deadbeef',
        },
      },
    );
    const result = await runDiff(emptyLock, afterGithub, {
      runDetectors: noDetectors,
      cache: new NullCache(),
      fetchOverride: async () => { throw new Error('offline'); },
    });
    const nonReg = result.findings.filter((f) => f.detector === 'deps.non-registry-source');
    expect(nonReg.length).toBeGreaterThan(0);
    expect(nonReg[0]!.severity).toBe('WARN');
  });

  it('does NOT emit non-registry-source for normal https registry URL', async () => {
    const afterNormal = mkNpmLock(
      { name: 'root', version: '1.0.0', deps: { chalk: '^5.0.0' } },
      {
        'node_modules/chalk': {
          version: '5.3.0',
          integrity: 'sha512-realChalk==',
          resolved: 'https://registry.npmjs.org/chalk/-/chalk-5.3.0.tgz',
        },
      },
    );
    const result = await runDiff(emptyLock, afterNormal, {
      runDetectors: noDetectors,
      cache: new NullCache(),
      fetchOverride: async () => { throw new Error('offline'); },
    });
    const nonReg = result.findings.filter((f) => f.detector === 'deps.non-registry-source');
    expect(nonReg).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// S9: absolute file: resolved URL → deps.local-source finding (newly-added only)
// ---------------------------------------------------------------------------

describe('REDTEAM S9: deps.local-source finding for newly-added absolute file: resolved URLs', () => {
  const afterAbsoluteFile = mkNpmLock(
    { name: 'root', version: '1.0.0', deps: { chalk: '^5.3.0' } },
    {
      'node_modules/chalk': {
        version: '5.3.1',
        integrity: 'sha512-fake531==',
        resolved: 'file:///Users/L122472/personal/vetlock/corpus/shai-hulud-2025/chalk-5.3.0/chalk-5.3.0.tgz',
      },
    },
  );

  it('emits deps.local-source INFO for a newly-added absolute file: resolved URL', async () => {
    const result = await runDiff(emptyLock, afterAbsoluteFile, {
      runDetectors: noDetectors,
      cache: new NullCache(),
      fetchOverride: async (ref) => {
        if (ref.resolved?.startsWith('file:')) return new URL(ref.resolved!).pathname;
        throw new Error('offline — no real fetch');
      },
    });
    const localSrc = result.findings.filter((f) => f.detector === 'deps.local-source');
    expect(localSrc.length).toBeGreaterThan(0);
    const f = localSrc[0]!;
    expect(f.severity).toBe('INFO');
    expect(f.category).toBe('DEPS');
    expect(f.package).toBe('chalk');
    expect(f.direction).toBe('added');
    expect(f.message).toContain('file:');
    expect(f.evidence[0]?.snippet).toContain('resolved:');
  });

  it('verdict is non-CLEAN when local-source or analysis.failed finding fires', async () => {
    const result = await runDiff(emptyLock, afterAbsoluteFile, {
      runDetectors: noDetectors,
      cache: new NullCache(),
      fetchOverride: async (ref) => {
        if (ref.resolved?.startsWith('file:')) return new URL(ref.resolved!).pathname;
        throw new Error('offline');
      },
    });
    expect(result.verdict).not.toBe('CLEAN');
  });

  it('does NOT emit local-source for relative file: paths (normal in monorepos)', async () => {
    const afterRelativeFile = mkNpmLock(
      { name: 'root', version: '1.0.0', deps: { 'my-local-pkg': '^1.0.0' } },
      {
        'node_modules/my-local-pkg': {
          version: '1.0.0',
          integrity: 'sha512-local==',
          resolved: 'file:../packages/my-local-pkg',
        },
      },
    );
    const result = await runDiff(emptyLock, afterRelativeFile, {
      runDetectors: noDetectors,
      cache: new NullCache(),
      fetchOverride: async () => { throw new Error('offline'); },
    });
    const localSrc = result.findings.filter((f) => f.detector === 'deps.local-source');
    expect(localSrc).toHaveLength(0);
  });

  it('does NOT emit local-source for pre-existing file: entries (changed, not added)', async () => {
    const beforeWithFile = mkNpmLock(
      { name: 'root', version: '1.0.0', deps: { chalk: '^5.0.0' } },
      {
        'node_modules/chalk': {
          version: '5.3.0',
          integrity: 'sha512-fakechalk530==',
          resolved: 'file:///Users/L122472/personal/vetlock/corpus/chalk-5.3.0.tgz',
        },
      },
    );
    const afterUpdated = mkNpmLock(
      { name: 'root', version: '1.0.0', deps: { chalk: '^5.0.0' } },
      {
        'node_modules/chalk': {
          version: '5.3.1',
          integrity: 'sha512-fakechalk531==',
          resolved: 'file:///Users/L122472/personal/vetlock/corpus/chalk-5.3.1.tgz',
        },
      },
    );
    const result = await runDiff(beforeWithFile, afterUpdated, {
      runDetectors: noDetectors,
      cache: new NullCache(),
      fetchOverride: async () => { throw new Error('offline'); },
    });
    const localSrc = result.findings.filter((f) => f.detector === 'deps.local-source');
    expect(localSrc).toHaveLength(0);
  });
});
