/**
 * Regression tests for red-team confirmed exploits S4 and L6.
 * @security-critical
 *
 * S4 — Analyze-timeout / extract-error silently drops the entire package.
 *      A tarball that throws during analysis yields no findings, so a malicious
 *      package that stalls or crashes the analyzer is reported CLEAN.
 *      Fix: emit a synthetic BLOCK-tier `analysis.failed` finding so the run
 *      can never render CLEAN when any package failed to analyze.
 *
 * L6 — Unterminated backtick chain crashes @babel/traverse mid-fold.
 *      The try/catch in extractCapabilities wraps only `parser.parse` — the
 *      subsequent foldConstants / traverse call has no error handler.
 *      A file with ~15000 backticks parses fine (errorRecovery) but then
 *      overflows the call stack during traverse, re-throwing a RangeError.
 *      Fix: wrap foldConstants and the main traverse() call in try/catch so
 *      any traversal crash fails-soft into a parseError FileCapabilities.
 */

import { describe, it, expect } from 'vitest';
import type { Finding, PackageSnapshot, SnapshotPair } from '../src/finding.js';
import { runDiff } from '../src/engine.js';
import { extractCapabilities } from '../src/capabilities.js';
import { SNAPSHOT_FORMAT_VERSION } from '../src/cache.js';

const FIXED_ISO = '2026-07-12T00:00:00.000Z';

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

function mkLock(
  root: { name: string; version: string; deps?: Record<string, string> },
  entries: Record<string, { version: string; integrity?: string }>,
) {
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
    };
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

// Minimal no-op cache so engine doesn't try real disk access.
class NullCache {
  readonly dir = '/tmp/null-cache';
  async get(_k: string) { return null; }
  async put(_k: string, _v: PackageSnapshot) {}
}

// ---------------------------------------------------------------------------
// REDTEAM S4: Synthetic analysis.failed finding when analyzeOne throws
// ---------------------------------------------------------------------------

describe('REDTEAM S4: analysis.failed synthetic finding on analyzer crash', () => {
  const oldLock = mkLock(
    { name: 'root', version: '1.0.0', deps: { clean: '^1', evil: '^1' } },
    {
      'node_modules/clean': { version: '1.0.0', integrity: 'sha512-clean=' },
      'node_modules/evil': { version: '1.0.0', integrity: 'sha512-evil=' },
    },
  );
  const newLock = mkLock(
    { name: 'root', version: '1.0.0', deps: { clean: '^1', evil: '^1' } },
    {
      'node_modules/clean': { version: '1.0.1', integrity: 'sha512-clean2=' },
      'node_modules/evil': { version: '1.0.1', integrity: 'sha512-evil2=' },
    },
  );

  // fetchOverride throws for `evil`, succeeds for `clean` by returning an
  // impossible path that doesn't exist — analyzeTarball will throw.
  const fetchOverride = async (ref: { name: string; version: string; resolved?: string | null }): Promise<string> => {
    if (ref.name === 'evil') {
      throw new Error('UnsafeArchiveError: entry-too-large (S4 fixture)');
    }
    // For 'clean', return a path that doesn't exist — this also throws inside
    // analyzeTarball, so make clean succeed via the cache (see FakeCache below).
    return '/nonexistent/path/that/does/not/exist.tgz';
  };

  // Provide a pre-loaded snapshot for `clean` both versions so that path
  // never needs the fetch; evil always falls through to fetchOverride.
  class FakeCache extends NullCache {
    private store = new Map<string, PackageSnapshot>([
      ['sha512-clean=', mkSnap('clean', '1.0.0')],
      ['sha512-clean2=', mkSnap('clean', '1.0.1')],
    ]);
    override async get(k: string) { return this.store.get(k) ?? null; }
  }

  const noDetectors = (_pair: SnapshotPair, _pkg: string): Finding[] => [];

  it('verdict is BLOCK when any package failed to analyze', async () => {
    const result = await runDiff(oldLock, newLock, {
      runDetectors: noDetectors,
      fetchOverride,
      cache: new FakeCache(),
    });
    expect(result.verdict).toBe('BLOCK');
  });

  it('findings contain an analysis.failed entry for the crashed package', async () => {
    const result = await runDiff(oldLock, newLock, {
      runDetectors: noDetectors,
      fetchOverride,
      cache: new FakeCache(),
    });
    const failed = result.findings.filter((f) => f.detector === 'analysis.failed');
    expect(failed.length, 'should have at least one analysis.failed finding').toBeGreaterThan(0);
    const evilFail = failed.find((f) => f.package === 'evil');
    expect(evilFail, 'analysis.failed finding must be for the evil package').toBeDefined();
    expect(evilFail!.severity).toBe('BLOCK');
    expect(evilFail!.category).toBe('META');
    expect(evilFail!.confidence).toBe('high');
    // Message must quote the original error
    expect(evilFail!.message).toContain('entry-too-large');
    // Evidence must have file: 'package.json'
    expect(evilFail!.evidence[0]?.file).toBe('package.json');
  });

  it('verdict must NOT be CLEAN when any package errored', async () => {
    // Even with an all-clean runDetectors, the failed package must prevent CLEAN
    const result = await runDiff(oldLock, newLock, {
      runDetectors: noDetectors,
      fetchOverride,
      cache: new FakeCache(),
    });
    expect(result.verdict).not.toBe('CLEAN');
    expect(result.verdict).not.toBe('WARN');
    expect(result.verdict).not.toBe('INFO');
  });

  it('errors array still records the per-package error (backwards compat)', async () => {
    const result = await runDiff(oldLock, newLock, {
      runDetectors: noDetectors,
      fetchOverride,
      cache: new FakeCache(),
    });
    expect(result.errors.some((e) => e.package === 'evil')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// REDTEAM L6: Fail-soft parse — 15000 backticks must not crash extractCapabilities
// ---------------------------------------------------------------------------

describe('REDTEAM L6: 15000-backtick stack-overflow fails soft into parseError', () => {
  it('does not throw when fed a file with 15000 backticks', () => {
    const text = 'const x = ' + '`'.repeat(15000);
    expect(() => extractCapabilities('index.js', text, 'sha256-fake', text.length)).not.toThrow();
  });

  it('returns a FileCapabilities with parseError set (not empty)', () => {
    const text = 'const x = ' + '`'.repeat(15000);
    const result = extractCapabilities('index.js', text, 'sha256-fake', text.length);
    // Must have a parseError — either from parser.parse failing or from the
    // traverse/foldConstants overflow being caught and returned as parseError.
    expect(result.parseError).toBeDefined();
    expect(result.parseError!.length).toBeGreaterThan(0);
  });

  it('parseError message contains descriptive text about the failure', () => {
    const text = 'const x = ' + '`'.repeat(15000);
    const result = extractCapabilities('index.js', text, 'sha256-fake', text.length);
    expect(result.parseError).toBeDefined();
    // Should mention "traverse failed" or similar (the fail-soft message shape)
    expect(result.parseError).toMatch(/traverse failed|parse error|Maximum call stack/i);
  });

  it('correctly sets path/bytes/sha256 even on parseError result', () => {
    const text = 'const x = ' + '`'.repeat(15000);
    const result = extractCapabilities('index.js', text, 'sha256-myfile', text.length);
    expect(result.path).toBe('index.js');
    expect(result.bytes).toBe(text.length);
    expect(result.sha256).toBe('sha256-myfile');
  });

  it('a normal file still parses correctly after the fix (no regression)', () => {
    const text = `const x = require('http'); process.env.NPM_TOKEN;`;
    const result = extractCapabilities('index.js', text, 'sha256-n', text.length);
    expect(result.parseError).toBeUndefined();
    expect(result.networkModules).toContain('http');
    expect(result.envAccesses.length).toBeGreaterThan(0);
  });

  it('a smaller valid template literal is still analyzed correctly (no regression)', () => {
    const text = 'const url = `https://example.com/api/${id}`;';
    const result = extractCapabilities('index.js', text, 'sha256-tpl', text.length);
    expect(result.parseError).toBeUndefined();
  });
});
