/**
 * MANIFEST-DEPS http-resolved-url — dep specs that are HTTP(S) URLs.
 *
 * Test contract:
 *  - Plain-http URL as dep spec → BLOCK.
 *  - Non-registry HTTPS URL as dep spec → WARN.
 *  - Registry HTTPS URL as dep spec → does NOT fire.
 *  - Semver / caret / range specs → does NOT fire.
 *  - Diff discipline: fires on newly-added OR changed dep entries only.
 *
 * Ports from guarddog:threat-npm-http-dependency, per §4 row 8.
 */

import { describe, it, expect } from 'vitest';
import {
  httpResolvedUrlDetector,
  classifyDepSpec,
} from '../src/manifest-deps-http.js';
import { mkSnap } from './helpers.js';
import type { PackageManifest } from '@vetlock/core';

function withDeps(name: string, version: string, deps: Record<string, string>): PackageManifest {
  return { name, version, dependencies: deps };
}

describe('manifest-deps.http-resolved-url — classifyDepSpec', () => {
  it('classifies plain-http URL as plain-http', () => {
    const c = classifyDepSpec('http://attacker.example/foo.tgz');
    expect(c).not.toBeNull();
    expect(c!.kind).toBe('plain-http');
    expect(c!.host).toBe('attacker.example');
  });

  it('classifies non-registry HTTPS URL as non-registry-https', () => {
    const c = classifyDepSpec('https://internal.example.com/foo.tgz');
    expect(c).not.toBeNull();
    expect(c!.kind).toBe('non-registry-https');
    expect(c!.host).toBe('internal.example.com');
  });

  it('does NOT classify registry.npmjs.org URLs', () => {
    expect(classifyDepSpec('https://registry.npmjs.org/foo/-/foo-1.0.0.tgz')).toBeNull();
  });

  it('does NOT classify registry.yarnpkg.com URLs', () => {
    expect(classifyDepSpec('https://registry.yarnpkg.com/foo/-/foo-1.0.0.tgz')).toBeNull();
  });

  it('does NOT classify GitHub Packages registry URLs', () => {
    expect(classifyDepSpec('https://npm.pkg.github.com/@scope/foo/-/foo-1.0.0.tgz')).toBeNull();
  });

  it('does NOT classify semver specs', () => {
    expect(classifyDepSpec('^1.2.3')).toBeNull();
    expect(classifyDepSpec('~1.0.0')).toBeNull();
    expect(classifyDepSpec('1.0.0')).toBeNull();
    expect(classifyDepSpec('>= 1.0.0 < 2.0.0')).toBeNull();
    expect(classifyDepSpec('latest')).toBeNull();
  });

  it('does NOT classify file:/git+ specs (those are engine-level)', () => {
    expect(classifyDepSpec('file:../local')).toBeNull();
    expect(classifyDepSpec('git+https://github.com/foo/bar.git')).toBeNull();
    expect(classifyDepSpec('github:foo/bar')).toBeNull();
  });
});

describe('manifest-deps.http-resolved-url — detector', () => {
  it('emits BLOCK for a newly-added dep with plain-http URL', () => {
    const pair = {
      old: null,
      new: mkSnap({
        name: 'my-package',
        version: '1.0.0',
        manifest: withDeps('my-package', '1.0.0', {
          evilLib: 'http://attacker.example/evil.tgz',
        }),
      }),
    };
    const findings = httpResolvedUrlDetector.run(pair, { direction: 'added' });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.detector).toBe('manifest-deps.http-resolved-url');
    expect(findings[0]!.severity).toBe('BLOCK');
    expect(findings[0]!.confidence).toBe('high');
    expect(findings[0]!.message).toMatch(/plain-http/);
  });

  it('emits WARN for a newly-added dep with non-registry HTTPS URL', () => {
    const pair = {
      old: null,
      new: mkSnap({
        name: 'my-package',
        version: '1.0.0',
        manifest: withDeps('my-package', '1.0.0', {
          internal: 'https://internal.mirror.example/foo.tgz',
        }),
      }),
    };
    const findings = httpResolvedUrlDetector.run(pair, { direction: 'added' });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('WARN');
    expect(findings[0]!.confidence).toBe('medium');
  });

  it('does NOT fire when all deps are semver or registry URLs', () => {
    const pair = {
      old: null,
      new: mkSnap({
        name: 'my-package',
        version: '1.0.0',
        manifest: withDeps('my-package', '1.0.0', {
          axios: '^1.0.0',
          debug: 'https://registry.npmjs.org/debug/-/debug-4.0.0.tgz',
        }),
      }),
    };
    expect(httpResolvedUrlDetector.run(pair, { direction: 'added' })).toHaveLength(0);
  });

  it('fires when a dep newly gains an http URL between versions', () => {
    const pair = {
      old: mkSnap({
        name: 'my-package',
        version: '1.0.0',
        manifest: withDeps('my-package', '1.0.0', { evilLib: '^1.0.0' }),
      }),
      new: mkSnap({
        name: 'my-package',
        version: '1.0.1',
        manifest: withDeps('my-package', '1.0.1', { evilLib: 'http://attacker.example/evil.tgz' }),
      }),
    };
    const findings = httpResolvedUrlDetector.run(pair, { direction: 'changed' });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('BLOCK');
    expect(findings[0]!.direction).toBe('changed');
  });

  it('does NOT re-fire on unchanged http URLs across versions', () => {
    const pair = {
      old: mkSnap({
        name: 'my-package',
        version: '1.0.0',
        manifest: withDeps('my-package', '1.0.0', { legacyLib: 'http://legacy.example/foo.tgz' }),
      }),
      new: mkSnap({
        name: 'my-package',
        version: '1.0.1',
        manifest: withDeps('my-package', '1.0.1', { legacyLib: 'http://legacy.example/foo.tgz' }),
      }),
    };
    expect(httpResolvedUrlDetector.run(pair, { direction: 'changed' })).toHaveLength(0);
  });

  it('scans optionalDependencies + peerDependencies too', () => {
    const pair = {
      old: null,
      new: mkSnap({
        name: 'my-package',
        version: '1.0.0',
        manifest: {
          name: 'my-package',
          version: '1.0.0',
          optionalDependencies: {
            optEvil: 'http://opt-attacker.example/foo.tgz',
          },
          peerDependencies: {
            peerEvil: 'https://non-registry.example/peer.tgz',
          },
        },
      }),
    };
    const findings = httpResolvedUrlDetector.run(pair, { direction: 'added' });
    expect(findings).toHaveLength(2);
    expect(findings.some((f) => f.severity === 'BLOCK')).toBe(true);
    expect(findings.some((f) => f.severity === 'WARN')).toBe(true);
  });
});
