/**
 * REDTEAM N4 FIX: scope-prefix typosquat.
 *
 * `closestTop` used to compare the FULL package name (including any
 * `@scope/` prefix) against the top-name list. `@evil-org/react` has a huge
 * whole-string edit distance from `react` (the scope alone is longer than
 * `react` itself), so the detector never fired — even though the base name
 * is an exact, shameless impersonation of the real unscoped `react`.
 *
 * Fix (packages/detectors/src/typo.ts): for a scoped name whose scope is NOT
 * on the trusted-scope allowlist, also compare the base name (after the
 * `/`) against every unscoped top name.
 */

import { describe, it, expect } from 'vitest';
import { closestTop, typosquatDetector } from '../src/typo.js';
import { mkSnap } from './helpers.js';

describe('REDTEAM N4: scope-prefix typosquat evades base typosquatDetector', () => {
  it('flags an unknown scope wrapping an exact top-package base name (`@evil-org/react`)', () => {
    const near = closestTop('@evil-org/react');
    expect(near, '@evil-org/react should be flagged as impersonating react').not.toBeNull();
    expect(near!.target).toBe('react');
    expect(near!.distance).toBe(0);
  });

  it('flags an unknown scope wrapping a near-miss of a top-package base name', () => {
    const near = closestTop('@evil-org/reactt');
    expect(near).not.toBeNull();
    expect(near!.target).toBe('react');
    expect(near!.distance).toBe(1);
  });

  it('does NOT flag a known-trusted scope even when the base matches a top name exactly', () => {
    // @babel/core IS a real top-npm-name — but even a fictional trusted-scope
    // base that happens to collide with an unscoped top name must not
    // self-flag. Use @types/node (a real top name) to prove the trusted-scope
    // carve-out doesn't create false positives for legitimate scoped packages.
    expect(closestTop('@types/node')).toBeNull();
    expect(closestTop('@babel/core')).toBeNull();
  });

  it('does not flag an unknown scope whose base name is unrelated to any top package', () => {
    expect(closestTop('@my-internal-org/totally-original-tool')).toBeNull();
  });

  it('typosquatDetector emits a WARN finding for the @evil-org/react fixture (escalatable to BLOCK in runAll)', () => {
    const pair = {
      old: null,
      new: mkSnap({ name: '@evil-org/react', version: '1.0.0' }),
    };
    const findings = typosquatDetector.run(pair, { direction: 'added' });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.detector).toBe('deps.typosquat-candidate');
    expect(findings[0]!.severity).toBe('WARN');
    expect(findings[0]!.confidence).toBe('high');
    expect(findings[0]!.message).toMatch(/react/);
  });
});
