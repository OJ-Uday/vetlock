/**
 * advisory-version-shift — completeness-vector transform self-tests.
 *
 * Contract: same PURITY / NON-TRIVIALITY / SYNTACTIC-VALIDITY protocol as the
 * sibling JSON-manifest transforms (dep-graph-alias.test.ts,
 * persistence-relocation.test.ts). Output is JSON, not JS.
 */

import { describe, it, expect } from 'vitest';
import { advisoryVersionShift } from '../../src/completeness-vectors/advisory-version-shift.js';

const SEEDS: readonly number[] = [0, 1, 7, 42, 1337, 2_147_483_647];

const PKG_WITH_BARE_VERSION = JSON.stringify(
  {
    name: 'defanged-fixture',
    version: '0.0.0',
    dependencies: {
      'some-package': '1.2.3',
    },
  },
  null,
  2,
);

const PKG_WITH_RANGE_OP = JSON.stringify(
  {
    name: 'defanged-fixture',
    version: '0.0.0',
    dependencies: {
      'some-package': '^1.2.3',
    },
  },
  null,
  2,
);

const PKG_WITHOUT_DEPS = JSON.stringify(
  { name: 'defanged-fixture', version: '0.0.0' },
  null,
  2,
);

describe('completeness-vectors — advisory-version-shift', () => {
  it('declares the advisory-known-vuln targetClass', () => {
    expect(advisoryVersionShift.targetClass).toBe('advisory-known-vuln');
    expect(advisoryVersionShift.family).toBe('sink-family-widening');
    expect(advisoryVersionShift.id.length).toBeGreaterThan(0);
  });

  it('is pure/deterministic', () => {
    for (const seed of SEEDS) {
      const a = advisoryVersionShift.transform(PKG_WITH_BARE_VERSION, seed);
      const b = advisoryVersionShift.transform(PKG_WITH_BARE_VERSION, seed);
      expect(b).toBe(a);
    }
  });

  it('is non-trivial when a bare-pinned version is present', () => {
    for (const seed of SEEDS) {
      const out = advisoryVersionShift.transform(PKG_WITH_BARE_VERSION, seed);
      expect(out).not.toBe(PKG_WITH_BARE_VERSION);
    }
  });

  it('produces valid JSON output', () => {
    for (const seed of SEEDS) {
      const out = advisoryVersionShift.transform(PKG_WITH_BARE_VERSION, seed);
      expect(() => JSON.parse(out)).not.toThrow();
    }
  });

  it('increments the patch component by 1 (semantic-preservation marker)', () => {
    const out = advisoryVersionShift.transform(PKG_WITH_BARE_VERSION, 0);
    const parsed = JSON.parse(out) as { dependencies?: Record<string, string> };
    expect(parsed.dependencies?.['some-package']).toBe('1.2.4');
  });

  it('is a no-op when the version is a range spec (^1.2.3)', () => {
    for (const seed of SEEDS) {
      const out = advisoryVersionShift.transform(PKG_WITH_RANGE_OP, seed);
      expect(out).toBe(PKG_WITH_RANGE_OP);
    }
  });

  it('is a no-op when dependencies is absent', () => {
    for (const seed of SEEDS) {
      const out = advisoryVersionShift.transform(PKG_WITHOUT_DEPS, seed);
      expect(out).toBe(PKG_WITHOUT_DEPS);
    }
  });

  it('is a no-op on non-JSON input', () => {
    const notJson = 'const x = 1;\n';
    for (const seed of SEEDS) {
      expect(advisoryVersionShift.transform(notJson, seed)).toBe(notJson);
    }
  });
});
