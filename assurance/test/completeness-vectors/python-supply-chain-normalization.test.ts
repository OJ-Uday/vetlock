/**
 * python-supply-chain-normalization — completeness-vector transform self-tests.
 */

import { describe, it, expect } from 'vitest';
import { pyHyphenToUnderscoreName } from '../../src/completeness-vectors/python-supply-chain-normalization.js';

const SEEDS: readonly number[] = [0, 1, 7, 42, 1337, 2_147_483_647];

const PYPROJECT_HYPHEN =
  '[project]\nname = "some-package"\nversion = "0.0.0"\n';
const PYPROJECT_UNDERSCORE =
  '[project]\nname = "some_package"\nversion = "0.0.0"\n';
const PYPROJECT_NO_HYPHEN =
  '[project]\nname = "simple"\nversion = "0.0.0"\n';

describe('completeness-vectors — python-supply-chain-normalization', () => {
  it('declares the python-supply-chain targetClass', () => {
    expect(pyHyphenToUnderscoreName.targetClass).toBe('python-supply-chain');
    expect(pyHyphenToUnderscoreName.family).toBe('string-normalization');
  });

  it('is pure/deterministic', () => {
    for (const seed of SEEDS) {
      const a = pyHyphenToUnderscoreName.transform(PYPROJECT_HYPHEN, seed);
      const b = pyHyphenToUnderscoreName.transform(PYPROJECT_HYPHEN, seed);
      expect(b).toBe(a);
    }
  });

  it('rewrites hyphen-form name to underscore-form', () => {
    const out = pyHyphenToUnderscoreName.transform(PYPROJECT_HYPHEN, 0);
    expect(out).not.toBe(PYPROJECT_HYPHEN);
    expect(out).toContain('name = "some_package"');
    expect(out).not.toContain('name = "some-package"');
  });

  it('is a no-op when name is already underscore-form', () => {
    for (const seed of SEEDS) {
      expect(pyHyphenToUnderscoreName.transform(PYPROJECT_UNDERSCORE, seed)).toBe(PYPROJECT_UNDERSCORE);
    }
  });

  it('is a no-op when name has no hyphens', () => {
    for (const seed of SEEDS) {
      expect(pyHyphenToUnderscoreName.transform(PYPROJECT_NO_HYPHEN, seed)).toBe(PYPROJECT_NO_HYPHEN);
    }
  });

  it('is a no-op on package.json (JS manifest, not pyproject.toml)', () => {
    const pkg = JSON.stringify({ name: 'foo-bar' }, null, 2);
    expect(pyHyphenToUnderscoreName.transform(pkg, 0)).toBe(pkg);
  });
});
