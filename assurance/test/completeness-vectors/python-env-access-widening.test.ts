/**
 * python-env-access-widening — completeness-vector transform self-tests.
 */

import { describe, it, expect } from 'vitest';
import { pyOsEnvironToGetenv } from '../../src/completeness-vectors/python-env-access-widening.js';

const SEEDS: readonly number[] = [0, 1, 7, 42, 1337, 2_147_483_647];

const PY_WITH_INDEXED = 'import os\ntoken = os.environ["NPM_TOKEN"]\n';
const PY_WITH_GET = 'import os\ntoken = os.environ.get("GITHUB_TOKEN")\n';

describe('completeness-vectors — python-env-access-widening', () => {
  it('declares the python-env-access targetClass', () => {
    expect(pyOsEnvironToGetenv.targetClass).toBe('python-env-access');
    expect(pyOsEnvironToGetenv.family).toBe('sink-family-widening');
  });

  it('is pure/deterministic', () => {
    for (const seed of SEEDS) {
      const a = pyOsEnvironToGetenv.transform(PY_WITH_INDEXED, seed);
      const b = pyOsEnvironToGetenv.transform(PY_WITH_INDEXED, seed);
      expect(b).toBe(a);
    }
  });

  it('rewrites os.environ["KEY"] to os.getenv("KEY")', () => {
    const out = pyOsEnvironToGetenv.transform(PY_WITH_INDEXED, 0);
    expect(out).not.toBe(PY_WITH_INDEXED);
    expect(out).toContain('os.getenv("NPM_TOKEN")');
    expect(out).not.toContain('os.environ["NPM_TOKEN"]');
  });

  it('rewrites os.environ.get("KEY") to os.getenv("KEY")', () => {
    const out = pyOsEnvironToGetenv.transform(PY_WITH_GET, 0);
    expect(out).not.toBe(PY_WITH_GET);
    expect(out).toContain('os.getenv("GITHUB_TOKEN")');
    expect(out).not.toContain('os.environ.get');
  });

  it('is a no-op on source without os.environ access', () => {
    const benign = 'import os\nprint(os.getcwd())\n';
    for (const seed of SEEDS) {
      expect(pyOsEnvironToGetenv.transform(benign, seed)).toBe(benign);
    }
  });

  it('is a no-op on JavaScript with process.env access', () => {
    const js = 'const t = process.env.NPM_TOKEN;\n';
    expect(pyOsEnvironToGetenv.transform(js, 0)).toBe(js);
  });
});
