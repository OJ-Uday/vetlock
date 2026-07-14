/**
 * python-install-hook-relocation — completeness-vector transform self-tests.
 */

import { describe, it, expect } from 'vitest';
import {
  pySetupPyToPyproject,
  PY_NESTED_FILE_MARKER_PREFIX,
} from '../../src/completeness-vectors/python-install-hook-relocation.js';

const SEEDS: readonly number[] = [0, 1, 7, 42, 1337, 2_147_483_647];

const SETUP_WITH_CMDCLASS =
  'from setuptools import setup\nfrom setuptools.command.install import install as _install\n\n' +
  'class CustomInstall(_install):\n    def run(self):\n        _install.run(self)\n\n' +
  'setup(name="fixture", version="0.0.0", cmdclass={"install": CustomInstall})\n';

const SETUP_WITHOUT_CMDCLASS = 'from setuptools import setup\nsetup(name="fixture")\n';

describe('completeness-vectors — python-install-hook-relocation', () => {
  it('declares the python-install-hook targetClass', () => {
    expect(pySetupPyToPyproject.targetClass).toBe('python-install-hook');
    expect(pySetupPyToPyproject.family).toBe('code-location');
  });

  it('is pure/deterministic', () => {
    for (const seed of SEEDS) {
      const a = pySetupPyToPyproject.transform(SETUP_WITH_CMDCLASS, seed);
      const b = pySetupPyToPyproject.transform(SETUP_WITH_CMDCLASS, seed);
      expect(b).toBe(a);
    }
  });

  it('appends a pyproject.toml nested-file marker when cmdclass is present', () => {
    const out = pySetupPyToPyproject.transform(SETUP_WITH_CMDCLASS, 0);
    expect(out).not.toBe(SETUP_WITH_CMDCLASS);
    expect(out).toContain(`${PY_NESTED_FILE_MARKER_PREFIX}pyproject.toml`);
    expect(out).toContain('[project.entry-points."distutils.commands"]');
    expect(out).toContain('install = "package_name:CustomInstall"');
  });

  it('preserves the original setup.py body verbatim', () => {
    const out = pySetupPyToPyproject.transform(SETUP_WITH_CMDCLASS, 0);
    // Every non-marker line from the original must still be present.
    for (const line of SETUP_WITH_CMDCLASS.split('\n')) {
      if (!line) continue;
      expect(out).toContain(line);
    }
  });

  it('is a no-op when cmdclass is absent', () => {
    for (const seed of SEEDS) {
      expect(pySetupPyToPyproject.transform(SETUP_WITHOUT_CMDCLASS, seed)).toBe(SETUP_WITHOUT_CMDCLASS);
    }
  });

  it('exports the marker prefix as a Python-style comment', () => {
    expect(PY_NESTED_FILE_MARKER_PREFIX).toBe('# FILE: ');
  });
});
