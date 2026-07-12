/**
 * Synthetic — T5 registry / lockfile tamper.
 *
 * No content-level malice: the tarball for package foo@1.2.3 was replaced,
 * so integrity hash changed while the version string stayed the same. This is
 * the ONE case where content analysis is irrelevant — the mismatched hash IS
 * the signal.
 */

import type { FixtureSpec } from '../fixture-spec.js';

const IDENTICAL = `'use strict';
module.exports = { hello: 'world' };
`;

export const spec: FixtureSpec = {
  id: 'integrity-tamper-synthetic',
  title: 'Integrity tamper (synthetic — same version, different tarball)',
  year: 2026,
  threatClass: 'T5 registry / lockfile tamper',
  summary:
    'Synthetic fixture: the tarball bytes for foo@1.2.3 differ between the two lockfiles, but the version string is unchanged. Real-world equivalent: registry compromise or in-flight MITM. This scenario is caught before content analysis even runs.',
  provenance: 'RECONSTRUCTED', // synthetic
  topology: 'direct',
  clean: {
    name: 'foo-lib',
    version: '1.2.3',
    manifest: {
      name: 'foo-lib',
      version: '1.2.3',
      main: 'index.js',
    },
    files: { 'index.js': IDENTICAL },
  },
  malicious: {
    // Same name+version — the ONLY difference is the tarball bytes (README added
    // is enough to change the hash). No manifest change, no dep change, nothing
    // for the content detectors to see.
    name: 'foo-lib',
    version: '1.2.3',
    manifest: {
      name: 'foo-lib',
      version: '1.2.3',
      main: 'index.js',
    },
    files: {
      'index.js': IDENTICAL,
      'CHANGED.md': 'bytes changed to force integrity mismatch',
    },
  },
  expect: {
    mustFire: [
      'integrity.hash-mismatch',
    ],
    verdict: 'BLOCK',
    minCategories: ['INTEG'],
  },
};
