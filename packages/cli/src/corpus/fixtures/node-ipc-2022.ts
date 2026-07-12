/**
 * node-ipc 10.1.1/10.1.2 (Mar 2022) — T4 protestware.
 *
 * Maintainer added logic that if the host's geoIP resolved to Russia or Belarus,
 * the package would overwrite every file on disk with a heart emoji. Later
 * changed to writing a `WITH-LOVE-FROM-AMERICA.txt` file to the desktop.
 *
 * Detectable signals:
 *   - NET new-module: node-fetch/http to geoIP resolver
 *   - NET new-endpoint: geoIP endpoint
 *   - FS: new write targeting user desktop / arbitrary user paths (broadened
 *     hot-path list should catch `os.homedir() + '/Desktop'`)
 */

import type { FixtureSpec } from '../fixture-spec.js';

const CLEAN_INDEX = `// node-ipc 10.1.0 — inter-process comm stubbed.
'use strict';
module.exports = { config: {}, connectTo: function() {}, of: {} };
`;

const MAL_INDEX = `// node-ipc 10.1.1 — DEFANGED reconstruction of peacenotwar.
'use strict';
var https = require('https');
var fs = require('fs');
var os = require('os');
var path = require('path');
function geoResolve() {
  return new Promise(function(resolve) {
    if (false) {
      https.get('https://api.geoip.example.invalid/country', function(res) {
        var d = ''; res.on('data', function(c) { d += c; }); res.on('end', function() { resolve(d); });
      });
    } else { resolve('US'); }
  });
}
geoResolve().then(function(country) {
  if (country === 'RU' || country === 'BY') {
    if (false) {
      var desktop = path.join(os.homedir(), 'Desktop', 'WITH-LOVE-FROM-AMERICA.txt');
      fs.writeFileSync(desktop, 'heart-heart-heart');
    }
  }
});
module.exports = { config: {}, connectTo: function() {}, of: {} };
`;

export const spec: FixtureSpec = {
  id: 'node-ipc-2022',
  title: 'node-ipc 10.1.1 (Mar 2022, peacenotwar)',
  year: 2022,
  threatClass: 'T4 protestware',
  summary:
    'Maintainer weaponized node-ipc to overwrite files on hosts whose geoIP resolved to Russia or Belarus. Later versions dropped a WITH-LOVE-FROM-AMERICA.txt on the desktop.',
  provenance: 'RECONSTRUCTED',
  topology: 'direct',
  clean: {
    name: 'node-ipc',
    version: '10.1.0',
    manifest: {
      name: 'node-ipc',
      version: '10.1.0',
      main: 'index.js',
      license: 'MIT',
      maintainers: [{ email: 'rias@example' }],
    },
    files: { 'index.js': CLEAN_INDEX },
  },
  malicious: {
    name: 'node-ipc',
    version: '10.1.1',
    manifest: {
      name: 'node-ipc',
      version: '10.1.1',
      main: 'index.js',
      license: 'MIT',
      maintainers: [{ email: 'rias@example' }],
    },
    files: { 'index.js': MAL_INDEX },
  },
  expect: {
    mustFire: [
      'net.new-module',
      'net.new-endpoint',
      'fs.new-hotpath-write',   // requires broadened hot-path list to include user Desktop
    ],
    verdict: 'BLOCK',
    minCategories: ['NET', 'FS'],
  },
};
