#!/usr/bin/env node
/**
 * Copy the Shai-Hulud demo fixture into the CLI's dist/ tree so the fixture
 * ships in the published npm tarball. Called as a `postbuild` step.
 *
 * Source: <repo-root>/corpus/shai-hulud-2025/
 * Dest:   packages/cli/dist/demo-fixture/
 *
 * We can't just add "../../corpus/shai-hulud-2025" to package.json's `files`
 * because npm's `files` cannot escape the package dir. Copy first, ship second.
 *
 * The fixture is ~20 KB — trivial. Zero-effort try-out (`npx @oj-uday/vetlock demo`)
 * requires no network and no external state.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CLI_PKG = path.resolve(HERE, '..');
const REPO_ROOT = path.resolve(CLI_PKG, '..', '..');
const SRC = path.join(REPO_ROOT, 'corpus', 'shai-hulud-2025');
const DEST = path.join(CLI_PKG, 'dist', 'demo-fixture');

if (!fs.existsSync(SRC)) {
  console.error(`copy-demo-fixture: source not found: ${SRC}`);
  console.error(`  build the corpus first: node packages/cli/dist/corpus/build-shai-hulud.js`);
  process.exit(1);
}

fs.rmSync(DEST, { recursive: true, force: true });
fs.mkdirSync(DEST, { recursive: true });

function copyTree(from, to) {
  const entries = fs.readdirSync(from, { withFileTypes: true });
  for (const entry of entries) {
    const srcPath = path.join(from, entry.name);
    const dstPath = path.join(to, entry.name);
    if (entry.isDirectory()) {
      fs.mkdirSync(dstPath, { recursive: true });
      copyTree(srcPath, dstPath);
    } else {
      fs.copyFileSync(srcPath, dstPath);
    }
  }
}
copyTree(SRC, DEST);

const files = [];
function walk(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(p);
    else files.push(path.relative(DEST, p));
  }
}
walk(DEST);

console.log(`copy-demo-fixture: ${files.length} files → dist/demo-fixture/`);
