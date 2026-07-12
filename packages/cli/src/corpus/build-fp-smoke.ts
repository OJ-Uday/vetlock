/**
 * FP smoke — build 3 realistic BENIGN version-bump fixtures and confirm vetlock
 * doesn't yell about them.
 *
 * Cases:
 *   - "docs-only bump": README/CHANGELOG changed; index.js identical.
 *   - "minor feature bump": added a new exported function; imported net module
 *     was ALREADY present in old (diff-framing test — should not fire NET).
 *   - "typescript type update": DTS-only diff; no runtime source change.
 *
 * We want each of these to produce verdict INFO or CLEAN, never WARN or BLOCK.
 */

import * as tar from 'tar';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as crypto from 'node:crypto';

const OUT_DIR = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '..', '..', '..', '..',
  'corpus', 'fp-smoke',
);

async function makeTarball(dir: string, files: Record<string, string>): Promise<{ path: string; integrity: string }> {
  const stage = fs.mkdtempSync(path.join(OUT_DIR, '.stage-'));
  const pkgDir = path.join(stage, 'package');
  fs.mkdirSync(pkgDir, { recursive: true });
  for (const [name, content] of Object.entries(files)) {
    const p = path.join(pkgDir, name);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, content);
  }
  fs.mkdirSync(dir, { recursive: true });
  const tarballPath = path.join(dir, path.basename(dir) + '.tgz');
  await tar.c({ gzip: true, file: tarballPath, cwd: stage, portable: true }, ['package']);
  const buf = fs.readFileSync(tarballPath);
  const hash = crypto.createHash('sha512').update(buf).digest('base64');
  fs.rmSync(stage, { recursive: true, force: true });
  return { path: tarballPath, integrity: `sha512-${hash}` };
}

async function writeCase(
  caseDir: string,
  pkgName: string,
  clean: { pkg: object; files: Record<string, string> },
  bumped: { pkg: object; files: Record<string, string> },
): Promise<void> {
  fs.mkdirSync(caseDir, { recursive: true });
  const oldTgz = await makeTarball(path.join(caseDir, `${pkgName}-old`), {
    'package.json': JSON.stringify(clean.pkg, null, 2),
    ...clean.files,
  });
  const newTgz = await makeTarball(path.join(caseDir, `${pkgName}-new`), {
    'package.json': JSON.stringify(bumped.pkg, null, 2),
    ...bumped.files,
  });
  const before = {
    name: 'app', version: '1.0.0', lockfileVersion: 3,
    packages: {
      '': { name: 'app', version: '1.0.0', dependencies: { [pkgName]: '^1' } },
      [`node_modules/${pkgName}`]: {
        name: pkgName, version: (clean.pkg as { version: string }).version,
        integrity: oldTgz.integrity, resolved: `file://${oldTgz.path}`,
      },
    },
  };
  const after = {
    name: 'app', version: '1.0.0', lockfileVersion: 3,
    packages: {
      '': { name: 'app', version: '1.0.0', dependencies: { [pkgName]: '^1' } },
      [`node_modules/${pkgName}`]: {
        name: pkgName, version: (bumped.pkg as { version: string }).version,
        integrity: newTgz.integrity, resolved: `file://${newTgz.path}`,
      },
    },
  };
  fs.writeFileSync(path.join(caseDir, 'lockfile.before.json'), JSON.stringify(before, null, 2));
  fs.writeFileSync(path.join(caseDir, 'lockfile.after.json'), JSON.stringify(after, null, 2));
}

async function main() {
  fs.mkdirSync(OUT_DIR, { recursive: true });

  // Case A: docs-only bump. Only README changes; JS identical, but package.json version bumps.
  await writeCase(
    path.join(OUT_DIR, 'a-docs-only'),
    'lodash-lite',
    {
      pkg: { name: 'lodash-lite', version: '1.2.0', main: 'index.js', license: 'MIT' },
      files: {
        'index.js': "export const chunk = (arr, n) => arr.slice(0, n);\n",
        'README.md': '# lodash-lite v1.2.0\n\nSmall utility.\n',
      },
    },
    {
      pkg: { name: 'lodash-lite', version: '1.2.1', main: 'index.js', license: 'MIT' },
      files: {
        'index.js': "export const chunk = (arr, n) => arr.slice(0, n);\n",
        'README.md': '# lodash-lite v1.2.1\n\nSmall utility. Doc fix.\n',
      },
    },
  );

  // Case B: legitimate new feature. axios-like library that already had NET;
  // adds a new helper that also uses NET (same module) — should be INFO at most.
  await writeCase(
    path.join(OUT_DIR, 'b-feature-bump'),
    'requests-lite',
    {
      pkg: {
        name: 'requests-lite', version: '2.0.0', main: 'index.js', license: 'MIT',
        maintainers: [{ email: 'a@ex.com' }],
      },
      files: {
        'index.js':
`import https from 'https';
export function get(url) {
  return new Promise((resolve, reject) => {
    const req = https.request(url, (res) => resolve(res));
    req.on('error', reject);
    req.end();
  });
}
`,
      },
    },
    {
      pkg: {
        name: 'requests-lite', version: '2.0.1', main: 'index.js', license: 'MIT',
        maintainers: [{ email: 'a@ex.com' }],
      },
      files: {
        'index.js':
`import https from 'https';
export function get(url) {
  return new Promise((resolve, reject) => {
    const req = https.request(url, (res) => resolve(res));
    req.on('error', reject);
    req.end();
  });
}
export function post(url, body) {
  return new Promise((resolve, reject) => {
    const req = https.request(url, { method: 'POST' }, (res) => resolve(res));
    req.on('error', reject);
    req.end(body);
  });
}
`,
      },
    },
  );

  // Case C: type-only update. Only .d.ts changes; runtime JS untouched.
  await writeCase(
    path.join(OUT_DIR, 'c-types-only'),
    'micro-mitt',
    {
      pkg: { name: 'micro-mitt', version: '3.0.0', main: 'index.js', types: 'index.d.ts', license: 'MIT' },
      files: {
        'index.js': "export const mitt = () => ({ on() {}, emit() {} });\n",
        'index.d.ts': 'export function mitt(): { on(): void; emit(): void };\n',
      },
    },
    {
      pkg: { name: 'micro-mitt', version: '3.0.1', main: 'index.js', types: 'index.d.ts', license: 'MIT' },
      files: {
        'index.js': "export const mitt = () => ({ on() {}, emit() {} });\n",
        'index.d.ts': 'export function mitt<T = unknown>(): { on(evt: string, h: (v: T) => void): void; emit(evt: string, v: T): void };\n',
      },
    },
  );

  // Case D: internal refactor. Same public API, code shape changes; nothing new externally.
  await writeCase(
    path.join(OUT_DIR, 'd-refactor'),
    'small-parser',
    {
      pkg: { name: 'small-parser', version: '1.5.0', main: 'index.js', license: 'MIT' },
      files: {
        'index.js':
`'use strict';
function parse(input) {
  return input.split(',').map(s => s.trim());
}
module.exports = { parse };
`,
      },
    },
    {
      pkg: { name: 'small-parser', version: '1.5.1', main: 'index.js', license: 'MIT' },
      files: {
        'index.js':
`'use strict';
function trim(x) { return x.trim(); }
function parse(input) {
  const parts = input.split(',');
  return parts.map(trim);
}
module.exports = { parse };
`,
      },
    },
  );

  // Case E: license correction — repo/license fields updated in manifest only.
  await writeCase(
    path.join(OUT_DIR, 'e-license-fix'),
    'tiny-util',
    {
      pkg: { name: 'tiny-util', version: '0.9.0', main: 'index.js', license: 'MIT-CMU' },
      files: {
        'index.js': 'module.exports = { identity: (x) => x };\n',
      },
    },
    {
      pkg: {
        name: 'tiny-util',
        version: '0.9.1',
        main: 'index.js',
        license: 'MIT',
        repository: { type: 'git', url: 'https://github.com/example/tiny-util.git' },
      },
      files: {
        'index.js': 'module.exports = { identity: (x) => x };\n',
      },
    },
  );

  // Case F: tests-only additions. Real code unchanged; author adds test files that ARE
  // in the tarball because they didn't set 'files' in package.json.
  await writeCase(
    path.join(OUT_DIR, 'f-added-tests'),
    'query-helper',
    {
      pkg: { name: 'query-helper', version: '2.1.0', main: 'index.js', license: 'MIT' },
      files: {
        'index.js': "exports.qs = (obj) => new URLSearchParams(obj).toString();\n",
      },
    },
    {
      pkg: { name: 'query-helper', version: '2.1.1', main: 'index.js', license: 'MIT' },
      files: {
        'index.js': "exports.qs = (obj) => new URLSearchParams(obj).toString();\n",
        'test/index.test.js': "const { qs } = require('..');\nconsole.log(qs({ a: 1 }));\n",
      },
    },
  );

  // Case G: minor bugfix — one function body changed to fix an edge case.
  await writeCase(
    path.join(OUT_DIR, 'g-bugfix'),
    'clamp-fn',
    {
      pkg: { name: 'clamp-fn', version: '1.0.0', main: 'index.js', license: 'MIT' },
      files: {
        'index.js': "module.exports = (x, lo, hi) => Math.min(hi, Math.max(lo, x));\n",
      },
    },
    {
      pkg: { name: 'clamp-fn', version: '1.0.1', main: 'index.js', license: 'MIT' },
      files: {
        'index.js':
`module.exports = function clamp(x, lo, hi) {
  if (Number.isNaN(x)) return lo;   // bugfix: preserve NaN handling
  return Math.min(hi, Math.max(lo, x));
};
`,
      },
    },
  );

  // Case H: new peerDep only — dep-metadata change without shipped code change.
  await writeCase(
    path.join(OUT_DIR, 'h-peerdep-added'),
    'ui-toolkit',
    {
      pkg: { name: 'ui-toolkit', version: '4.0.0', main: 'index.js', license: 'MIT' },
      files: { 'index.js': "exports.Button = () => 'button';\n" },
    },
    {
      pkg: {
        name: 'ui-toolkit',
        version: '4.0.1',
        main: 'index.js',
        license: 'MIT',
        peerDependencies: { react: '>=18' },
      },
      files: { 'index.js': "exports.Button = () => 'button';\n" },
    },
  );

  console.log('FP smoke corpus built:');
  console.log(`  ${path.join(OUT_DIR, 'a-docs-only')}`);
  console.log(`  ${path.join(OUT_DIR, 'b-feature-bump')}`);
  console.log(`  ${path.join(OUT_DIR, 'c-types-only')}`);
  console.log(`  ${path.join(OUT_DIR, 'd-refactor')}`);
  console.log(`  ${path.join(OUT_DIR, 'e-license-fix')}`);
  console.log(`  ${path.join(OUT_DIR, 'f-added-tests')}`);
  console.log(`  ${path.join(OUT_DIR, 'g-bugfix')}`);
  console.log(`  ${path.join(OUT_DIR, 'h-peerdep-added')}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
