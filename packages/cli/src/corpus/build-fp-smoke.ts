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

  console.log('FP smoke corpus built:');
  console.log(`  ${path.join(OUT_DIR, 'a-docs-only')}`);
  console.log(`  ${path.join(OUT_DIR, 'b-feature-bump')}`);
  console.log(`  ${path.join(OUT_DIR, 'c-types-only')}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
