/**
 * Corpus builder — reads FixtureSpec values and emits, per fixture:
 *   corpus/<id>/
 *     manifest.json                — echoes the spec metadata + integrity hashes
 *     lockfile.before.json         — root project depending on the clean version
 *     lockfile.after.json          — same root project, resolved to malicious
 *     <name>-<v_old>/<pkg>.tgz     — the clean tarball
 *     <name>-<v_new>/<pkg>.tgz     — the malicious tarball
 *
 * Every URL literal in every fixture must resolve to a reserved/invalid TLD;
 * corpus-defanged.test.ts (added below) enforces this by grepping the resulting
 * files at test time.
 */

import * as tar from 'tar';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as crypto from 'node:crypto';
import type { FixtureSpec, PackageDefinition } from './fixture-spec.js';

// Import all fixture specs statically — this is deterministic and gives the
// TypeScript compiler visibility into the shape.
import { spec as eslintScope } from './fixtures/eslint-scope-2018.js';
import { spec as eventStream, transitiveSpec as eventStreamChild } from './fixtures/event-stream-2018.js';
import { spec as uaParser } from './fixtures/ua-parser-2021.js';
import { spec as coaRc } from './fixtures/coa-rc-2021.js';
import { spec as colors } from './fixtures/colors-2022.js';
import { spec as nodeIpc } from './fixtures/node-ipc-2022.js';
import { spec as solanaWeb3 } from './fixtures/solana-web3-2024.js';
import { spec as lottiePlayer } from './fixtures/lottie-player-2024.js';
import { spec as randUserAgent } from './fixtures/rand-user-agent-2025.js';
import { spec as integrityTamper } from './fixtures/integrity-tamper-synthetic.js';
import { spec as typosquat } from './fixtures/typosquat-synthetic.js';
import { spec as hardenedEvader } from './fixtures/hardened-evader-2026.js';

// The Shai-Hulud fixture predates the DSL — it's still built by its own script.
// The replay runner picks up ALL corpus/<id>/manifest.json entries so it's
// included automatically.

export const ALL_FIXTURES: FixtureSpec[] = [
  eslintScope,
  eventStream,
  uaParser,
  coaRc,
  colors,
  nodeIpc,
  solanaWeb3,
  lottiePlayer,
  randUserAgent,
  integrityTamper,
  typosquat,
  hardenedEvader,
];

const CORPUS_ROOT = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '..', '..', '..', '..',
  'corpus',
);

async function makeTarball(
  outDir: string,
  pkg: PackageDefinition,
): Promise<{ path: string; integrity: string }> {
  fs.mkdirSync(outDir, { recursive: true });
  const stageBase = path.join(CORPUS_ROOT, '_meta', '.stage');
  fs.mkdirSync(stageBase, { recursive: true });
  const stage = fs.mkdtempSync(path.join(stageBase, 's-'));
  const pkgDir = path.join(stage, 'package');
  fs.mkdirSync(pkgDir, { recursive: true });
  fs.writeFileSync(path.join(pkgDir, 'package.json'), JSON.stringify(pkg.manifest, null, 2));
  for (const [name, content] of Object.entries(pkg.files)) {
    const p = path.join(pkgDir, name);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, content);
  }
  const tarballPath = path.join(outDir, `${sanitize(pkg.name)}-${pkg.version}.tgz`);
  await tar.c({ gzip: true, file: tarballPath, cwd: stage, portable: true }, ['package']);
  const buf = fs.readFileSync(tarballPath);
  const hash = crypto.createHash('sha512').update(buf).digest('base64');
  fs.rmSync(stage, { recursive: true, force: true });
  return { path: tarballPath, integrity: `sha512-${hash}` };
}

function sanitize(s: string): string {
  return s.replace(/[^A-Za-z0-9._-]/g, '_');
}

async function buildFixture(spec: FixtureSpec): Promise<void> {
  const dir = path.join(CORPUS_ROOT, spec.id);
  fs.mkdirSync(dir, { recursive: true });

  const cleanTgz = await makeTarball(
    path.join(dir, `${sanitize(spec.clean.name)}-${spec.clean.version}`),
    spec.clean,
  );
  const malTgz = await makeTarball(
    path.join(dir, `${sanitize(spec.malicious.name)}-${spec.malicious.version}`),
    spec.malicious,
  );

  // Special handling for event-stream: attach flatmap-stream as a transitive
  // in the after-lockfile.
  const transitives: Array<{ pkg: PackageDefinition; integrity: string; path: string }> = [];
  if (spec.id === 'event-stream-2018') {
    const child = eventStreamChild.malicious;
    const childTgz = await makeTarball(
      path.join(dir, `${sanitize(child.name)}-${child.version}`),
      child,
    );
    transitives.push({ pkg: child, integrity: childTgz.integrity, path: childTgz.path });
  }

  // Build the before/after lockfiles.
  // Special case: typosquat — the clean and malicious are DIFFERENT package
  // names (my-app root vs crossenv new dep). The "before" lockfile has just
  // the app; "after" adds crossenv.
  let before: unknown, after: unknown;
  if (spec.id === 'typosquat-synthetic') {
    // Build the app tarball at both versions (before/after) — same content, only
    // the app's own dep list differs.
    const appClean = await makeTarball(
      path.join(dir, `my-app-1.0.0`),
      { name: 'my-app', version: '1.0.0', manifest: { name: 'my-app', version: '1.0.0' }, files: { 'index.js': '' } },
    );
    const appAfter = await makeTarball(
      path.join(dir, `my-app-1.0.1`),
      { name: 'my-app', version: '1.0.1', manifest: { name: 'my-app', version: '1.0.1', dependencies: { crossenv: '^1' } }, files: { 'index.js': "require('crossenv');" } },
    );
    before = {
      name: 'my-app', version: '1.0.0', lockfileVersion: 3,
      packages: {
        '': { name: 'my-app', version: '1.0.0', dependencies: {} },
      },
    };
    after = {
      name: 'my-app', version: '1.0.1', lockfileVersion: 3,
      packages: {
        '': { name: 'my-app', version: '1.0.1', dependencies: { crossenv: '^1' } },
        'node_modules/crossenv': {
          name: 'crossenv', version: '1.0.0',
          integrity: malTgz.integrity, resolved: `file://${malTgz.path}`,
        },
      },
    };
    // Reference the app tarballs to keep tree connected (they're only used as
    // markers here; the app itself isn't analyzed as a changed package).
    void appClean; void appAfter;
  } else {
    // Standard case: root depends on the target package; version bumps clean->mal.
    const rootDeps: Record<string, string> = { [spec.clean.name]: '^1' };
    before = {
      name: 'my-app', version: '1.0.0', lockfileVersion: 3,
      packages: {
        '': { name: 'my-app', version: '1.0.0', dependencies: rootDeps },
        [`node_modules/${spec.clean.name}`]: {
          name: spec.clean.name, version: spec.clean.version,
          integrity: cleanTgz.integrity, resolved: `file://${cleanTgz.path}`,
          dependencies: (spec.clean.manifest as { dependencies?: Record<string, string> }).dependencies,
        },
      },
    };
    const afterPackages: Record<string, unknown> = {
      '': { name: 'my-app', version: '1.0.0', dependencies: rootDeps },
      [`node_modules/${spec.malicious.name}`]: {
        name: spec.malicious.name, version: spec.malicious.version,
        integrity: malTgz.integrity, resolved: `file://${malTgz.path}`,
        dependencies: (spec.malicious.manifest as { dependencies?: Record<string, string> }).dependencies,
      },
    };
    for (const t of transitives) {
      afterPackages[`node_modules/${t.pkg.name}`] = {
        name: t.pkg.name, version: t.pkg.version,
        integrity: t.integrity, resolved: `file://${t.path}`,
      };
    }
    after = {
      name: 'my-app', version: '1.0.0', lockfileVersion: 3,
      packages: afterPackages,
    };
  }

  fs.writeFileSync(path.join(dir, 'lockfile.before.json'), JSON.stringify(before, null, 2));
  fs.writeFileSync(path.join(dir, 'lockfile.after.json'), JSON.stringify(after, null, 2));

  fs.writeFileSync(
    path.join(dir, 'manifest.json'),
    JSON.stringify(
      {
        id: spec.id,
        title: spec.title,
        year: spec.year,
        threatClass: spec.threatClass,
        summary: spec.summary,
        provenance: spec.provenance,
        topology: spec.topology,
        defanged: true,
        expect: spec.expect,
        packages: {
          clean: { name: spec.clean.name, version: spec.clean.version, integrity: cleanTgz.integrity },
          malicious: { name: spec.malicious.name, version: spec.malicious.version, integrity: malTgz.integrity },
          transitives: transitives.map((t) => ({
            name: t.pkg.name, version: t.pkg.version, integrity: t.integrity,
          })),
        },
      },
      null,
      2,
    ),
  );
}

async function main(): Promise<void> {
  fs.mkdirSync(path.join(CORPUS_ROOT, '_meta'), { recursive: true });
  for (const spec of ALL_FIXTURES) {
    console.log(`building ${spec.id} …`);
    await buildFixture(spec);
  }
  console.log(`built ${ALL_FIXTURES.length} fixtures.`);
  // Best-effort cleanup of any leftover stage dir
  const stageBase = path.join(CORPUS_ROOT, '_meta', '.stage');
  if (fs.existsSync(stageBase)) fs.rmSync(stageBase, { recursive: true, force: true });
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
