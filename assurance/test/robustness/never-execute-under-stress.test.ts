/**
 * @critical — assurance-level extension of the engine's never-execute-canary.
 *
 * The engine's canary (packages/core/test/never-execute-canary.test.ts) proves that
 * `analyzeTarball` does not execute a MINIMAL hostile fixture — a preinstall/postinstall
 * pair plus three .js file bodies that would each write a sentinel if invoked.
 *
 * This test extends that invariant to a MAXIMALLY hostile fixture: every documented
 * npm lifecycle hook, an import-side-effect body in every .js file, a `main` entry
 * pointing at a sentinel writer, multiple `bin` entries, a native `.node` artifact,
 * and a `.wasm` artifact. Then it runs the analysis ten times sequentially — because
 * a late-firing or racy execution path (e.g. cleanup running the postinstall on a
 * final `finally`) could plausibly only appear under repeated stress.
 *
 * See packet rule #3 (NEVER-EXECUTE) and root docs/adr/0005-never-execute.md.
 *
 * Option A (in-process invocation, no runBounded)
 * ------------------------------------------------
 * `analyzeTarball` is invoked directly rather than through `runBounded` /
 * `engine:...`. This is a legitimate exception because NEVER-EXECUTE is a STATIC
 * invariant: ADR 0005 says no code from an analyzed tarball ever runs. The whole
 * assertion here is "no code runs from the tarball" — sandboxing the caller adds
 * nothing to that assertion. The engine's own canary uses the same in-process shape
 * for the same reason. Running in-process also gives us the strongest signal: if a
 * later change introduced a covert execution path, we want the sentinel write to
 * happen in THIS process, where we can observe it, rather than be swallowed by a
 * worker's cleanup.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { promises as fs } from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as crypto from 'node:crypto';
import { analyzeTarball, type PackageSnapshot } from '@vetlock/core';
import { writeTempTgz } from '../../../packages/core/test/tgz-builder.js';

const SENTINEL_PATH = path.join(
  os.tmpdir(),
  `vetlock-assurance-canary-${crypto.randomBytes(8).toString('hex')}`,
);

/**
 * Body used for every regular .js file. If the engine required() or eval()'d the
 * file, the top-level require('fs').writeFileSync would fire an import side effect.
 */
const sentinelWriter = `
const fs = require('fs');
try { fs.writeFileSync(${JSON.stringify(SENTINEL_PATH)}, 'PWNED-import', { flag: 'a' }); } catch (e) {}
module.exports = { hello: 'world' };
`;

/** Body for the file referenced by manifest.main. Sentinel on import. */
const mainSentinelWriter = `
require('fs').writeFileSync(${JSON.stringify(SENTINEL_PATH)}, 'PWNED-main');
module.exports = {};
`;

/** Body for each file referenced by manifest.bin. Sentinel on invocation OR import. */
const binSentinelWriter = `
// shebang omitted — babel parser handles either, but we don't need it for the test
require('fs').writeFileSync(${JSON.stringify(SENTINEL_PATH)}, 'PWNED-bin');
`;

/**
 * package.json wired to maximise the number of npm-invocation vectors:
 *   - `main` -> a sentinel writer
 *   - `bin`  -> two sentinel writers
 *   - `scripts` -> every documented lifecycle hook that npm would run at install
 *                  time, plus prepare / prepublish that publishers run at publish.
 * Every script body attempts to write a distinct sentinel tag, so a failure would
 * also tell us WHICH hook fired.
 */
const pkgJson = JSON.stringify(
  {
    name: 'assurance-canary-pkg',
    version: '0.0.1',
    main: 'index.js',
    bin: {
      'hostile-tool-a': 'bin/a.js',
      'hostile-tool-b': 'bin/b.js',
    },
    scripts: {
      preinstall: `node -e "require('fs').writeFileSync('${SENTINEL_PATH}', 'PWNED-preinstall')"`,
      install: `node -e "require('fs').writeFileSync('${SENTINEL_PATH}', 'PWNED-install')"`,
      postinstall: `node -e "require('fs').writeFileSync('${SENTINEL_PATH}', 'PWNED-postinstall')"`,
      prepare: `node -e "require('fs').writeFileSync('${SENTINEL_PATH}', 'PWNED-prepare')"`,
      prepublish: `node -e "require('fs').writeFileSync('${SENTINEL_PATH}', 'PWNED-prepublish')"`,
    },
  },
  null,
  2,
);

/**
 * Minimal-but-valid WASM header (`\0asm` + version 1). The engine's summarizeWasm
 * parses this statically to enumerate imports; it never calls WebAssembly.instantiate.
 * The point is to prove instantiation is not attempted — the body is intentionally
 * incomplete because parsers should NEVER fall back to execution to make sense of it.
 */
const wasmBytes = Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);

/**
 * Empty `.node` addon. The engine records it as a native artifact; it must never
 * be handed to `process.dlopen` or otherwise loaded.
 */
const nodeBytes = Buffer.alloc(0);

async function buildHostileTgz(): Promise<string> {
  return writeTempTgz([
    { name: 'package/package.json', content: Buffer.from(pkgJson) },
    { name: 'package/index.js', content: Buffer.from(mainSentinelWriter) },
    { name: 'package/lib/util.js', content: Buffer.from(sentinelWriter) },
    { name: 'package/lib/inner/deeper.js', content: Buffer.from(sentinelWriter) },
    { name: 'package/bin/a.js', content: Buffer.from(binSentinelWriter) },
    { name: 'package/bin/b.js', content: Buffer.from(binSentinelWriter) },
    { name: 'package/native/addon.node', content: nodeBytes },
    { name: 'package/wasm/mod.wasm', content: wasmBytes },
  ]);
}

async function sentinelExists(): Promise<boolean> {
  try {
    await fs.access(SENTINEL_PATH);
    return true;
  } catch {
    return false;
  }
}

beforeAll(async () => {
  // Defensive: no prior run should have left the sentinel behind (SENTINEL_PATH
  // is randomised per run), but we clear it anyway so the assertions are honest.
  await fs.unlink(SENTINEL_PATH).catch(() => {});
});

afterAll(async () => {
  await fs.unlink(SENTINEL_PATH).catch(() => {});
});

describe('NEVER-EXECUTE under stress (@critical)', () => {
  it('sentinel is not written after analyzing maximally-hostile tarball', async () => {
    const tgz = await buildHostileTgz();
    const snap = await analyzeTarball(tgz);
    // Analysis must have succeeded — otherwise we wouldn't have proven the engine
    // even reached the hostile shapes.
    expect(snap.name).toBe('assurance-canary-pkg');
    expect(snap.version).toBe('0.0.1');
    // And the sentinel must NOT exist.
    expect(await sentinelExists()).toBe(false);
  });

  it('sentinel is not written after 10 sequential analyses (under stress)', async () => {
    for (let i = 0; i < 10; i++) {
      const tgz = await buildHostileTgz();
      await analyzeTarball(tgz);
      // Check inside the loop so a late-firing execution path is attributed to
      // the iteration that caused it, not blamed on the final one.
      if (await sentinelExists()) {
        throw new Error(
          `Sentinel appeared after iteration ${i + 1} of 10 — NEVER-EXECUTE violated.`,
        );
      }
    }
    expect(await sentinelExists()).toBe(false);
  });

  it('snapshot exposes all hostile scripts + artifacts (proves engine did analyze them)', async () => {
    const tgz = await buildHostileTgz();
    const snap: PackageSnapshot = await analyzeTarball(tgz);

    // Every lifecycle hook must appear verbatim in the manifest — detectors need
    // them to fire INSTALL findings. "Analyzed but not executed" is the whole
    // point: the strings ride through unchanged.
    const scripts = snap.manifest.scripts ?? {};
    for (const hook of ['preinstall', 'install', 'postinstall', 'prepare', 'prepublish']) {
      expect(scripts[hook], `manifest.scripts.${hook} missing`).toBeDefined();
      expect(scripts[hook]).toContain('PWNED-');
    }

    // main + bin round-trip.
    expect(snap.manifest.main).toBe('index.js');
    expect(snap.manifest.bin).toEqual({
      'hostile-tool-a': 'bin/a.js',
      'hostile-tool-b': 'bin/b.js',
    });

    // Every .js body was reached by the capability extractor.
    const jsPaths = snap.files.map((f) => f.path).sort();
    expect(jsPaths).toContain('index.js');
    expect(jsPaths).toContain('lib/util.js');
    expect(jsPaths).toContain('lib/inner/deeper.js');
    expect(jsPaths).toContain('bin/a.js');
    expect(jsPaths).toContain('bin/b.js');

    // Native artifacts recorded — the .node and .wasm entries are visible without
    // ever having been loaded / instantiated.
    const nativePaths = snap.nativeArtifacts.map((a) => a.path).sort();
    expect(nativePaths).toContain('native/addon.node');
    expect(nativePaths).toContain('wasm/mod.wasm');
    const kinds = new Set(snap.nativeArtifacts.map((a) => a.kind));
    expect(kinds.has('node')).toBe(true);
    expect(kinds.has('wasm')).toBe(true);

    // And, once more, the sentinel invariant. This third check is redundant with
    // the first test but cheap, and having it here makes the "engine analyzed
    // vs. engine executed" contrast obvious at the assertion site.
    expect(await sentinelExists()).toBe(false);
  });
});
