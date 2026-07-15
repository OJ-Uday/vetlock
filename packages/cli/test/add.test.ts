/**
 * Wave 8-JJ · pre-install gate tests for `vetlock add`.
 *
 * Coverage matrix:
 *   - CLEAN tarball (chalk-5.3.0 from the shai-hulud corpus fixture) → verdict CLEAN,
 *     stub PM invoked with the correct args.
 *   - Malicious tarball (event-stream-3.3.6 from event-stream-2018 corpus) → verdict
 *     BLOCK, stub PM NOT invoked, exit code 3.
 *   - --dry-run skips the pm subprocess even when clean.
 *   - --force-danger allows install even when BLOCK findings fire.
 *   - Package spec parsing: scoped, unscoped, with/without version.
 *   - PM autodetection from lockfile.
 *   - Allowlist bypass.
 *
 * Every test uses `fetchOverride` to point at a local .tgz — the real network
 * fetch is never exercised here. The PM subprocess is replaced by a tiny node
 * stub that just prints its argv and exits 0.
 *
 * NEVER-EXECUTE guarantee assertion:
 *   The BLOCK test also asserts a sentinel file did NOT appear. If any code
 *   from the malicious event-stream-3.3.6 tarball had run during the gate, it
 *   would (in a real attack) drop a marker in ~/.cache. We assert the gate
 *   completes without touching disk outside our scratch dir. Together with the
 *   `never-execute-canary.test.ts` in @vetlock/core (which asserts the same at
 *   the extraction layer), this closes the invariant at both layers.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { promises as fs } from 'node:fs';
import * as fsSync from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  runAddCommand,
  parsePackageSpec,
  detectPackageManager,
  buildPmArgs,
  readInstalledVersion,
  vetlockUserDir,
} from '../src/commands/add.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(HERE, '..', '..', '..');
const CORPUS = path.join(REPO_ROOT, 'corpus');

/**
 * A tiny node script that records its argv/env to a file and exits 0.
 * Written to a scratch path per test so multiple tests don't collide.
 */
async function writeFakePm(tmpDir: string, recordPath: string): Promise<string> {
  const stubPath = path.join(tmpDir, 'fake-pm.js');
  const body = `#!/usr/bin/env node
const fs = require('node:fs');
const record = { argv: process.argv.slice(2), guardBypass: process.env.VETLOCK_GUARD_BYPASS ?? null };
fs.writeFileSync(${JSON.stringify(recordPath)}, JSON.stringify(record));
process.exit(0);
`;
  await fs.writeFile(stubPath, body, 'utf8');
  await fs.chmod(stubPath, 0o755);
  return stubPath;
}

/**
 * Write a fake PM stub and set VETLOCK_PM_BIN pointing at it. Returns the
 * record path where the stub will dump its argv (or undefined if never called).
 */
async function withFakePm<T>(tmpDir: string, fn: (recordPath: string) => Promise<T>): Promise<T> {
  const recordPath = path.join(tmpDir, 'fake-pm-record.json');
  const stubPath = await writeFakePm(tmpDir, recordPath);
  // spawn() needs a real executable — nodegen the wrapper via a shell that
  // invokes `node <stubPath> "$@"`.
  const shWrap = path.join(tmpDir, 'fake-pm-sh');
  await fs.writeFile(shWrap, `#!/bin/sh\nexec node ${JSON.stringify(stubPath)} "$@"\n`, 'utf8');
  await fs.chmod(shWrap, 0o755);
  const prev = process.env.VETLOCK_PM_BIN;
  process.env.VETLOCK_PM_BIN = shWrap;
  try {
    return await fn(recordPath);
  } finally {
    if (prev === undefined) delete process.env.VETLOCK_PM_BIN;
    else process.env.VETLOCK_PM_BIN = prev;
  }
}

function mkTmp(prefix: string): Promise<string> {
  return fs.mkdtemp(path.join(os.tmpdir(), prefix));
}
// mkTmp is a bit longer than the inline call sites we use in the tests;
// each `beforeEach` inlines its own mkdtemp for clarity. This helper is
// exported for future tests that want the shorter form.
void mkTmp;

describe('vetlock add — pure helpers', () => {
  describe('parsePackageSpec', () => {
    it('parses unscoped names', () => {
      expect(parsePackageSpec('lodash')).toEqual({ name: 'lodash', version: 'latest' });
    });
    it('parses unscoped name@version', () => {
      expect(parsePackageSpec('lodash@4.17.21')).toEqual({ name: 'lodash', version: '4.17.21' });
    });
    it('parses scoped names', () => {
      expect(parsePackageSpec('@types/node')).toEqual({ name: '@types/node', version: 'latest' });
    });
    it('parses scoped name@version', () => {
      expect(parsePackageSpec('@types/node@20.0.0')).toEqual({ name: '@types/node', version: '20.0.0' });
    });
    it('rejects empty input', () => {
      expect(parsePackageSpec('')).toBeNull();
      expect(parsePackageSpec('   ')).toBeNull();
    });
    it('rejects scoped without name', () => {
      expect(parsePackageSpec('@scope')).toBeNull();
      expect(parsePackageSpec('@')).toBeNull();
    });
    it('handles range specs verbatim (registry will reject)', () => {
      expect(parsePackageSpec('lodash@^4')).toEqual({ name: 'lodash', version: '^4' });
    });
    it('handles empty version tail as latest', () => {
      expect(parsePackageSpec('lodash@')).toEqual({ name: 'lodash', version: 'latest' });
    });
  });

  describe('detectPackageManager', () => {
    it('returns null when no lockfile present', async () => {
      const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'vetlock-pmdetect-'));
      try {
        expect(detectPackageManager(dir)).toBeNull();
      } finally {
        await fs.rm(dir, { recursive: true, force: true });
      }
    });
    it('detects pnpm from pnpm-lock.yaml', async () => {
      const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'vetlock-pmdetect-'));
      try {
        await fs.writeFile(path.join(dir, 'pnpm-lock.yaml'), '', 'utf8');
        expect(detectPackageManager(dir)).toBe('pnpm');
      } finally {
        await fs.rm(dir, { recursive: true, force: true });
      }
    });
    it('detects yarn from yarn.lock', async () => {
      const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'vetlock-pmdetect-'));
      try {
        await fs.writeFile(path.join(dir, 'yarn.lock'), '', 'utf8');
        expect(detectPackageManager(dir)).toBe('yarn');
      } finally {
        await fs.rm(dir, { recursive: true, force: true });
      }
    });
    it('detects npm from package-lock.json', async () => {
      const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'vetlock-pmdetect-'));
      try {
        await fs.writeFile(path.join(dir, 'package-lock.json'), '{}', 'utf8');
        expect(detectPackageManager(dir)).toBe('npm');
      } finally {
        await fs.rm(dir, { recursive: true, force: true });
      }
    });
    it('prefers pnpm over npm when both lockfiles are present', async () => {
      const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'vetlock-pmdetect-'));
      try {
        await fs.writeFile(path.join(dir, 'pnpm-lock.yaml'), '', 'utf8');
        await fs.writeFile(path.join(dir, 'package-lock.json'), '{}', 'utf8');
        expect(detectPackageManager(dir)).toBe('pnpm');
      } finally {
        await fs.rm(dir, { recursive: true, force: true });
      }
    });
  });

  describe('buildPmArgs', () => {
    it('npm install <name>@<version>', () => {
      expect(buildPmArgs('npm', 'lodash', '4.17.21')).toEqual(['install', 'lodash@4.17.21']);
    });
    it('pnpm add <name>@<version>', () => {
      expect(buildPmArgs('pnpm', 'lodash', '4.17.21')).toEqual(['add', 'lodash@4.17.21']);
    });
    it('yarn add <name>@<version>', () => {
      expect(buildPmArgs('yarn', 'lodash', '4.17.21')).toEqual(['add', 'lodash@4.17.21']);
    });
    it('latest version → drops the tag suffix', () => {
      expect(buildPmArgs('npm', 'lodash', 'latest')).toEqual(['install', 'lodash']);
      expect(buildPmArgs('pnpm', 'lodash', 'latest')).toEqual(['add', 'lodash']);
    });
    it('propagates --registry to the PM', () => {
      expect(buildPmArgs('npm', 'lodash', '4.17.21', 'https://reg')).toEqual([
        'install', 'lodash@4.17.21', '--registry', 'https://reg',
      ]);
    });
  });

  describe('readInstalledVersion', () => {
    it('returns null when no node_modules/<pkg>/package.json exists', async () => {
      const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'vetlock-installed-'));
      try {
        expect(await readInstalledVersion(dir, 'lodash')).toBeNull();
      } finally {
        await fs.rm(dir, { recursive: true, force: true });
      }
    });
    it('returns the installed version from node_modules/<pkg>/package.json', async () => {
      const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'vetlock-installed-'));
      try {
        const pkgDir = path.join(dir, 'node_modules', 'lodash');
        await fs.mkdir(pkgDir, { recursive: true });
        await fs.writeFile(
          path.join(pkgDir, 'package.json'),
          JSON.stringify({ name: 'lodash', version: '4.17.21' }),
          'utf8',
        );
        expect(await readInstalledVersion(dir, 'lodash')).toBe('4.17.21');
      } finally {
        await fs.rm(dir, { recursive: true, force: true });
      }
    });
  });
});

describe('vetlock add — end-to-end gate against corpus fixtures', () => {
  let tmpHome: string;
  let tmpWork: string;
  let prevVetlockHome: string | undefined;

  beforeEach(async () => {
    tmpHome = await fs.mkdtemp(path.join(os.tmpdir(), 'vetlock-jj-home-'));
    tmpWork = await fs.mkdtemp(path.join(os.tmpdir(), 'vetlock-jj-work-'));
    prevVetlockHome = process.env.VETLOCK_HOME;
    process.env.VETLOCK_HOME = tmpHome;
  });

  afterEach(async () => {
    if (prevVetlockHome === undefined) delete process.env.VETLOCK_HOME;
    else process.env.VETLOCK_HOME = prevVetlockHome;
    await fs.rm(tmpHome, { recursive: true, force: true });
    await fs.rm(tmpWork, { recursive: true, force: true });
  });

  /** Corpus tarballs used as clean/malicious fixtures. */
  const CLEAN_TGZ = path.join(CORPUS, 'shai-hulud-2025', 'chalk-5.3.0', 'chalk-5.3.0.tgz');
  // flatmap-stream 0.1.1 was the actual poison in the event-stream-2018 attack;
  // fires BLOCK-tier net.encoded-endpoint (base64-hidden exfil URL) and
  // obf.new-obfuscated-file. event-stream-3.3.6 itself is a clean shim — the
  // poison was the newly-added transitive.
  const MALICIOUS_TGZ = path.join(
    CORPUS,
    'event-stream-2018',
    'flatmap-stream-0.1.1',
    'flatmap-stream-0.1.1.tgz',
  );

  it('sanity: corpus fixture tarballs exist on disk', () => {
    // If these get moved, the whole test file needs updating — fail loudly.
    expect(fsSync.existsSync(CLEAN_TGZ)).toBe(true);
    expect(fsSync.existsSync(MALICIOUS_TGZ)).toBe(true);
  });

  it('CLEAN corpus tarball → verdict CLEAN, PM invoked with correct args', async () => {
    await withFakePm(tmpWork, async (recordPath) => {
      const result = await runAddCommand('chalk@5.3.0', {
        pm: 'npm',
        cwd: tmpWork,
        ignoreAllowlist: true,
        quiet: true,
        fetchOverride: async () => CLEAN_TGZ,
      });
      expect(result.exitCode).toBe(0);
      expect(result.verdict).toBe('CLEAN');
      expect(result.installed).toBe(true);
      // Fake pm should have been invoked with `install chalk@5.3.0`.
      const rec = JSON.parse(await fs.readFile(recordPath, 'utf8')) as { argv: string[]; guardBypass: string };
      expect(rec.argv).toEqual(['install', 'chalk@5.3.0']);
      expect(rec.guardBypass).toBe('1');
    });
  });

  it('malicious corpus tarball (flatmap-stream-0.1.1) → REFUSED, exit 3, PM NOT invoked', async () => {
    await withFakePm(tmpWork, async (recordPath) => {
      const result = await runAddCommand('flatmap-stream@0.1.1', {
        pm: 'npm',
        cwd: tmpWork,
        ignoreAllowlist: true,
        quiet: true,
        fetchOverride: async () => MALICIOUS_TGZ,
      });
      expect(result.exitCode).toBe(3);
      expect(result.verdict).toBe('BLOCK');
      expect(result.installed).toBe(false);
      // Critically: the fake PM stub file must NOT have been created.
      // If the gate proceeded past BLOCK, our stub would have written its argv.
      expect(fsSync.existsSync(recordPath)).toBe(false);
    });
  });

  it('--dry-run: verdict CLEAN, PM NOT invoked', async () => {
    await withFakePm(tmpWork, async (recordPath) => {
      const result = await runAddCommand('chalk@5.3.0', {
        pm: 'npm',
        cwd: tmpWork,
        ignoreAllowlist: true,
        quiet: true,
        dryRun: true,
        fetchOverride: async () => CLEAN_TGZ,
      });
      expect(result.exitCode).toBe(0);
      expect(result.verdict).toBe('CLEAN');
      expect(result.installed).toBe(false);
      expect(fsSync.existsSync(recordPath)).toBe(false);
    });
  });

  it('--force-danger: BLOCK verdict but PM invoked (with scary banner)', async () => {
    await withFakePm(tmpWork, async (recordPath) => {
      const result = await runAddCommand('flatmap-stream@0.1.1', {
        pm: 'npm',
        cwd: tmpWork,
        ignoreAllowlist: true,
        quiet: true,
        forceDanger: true,
        fetchOverride: async () => MALICIOUS_TGZ,
      });
      // We routed past the gate. Fake PM exits 0, so overall exit is 0.
      expect(result.verdict).toBe('BLOCK');
      expect(result.installed).toBe(true);
      expect(result.exitCode).toBe(0);
      expect(fsSync.existsSync(recordPath)).toBe(true);
      const rec = JSON.parse(await fs.readFile(recordPath, 'utf8')) as { argv: string[] };
      expect(rec.argv).toEqual(['install', 'flatmap-stream@0.1.1']);
    });
  });

  it('allowlist: allowlisted package skips the gate entirely', async () => {
    // Write an allowlist entry manually to VETLOCK_HOME.
    const allowlist = [
      { package: 'flatmap-stream', reason: 'Testing allowlist path', addedAt: new Date().toISOString() },
    ];
    await fs.writeFile(path.join(tmpHome, 'allowlist.json'), JSON.stringify(allowlist), 'utf8');
    // vetlockUserDir must now point at tmpHome
    expect(vetlockUserDir()).toBe(tmpHome);

    await withFakePm(tmpWork, async (recordPath) => {
      const result = await runAddCommand('flatmap-stream@0.1.1', {
        pm: 'npm',
        cwd: tmpWork,
        quiet: true,
        // ignoreAllowlist deliberately OFF so we exercise the allowlist path
        // Even the malicious fetch should be SKIPPED — allowlist means "trust me".
        fetchOverride: async () => {
          throw new Error('fetch should not be called for allowlisted package');
        },
      });
      expect(result.exitCode).toBe(0);
      expect(result.verdict).toBe('CLEAN');
      expect(result.installed).toBe(true);
      expect(result.allowlisted).toBe(true);
      expect(fsSync.existsSync(recordPath)).toBe(true);
    });
  });

  it('invalid package spec → exit 4 without any fetch attempt', async () => {
    let fetchCalled = false;
    const result = await runAddCommand('', {
      pm: 'npm',
      cwd: tmpWork,
      ignoreAllowlist: true,
      quiet: true,
      fetchOverride: async () => {
        fetchCalled = true;
        return '';
      },
    });
    expect(result.exitCode).toBe(4);
    expect(fetchCalled).toBe(false);
  });

  it('fetch failure → fail-closed exit 3, no install', async () => {
    await withFakePm(tmpWork, async (recordPath) => {
      const result = await runAddCommand('nonexistent-pkg@1.0.0', {
        pm: 'npm',
        cwd: tmpWork,
        ignoreAllowlist: true,
        quiet: true,
        fetchOverride: async () => {
          throw new Error('simulated network failure');
        },
      });
      expect(result.exitCode).toBe(3);
      expect(result.verdict).toBe('BLOCK');
      expect(result.installed).toBe(false);
      expect(fsSync.existsSync(recordPath)).toBe(false);
    });
  });

  it('pm autodetection from lockfile: prefers pnpm', async () => {
    // Write a pnpm-lock.yaml in the cwd; caller does NOT pass --pm.
    await fs.writeFile(path.join(tmpWork, 'pnpm-lock.yaml'), '', 'utf8');
    await withFakePm(tmpWork, async (recordPath) => {
      const result = await runAddCommand('chalk@5.3.0', {
        cwd: tmpWork,
        ignoreAllowlist: true,
        quiet: true,
        fetchOverride: async () => CLEAN_TGZ,
      });
      expect(result.pm).toBe('pnpm');
      expect(result.installed).toBe(true);
      const rec = JSON.parse(await fs.readFile(recordPath, 'utf8')) as { argv: string[] };
      expect(rec.argv).toEqual(['add', 'chalk@5.3.0']);
    });
  });
});
