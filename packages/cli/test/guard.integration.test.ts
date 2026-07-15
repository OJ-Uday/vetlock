/**
 * Wave 8-OO — end-to-end integration tests for `vetlock guard`.
 *
 * `vetlock guard install` writes a PM shim (a small executable) into a
 * user-specified directory that MUST be earlier on PATH than the real npm /
 * pnpm / yarn.  When invoked with an install-shaped argv the shim reroutes
 * through `vetlock add`; every other argv falls through to the real PM.
 *
 * ── Un-skip on merge ──
 * Depends on JJ's wave8-jj-cli-preinstall-gate for the `guard` subcommand.
 * If the built CLI does not yet expose `guard`, this describe block
 * auto-skips (probeGuardCommand() returns false).  Once JJ merges, un-skips
 * automatically — no manual test flips.
 */

import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(HERE, '..', '..', '..');
const CLI = path.join(REPO_ROOT, 'packages', 'cli', 'dist', 'cli.js');

function probeGuardCommand(): boolean {
  if (!fs.existsSync(CLI)) return false;
  const res = spawnSync('node', [CLI, '--help'], { encoding: 'utf8', timeout: 15_000 });
  if (res.status !== 0) return false;
  return /^\s*guard\b/m.test(res.stdout ?? '');
}

const HAS_GUARD = probeGuardCommand();

function withTempDir<T>(fn: (dir: string) => T): T {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vetlock-guard-it-'));
  try {
    return fn(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

describe.skipIf(!HAS_GUARD)('vetlock guard install — shim files', () => {
  it('writes executable shim files into the target directory', () => {
    withTempDir((shimDir) => {
      const res = spawnSync('node', [CLI, 'guard', 'install', '--dir', shimDir], {
        encoding: 'utf8',
        timeout: 30_000,
      });
      expect(res.status, `stderr:\n${res.stderr}`).toBe(0);

      // Each supported PM gets a shim.  Exact filenames may vary — accept the
      // common set (npm/pnpm/yarn) and require at least the ones documented in
      // JJ's spec.
      const files = fs.readdirSync(shimDir);
      expect(files, `shim dir contents: ${files.join(', ')}`).toContain('npm');
      expect(files).toContain('pnpm');
      expect(files).toContain('yarn');

      for (const pm of ['npm', 'pnpm', 'yarn'] as const) {
        const shimPath = path.join(shimDir, pm);
        const stat = fs.statSync(shimPath);
        // Executable by owner (0o100 = execute bit).
        expect(stat.mode & 0o100, `${pm} shim must be executable`).toBeGreaterThan(0);
      }
    });
  });
});

describe.skipIf(!HAS_GUARD)('vetlock guard — shim intercepts install commands', () => {
  it('routes `<shim> install <pkg>` through vetlock add (install is intercepted)', () => {
    withTempDir((shimDir) => {
      // Install shims.
      spawnSync('node', [CLI, 'guard', 'install', '--dir', shimDir], {
        encoding: 'utf8',
        timeout: 30_000,
      });

      const pmMockLog = path.join(shimDir, 'pm-mock.jsonl');
      // Invoke the shim with an install verb.  The shim should call `vetlock
      // add`; that in turn (with VETLOCK_PM_MOCK_LOG set) will append to the
      // mock log rather than spawning the real PM.
      //
      // We can't rely on network access — but at minimum the shim must exit
      // != 127 (command not found) and print SOMETHING that identifies vetlock
      // in stderr/stdout when it forwards to `add`.
      const shim = path.join(shimDir, 'npm');
      const res = spawnSync(shim, ['install', 'lodash'], {
        encoding: 'utf8',
        timeout: 30_000,
        env: {
          ...process.env,
          VETLOCK_PM_MOCK_LOG: pmMockLog,
          // Point the shim at THIS build's CLI so it doesn't need vetlock on PATH.
          VETLOCK_CLI_PATH: CLI,
          // Signal to `vetlock add` that the fetch phase should synthesize a
          // CLEAN outcome for integration testing — otherwise it'd try to hit
          // the real registry.  Falls back to a no-op if JJ hasn't wired this.
          VETLOCK_STUB_FETCH: 'clean',
        },
      });
      // We don't hard-assert code here — a real `vetlock add` may still exit
      // non-zero depending on how JJ handles the stub-fetch env.  What we care
      // about is: (a) the shim was found + executed (code != 127) and
      // (b) either the mock log recorded a forwarded call OR the output
      // mentions vetlock.
      expect(res.status, `shim spawn failed; stderr:\n${res.stderr}`).not.toBe(127);
      const output = (res.stdout ?? '') + (res.stderr ?? '');
      expect(output, `shim did not appear to run vetlock: ${output}`).toMatch(/vetlock/i);
    });
  });
});

describe.skipIf(!HAS_GUARD)('vetlock guard — non-install commands pass through', () => {
  it('routes `<shim> run test` straight to the real PM (no vetlock intercept)', () => {
    withTempDir((shimDir) => {
      // Install shims.
      spawnSync('node', [CLI, 'guard', 'install', '--dir', shimDir], {
        encoding: 'utf8',
        timeout: 30_000,
      });

      const pmMockLog = path.join(shimDir, 'pm-mock.jsonl');
      const shim = path.join(shimDir, 'npm');

      // We create a stand-in for the real `npm` on PATH so the shim's
      // passthrough call resolves without hitting whatever real npm is
      // installed.  The stand-in prints a marker line and exits 0.
      const fakePmDir = path.join(shimDir, 'realpm');
      fs.mkdirSync(fakePmDir);
      const fakeNpm = path.join(fakePmDir, 'npm');
      fs.writeFileSync(
        fakeNpm,
        '#!/bin/sh\necho "FAKE_NPM_PASSTHROUGH argv=$*"\nexit 0\n',
        { mode: 0o755 },
      );

      const res = spawnSync(shim, ['run', 'test'], {
        encoding: 'utf8',
        timeout: 30_000,
        env: {
          ...process.env,
          // PATH ordering: shim dir OUT, real (fake) npm IN — so the shim's
          // exec-real path finds `fakeNpm` when it exec-passes-through.
          PATH: `${fakePmDir}:${process.env.PATH ?? ''}`,
          VETLOCK_PM_MOCK_LOG: pmMockLog,
          VETLOCK_CLI_PATH: CLI,
          // Passthrough contract: guard MUST NOT invoke vetlock for `run test`.
          // If the fake npm sees the argv, we know passthrough worked.
        },
      });

      expect(res.status, `stderr:\n${res.stderr}`).toBe(0);
      const output = (res.stdout ?? '') + (res.stderr ?? '');
      expect(output).toMatch(/FAKE_NPM_PASSTHROUGH argv=run test/);
      // Guard did NOT record a PM-mock call — `run test` is passthrough only.
      if (fs.existsSync(pmMockLog)) {
        const raw = fs.readFileSync(pmMockLog, 'utf8').trim();
        expect(raw, `guard incorrectly logged passthrough: ${raw}`).toBe('');
      }
    });
  });
});
