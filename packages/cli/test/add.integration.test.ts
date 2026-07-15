/**
 * Wave 8-OO — end-to-end integration tests for `vetlock add`.
 *
 * These tests exercise the CLI's pre-install gate at subprocess level. They
 * complement JJ's unit tests (packages/cli/test/add.test.ts) by driving the
 * built CLI binary against real (defanged) corpus fixtures.
 *
 * ┌─ Coverage matrix ──────────────────────────────────────────────────────┐
 * │ #1  CLEAN     corpus/fp-smoke/*             → exit 0, verdict CLEAN    │
 * │ #2  BLOCK     corpus/event-stream-2018       → exit 3, verdict BLOCK    │
 * │ #2  BLOCK     corpus/shai-hulud-2025         → exit 3, verdict BLOCK    │
 * │ #3  BYPASS    --force-danger on malicious   → exit 0, PM invoked      │
 * │ #5  MULTI-PM  same matrix × npm/pnpm/yarn   → correct dispatch       │
 * └────────────────────────────────────────────────────────────────────────┘
 *
 * ── Un-skip on merge ──
 * These integration tests depend on JJ's wave8-jj-cli-preinstall-gate track
 * which introduces the `vetlock add <pkg>` subcommand.  If the CLI binary
 * built from this branch does NOT yet expose `add`, the entire describe
 * block auto-skips (probeAddCommand() returns false).  Once JJ's PR merges
 * to main and this branch rebases, `vetlock add` will be present and the
 * tests un-skip themselves automatically — NO manual xit / it.skip →
 * it flips required.
 *
 * ── PM subprocess mocking ──
 * `vetlock add` must, on a CLEAN or --force-danger verdict, delegate to
 * the underlying package manager (npm / pnpm / yarn install <pkg>).  We
 * MUST NOT actually run the real PM in a test — it would hit the live
 * registry.  JJ's contract exposes an env var VETLOCK_PM_MOCK_LOG=<path>
 * that, if set, causes `vetlock add` to APPEND a JSONL line describing
 * what it WOULD have invoked (argv, cwd, PM name) instead of spawning the
 * real subprocess.  All tests here use that hook, then assert on the log
 * contents.  If JJ's final shape names the env differently, adjust
 * `PM_MOCK_ENV` below — nothing else changes.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(HERE, '..', '..', '..');
const CLI = path.join(REPO_ROOT, 'packages', 'cli', 'dist', 'cli.js');
const CORPUS_ROOT = path.join(REPO_ROOT, 'corpus');

/** Env variable name JJ's add.ts recognizes to redirect PM calls into a log. */
const PM_MOCK_ENV = 'VETLOCK_PM_MOCK_LOG';

/** Env variable name JJ's add.ts recognizes to bypass the fetch phase and use
 *  a local corpus fixture as the "after" lockfile.  This is the integration-
 *  test hook: without it we'd need to boot a fake registry. */
const FIXTURE_ENV = 'VETLOCK_FIXTURE_DIR';

/**
 * Probe the built CLI binary once to see whether `add` is registered as a
 * subcommand yet.  If not, every scenario below auto-skips with a message
 * pointing at wave8-jj-cli-preinstall-gate.
 */
function probeAddCommand(): boolean {
  if (!fs.existsSync(CLI)) return false;
  const res = spawnSync('node', [CLI, '--help'], { encoding: 'utf8', timeout: 15_000 });
  if (res.status !== 0) return false;
  return /^\s*add\b/m.test(res.stdout ?? '');
}

const HAS_ADD = probeAddCommand();

function withTempDir<T>(fn: (dir: string) => T): T {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vetlock-add-it-'));
  try {
    return fn(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

interface RunResult {
  code: number | null;
  stdout: string;
  stderr: string;
  pmLog: PmMockEntry[];
}

interface PmMockEntry {
  pm: string;
  argv: string[];
  cwd?: string;
}

/**
 * Spawn `vetlock add <args>` with fixture + PM-mock env plumbing.  Returns
 * exit code, stdout, stderr, AND any PM-mock JSONL entries that add.ts
 * appended (empty array if none — that's what we assert on for BLOCK).
 */
function runAdd(args: string[], opts: { fixtureDir?: string; cwd?: string } = {}): RunResult {
  return withTempDir((tmp) => {
    const pmLogPath = path.join(tmp, 'pm-mock.jsonl');
    const env: NodeJS.ProcessEnv = {
      ...process.env,
      [PM_MOCK_ENV]: pmLogPath,
    };
    if (opts.fixtureDir) env[FIXTURE_ENV] = opts.fixtureDir;

    const res = spawnSync('node', [CLI, 'add', ...args, '--no-progress'], {
      encoding: 'utf8',
      timeout: 60_000,
      env,
      cwd: opts.cwd ?? tmp,
    });

    let pmLog: PmMockEntry[] = [];
    if (fs.existsSync(pmLogPath)) {
      const raw = fs.readFileSync(pmLogPath, 'utf8').trim();
      if (raw) {
        pmLog = raw
          .split('\n')
          .filter((l) => l.trim())
          .map((l) => JSON.parse(l) as PmMockEntry);
      }
    }

    return {
      code: res.status,
      stdout: res.stdout ?? '',
      stderr: res.stderr ?? '',
      pmLog,
    };
  });
}

// ─────────────────────────────────────────────────────────────────────────
// Scenario 1 — CLEAN corpus (fp-smoke/a-docs-only)
// ─────────────────────────────────────────────────────────────────────────
describe.skipIf(!HAS_ADD)('vetlock add — CLEAN (fp-smoke)', () => {
  it('exits 0 on a docs-only bump and delegates to the PM', () => {
    const fixture = path.join(CORPUS_ROOT, 'fp-smoke', 'a-docs-only');
    const r = runAdd(['lodash-lite'], { fixtureDir: fixture });

    expect(r.code, `stderr:\n${r.stderr}`).toBe(0);
    // CLEAN in either machine-readable or human-readable form.
    expect(r.stdout + r.stderr).toMatch(/CLEAN/i);
    // PM subprocess IS invoked on CLEAN — that's the whole point of the wrapper.
    expect(r.pmLog.length).toBeGreaterThan(0);
    expect(r.pmLog[0].argv.join(' ')).toMatch(/lodash-lite/);
  });
});

// ─────────────────────────────────────────────────────────────────────────
// Scenario 2 — BLOCK on malicious corpus (event-stream, shai-hulud)
// ─────────────────────────────────────────────────────────────────────────
describe.skipIf(!HAS_ADD)('vetlock add — BLOCK (malicious corpus)', () => {
  it('blocks event-stream-2018 (T2 transitive injection) with exit 3', () => {
    const fixture = path.join(CORPUS_ROOT, 'event-stream-2018');
    const r = runAdd(['event-stream'], { fixtureDir: fixture });

    expect(r.code, `expected exit 3 (BLOCK); stderr:\n${r.stderr}`).toBe(3);
    const output = r.stdout + r.stderr;
    expect(output).toMatch(/BLOCK/);
    // Human-readable output must include at least one of the finding classes
    // event-stream 2018's manifest lists as must-fire.
    expect(output).toMatch(/(new-direct-dep|maintainer-change|deps\.|meta\.)/i);
    // Severity signal (BLOCK is severity, verdict).
    expect(output).toMatch(/BLOCK/);
    // PM subprocess is NOT invoked — this is the pre-install gate's contract.
    expect(r.pmLog, `pm-mock unexpectedly received: ${JSON.stringify(r.pmLog)}`).toEqual([]);
  });

  it('blocks shai-hulud-2025 (T1 maintainer takeover + worm) with exit 3', () => {
    const fixture = path.join(CORPUS_ROOT, 'shai-hulud-2025');
    const r = runAdd(['chalk'], { fixtureDir: fixture });

    expect(r.code, `expected exit 3 (BLOCK); stderr:\n${r.stderr}`).toBe(3);
    const output = r.stdout + r.stderr;
    expect(output).toMatch(/BLOCK/);
    // At least one of shai-hulud's characteristic detectors surfaces.
    expect(output).toMatch(/(install\.script-added|env\.token-harvest|net\.new-endpoint|maintainer-change)/);
    expect(r.pmLog).toEqual([]);
  });
});

// ─────────────────────────────────────────────────────────────────────────
// Scenario 3 — --force-danger bypass
// ─────────────────────────────────────────────────────────────────────────
describe.skipIf(!HAS_ADD)('vetlock add --force-danger — bypass', () => {
  it('still prints the BLOCK banner but returns exit 0 and invokes the PM', () => {
    const fixture = path.join(CORPUS_ROOT, 'shai-hulud-2025');
    const r = runAdd(['chalk', '--force-danger'], { fixtureDir: fixture });

    // Bypass succeeded — real add would proceed.
    expect(r.code, `stderr:\n${r.stderr}`).toBe(0);
    // The scary banner MUST still be printed so the human knows what they did.
    // Accept either literal "BLOCK", "DANGER", or "OVERRIDE" as the banner
    // signal — JJ's exact wording may vary; the point is the user sees it.
    const output = r.stdout + r.stderr;
    expect(output).toMatch(/BLOCK|DANGER|FORCE|OVERRIDE/i);
    // PM WAS invoked (bypass works).
    expect(r.pmLog.length).toBeGreaterThan(0);
    expect(r.pmLog[0].argv.join(' ')).toMatch(/chalk/);
  });
});

// ─────────────────────────────────────────────────────────────────────────
// Scenario 5 — Multi-PM detection & dispatch
//
// vetlock detects the ambient PM from the lockfile present in the cwd:
//   package-lock.json  → npm
//   pnpm-lock.yaml     → pnpm
//   yarn.lock          → yarn
// This test seeds each lockfile shape in a fresh tmp cwd, runs `vetlock add`
// against the CLEAN fp-smoke fixture, and asserts the PM-mock log records
// the correct downstream PM.
// ─────────────────────────────────────────────────────────────────────────
describe.skipIf(!HAS_ADD)('vetlock add — multi-PM dispatch', () => {
  const MATRIX: Array<{ pm: 'npm' | 'pnpm' | 'yarn'; lockfileName: string; lockfileBody: string }> = [
    {
      pm: 'npm',
      lockfileName: 'package-lock.json',
      lockfileBody: JSON.stringify({ name: 'app', version: '1.0.0', lockfileVersion: 3, packages: { '': { name: 'app', version: '1.0.0' } } }),
    },
    {
      pm: 'pnpm',
      lockfileName: 'pnpm-lock.yaml',
      lockfileBody: `lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies: {}\npackages: {}\n`,
    },
    {
      pm: 'yarn',
      lockfileName: 'yarn.lock',
      lockfileBody: `# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\n# yarn lockfile v1\n\n`,
    },
  ];

  it.each(MATRIX)('detects $pm from $lockfileName and dispatches correctly', ({ pm, lockfileName, lockfileBody }) => {
    withTempDir((cwd) => {
      // Seed the ambient lockfile.
      fs.writeFileSync(path.join(cwd, lockfileName), lockfileBody);
      // Also add a package.json so PM detection is realistic.
      fs.writeFileSync(path.join(cwd, 'package.json'), JSON.stringify({ name: 'test', version: '1.0.0' }));

      const fixture = path.join(CORPUS_ROOT, 'fp-smoke', 'a-docs-only');
      const r = runAdd(['lodash-lite'], { fixtureDir: fixture, cwd });

      expect(r.code, `pm=${pm}; stderr:\n${r.stderr}`).toBe(0);
      expect(r.pmLog.length).toBeGreaterThan(0);
      expect(r.pmLog[0].pm).toBe(pm);
    });
  });
});
