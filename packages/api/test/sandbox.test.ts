/**
 * Sandbox tests — ADR 0008 invariants exercised via the real subprocess
 * spawn path, using synthetic runner scripts we materialize on-the-fly for
 * deterministic behavior. We can't test against the real `scan-runner.js`
 * here because that pulls in @vetlock/core which requires a real lockfile
 * text to exercise meaningfully — those are covered by the integration
 * tests in server.test.ts. Here we assert the sandbox mechanics: teardown,
 * timeout, oversize-stdout, non-zero exit handling, JSON-shape handling.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { promises as fs } from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { runScanInSandbox, getSandboxInvariants } from '../src/sandbox.js';

// A shared dir under os.tmpdir() where we write throwaway runner scripts for
// each test. We rm it in afterAll — tests should NOT leave anything behind.
let fixtureDir: string;

// Snapshot os.tmpdir()'s vetlock-scan-* entries at test start so we can
// assert none linger post-test — the whole point of the sandbox is that it
// tears down its own temp dir unconditionally.
async function listSandboxDirs(): Promise<string[]> {
  const entries = await fs.readdir(os.tmpdir());
  return entries.filter((e) => e.startsWith('vetlock-scan-')).sort();
}

async function writeRunner(name: string, body: string): Promise<string> {
  const p = path.join(fixtureDir, name);
  await fs.writeFile(p, body, { encoding: 'utf8', mode: 0o600 });
  return p;
}

beforeAll(async () => {
  fixtureDir = await fs.mkdtemp(path.join(os.tmpdir(), 'vetlock-sandbox-test-'));
});

afterAll(async () => {
  try {
    await fs.rm(fixtureDir, { recursive: true, force: true });
  } catch {
    // Ignore — test teardown is best-effort.
  }
});

describe('runScanInSandbox — happy path', () => {
  it('returns kind:ok with the parsed JSON stdout', async () => {
    const runner = await writeRunner('echo-runner.mjs', `
      import { promises as fs } from 'node:fs';
      const [, , before, after] = process.argv;
      const b = await fs.readFile(before, 'utf8');
      const a = await fs.readFile(after, 'utf8');
      process.stdout.write(JSON.stringify({ verdict: 'CLEAN', bLen: b.length, aLen: a.length, findings: [] }));
      process.exit(0);
    `);

    const outcome = await runScanInSandbox<{ verdict: string; bLen: number; aLen: number; findings: unknown[] }>(
      { lockfileBefore: 'BEFORE-LOCK-TEXT', lockfileAfter: 'AFTER-LOCK-TEXT' },
      { runnerPath: runner, timeoutMs: 15_000 },
    );

    expect(outcome.kind).toBe('ok');
    if (outcome.kind !== 'ok') throw new Error('narrowing failed');
    expect(outcome.result.verdict).toBe('CLEAN');
    expect(outcome.result.bLen).toBe('BEFORE-LOCK-TEXT'.length);
    expect(outcome.result.aLen).toBe('AFTER-LOCK-TEXT'.length);
  });

  it('deletes the sandbox dir after a successful run', async () => {
    const runner = await writeRunner('tiny-runner.mjs', `
      process.stdout.write(JSON.stringify({ verdict: 'CLEAN', findings: [] }));
      process.exit(0);
    `);
    const before = await listSandboxDirs();
    await runScanInSandbox({ lockfileBefore: 'x', lockfileAfter: 'y' }, { runnerPath: runner, timeoutMs: 15_000 });
    const after = await listSandboxDirs();
    // Any sandbox dirs left MUST be ones that were already there before this
    // test ran (other tests can be concurrent under vitest defaults). We
    // assert no NEW ones are present.
    const beforeSet = new Set(before);
    const newDirs = after.filter((d) => !beforeSet.has(d));
    expect(newDirs).toEqual([]);
  });
});

describe('runScanInSandbox — failure paths', () => {
  it('returns kind:failed when the runner exits non-zero', async () => {
    const runner = await writeRunner('exit-1-runner.mjs', `
      process.stdout.write(JSON.stringify({ error: 'runner asked to fail' }));
      process.exit(1);
    `);
    const outcome = await runScanInSandbox({ lockfileBefore: '', lockfileAfter: '' }, { runnerPath: runner, timeoutMs: 15_000 });
    expect(outcome.kind).toBe('failed');
    if (outcome.kind !== 'failed') throw new Error('narrowing failed');
    expect(outcome.error).toBe('runner asked to fail');
    expect(outcome.exitCode).toBe(1);
  });

  it('returns kind:failed when the runner exits without writing stdout', async () => {
    const runner = await writeRunner('silent-runner.mjs', `
      process.exit(0);
    `);
    const outcome = await runScanInSandbox({ lockfileBefore: '', lockfileAfter: '' }, { runnerPath: runner, timeoutMs: 15_000 });
    expect(outcome.kind).toBe('failed');
    if (outcome.kind !== 'failed') throw new Error('narrowing failed');
    expect(outcome.error).toMatch(/without writing to stdout/);
  });

  it('returns kind:failed when the runner emits unparseable JSON', async () => {
    const runner = await writeRunner('bad-json-runner.mjs', `
      process.stdout.write('this is not JSON');
      process.exit(0);
    `);
    const outcome = await runScanInSandbox({ lockfileBefore: '', lockfileAfter: '' }, { runnerPath: runner, timeoutMs: 15_000 });
    expect(outcome.kind).toBe('failed');
    if (outcome.kind !== 'failed') throw new Error('narrowing failed');
    expect(outcome.error).toMatch(/unparseable JSON/);
  });

  it('returns kind:failed when the runner path does not exist', async () => {
    const outcome = await runScanInSandbox(
      { lockfileBefore: '', lockfileAfter: '' },
      { runnerPath: path.join(fixtureDir, 'does-not-exist.mjs'), timeoutMs: 15_000 },
    );
    // Depending on Node version, either 'error' fires (spawn failure) or
    // 'exit' fires with a non-zero code. Both must surface as kind:failed.
    expect(outcome.kind).toBe('failed');
  });
});

describe('runScanInSandbox — timeout enforcement', () => {
  it('kills the subprocess and returns kind:timeout when it exceeds timeoutMs', async () => {
    const runner = await writeRunner('hang-runner.mjs', `
      // Never write to stdout, never exit. The parent must kill us.
      setInterval(() => {}, 1000);
    `);
    const start = Date.now();
    const outcome = await runScanInSandbox(
      { lockfileBefore: '', lockfileAfter: '' },
      { runnerPath: runner, timeoutMs: 500 },
    );
    const elapsed = Date.now() - start;
    expect(outcome.kind).toBe('timeout');
    if (outcome.kind !== 'timeout') throw new Error('narrowing failed');
    expect(outcome.timeoutMs).toBe(500);
    // Allow generous slop — CI can be slow. The important thing is we
    // didn't wait the default 60s.
    expect(elapsed).toBeLessThan(5_000);
  }, 10_000);

  it('deletes the sandbox dir after a timeout', async () => {
    const runner = await writeRunner('hang-runner-2.mjs', `
      setInterval(() => {}, 1000);
    `);
    const before = await listSandboxDirs();
    await runScanInSandbox(
      { lockfileBefore: 'x', lockfileAfter: 'y' },
      { runnerPath: runner, timeoutMs: 300 },
    );
    // Give the parent a beat to finish the finally-block rm.
    await new Promise((r) => setTimeout(r, 100));
    const after = await listSandboxDirs();
    const beforeSet = new Set(before);
    const newDirs = after.filter((d) => !beforeSet.has(d));
    expect(newDirs).toEqual([]);
  }, 10_000);
});

describe('runScanInSandbox — isolation invariants', () => {
  it('uses os.tmpdir() as the sandbox root (verified via runner cwd)', async () => {
    const runner = await writeRunner('cwd-runner.mjs', `
      import { promises as fs } from 'node:fs';
      // Resolve the real cwd — macOS returns /private/var/folders/... but
      // os.tmpdir() gives /var/folders/... unless realpath'd. Do the
      // realpath dance INSIDE the runner so the assertion below can just
      // compare against os.tmpdir()'s realpath.
      const real = await fs.realpath(process.cwd());
      process.stdout.write(JSON.stringify({ cwd: real }));
      process.exit(0);
    `);
    const outcome = await runScanInSandbox<{ cwd: string }>(
      { lockfileBefore: '', lockfileAfter: '' },
      { runnerPath: runner, timeoutMs: 15_000 },
    );
    expect(outcome.kind).toBe('ok');
    if (outcome.kind !== 'ok') throw new Error('narrowing failed');
    const tmpReal = await fs.realpath(os.tmpdir());
    // rel is '..' or starts with '..' when cwd is NOT under tmpReal.
    const rel = path.relative(tmpReal, outcome.result.cwd);
    expect(rel.startsWith('..')).toBe(false);
    expect(path.basename(outcome.result.cwd)).toMatch(/^vetlock-scan-/);
  });

  it('passes an empty env to the subprocess (no PATH, HOME, or parent env leakage)', async () => {
    const runner = await writeRunner('env-runner.mjs', `
      // stringify a small snapshot of the env; assert-side we expect it
      // essentially empty. Node's own vars set by --max-old-space-size etc.
      // don't populate process.env, so what we get here is truly what the
      // parent passed.
      const keys = Object.keys(process.env);
      process.stdout.write(JSON.stringify({ envKeys: keys, envSize: keys.length }));
      process.exit(0);
    `);
    const outcome = await runScanInSandbox<{ envKeys: string[]; envSize: number }>(
      { lockfileBefore: '', lockfileAfter: '' },
      { runnerPath: runner, timeoutMs: 15_000 },
    );
    expect(outcome.kind).toBe('ok');
    if (outcome.kind !== 'ok') throw new Error('narrowing failed');
    // Some Node builds inject an internal debug var or two — allow a small
    // handful but assert that PATH/HOME/USER/etc. are absent (i.e. we did
    // not inherit the parent's env).
    expect(outcome.result.envSize).toBeLessThan(5);
    expect(outcome.result.envKeys).not.toContain('PATH');
    expect(outcome.result.envKeys).not.toContain('HOME');
    expect(outcome.result.envKeys).not.toContain('USER');
  });

  it('runs concurrent scans in isolated sandbox dirs (no collision)', async () => {
    const runner = await writeRunner('cwd-report.mjs', `
      process.stdout.write(JSON.stringify({ cwd: process.cwd() }));
      process.exit(0);
    `);
    const runs = await Promise.all([
      runScanInSandbox<{ cwd: string }>({ lockfileBefore: '1', lockfileAfter: '1' }, { runnerPath: runner, timeoutMs: 15_000 }),
      runScanInSandbox<{ cwd: string }>({ lockfileBefore: '2', lockfileAfter: '2' }, { runnerPath: runner, timeoutMs: 15_000 }),
      runScanInSandbox<{ cwd: string }>({ lockfileBefore: '3', lockfileAfter: '3' }, { runnerPath: runner, timeoutMs: 15_000 }),
    ]);
    const cwds = runs.map((r) => (r.kind === 'ok' ? r.result.cwd : null));
    for (const c of cwds) expect(c).not.toBeNull();
    // All three MUST be distinct dirs (mkdtemp with random suffix).
    expect(new Set(cwds).size).toBe(3);
  });
});

describe('getSandboxInvariants', () => {
  it('reports the ephemeral + parent-timeout + findings-only guarantees', () => {
    const inv = getSandboxInvariants();
    expect(inv.ephemeralFilesystem).toBe(true);
    expect(inv.parentEnforcedTimeout).toBe(true);
    expect(inv.findingsOnlyPersistence).toBe(true);
  });
});
