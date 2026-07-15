import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(HERE, '..', '..', '..');
const CLI = path.join(REPO_ROOT, 'packages', 'cli', 'dist', 'cli.js');
const WORK_ROOT = path.join(REPO_ROOT, 'packages', 'cli', 'test', '.generated', 'exit-codes');

const LOCKFILE = JSON.stringify({
  name: 'exit-code-test',
  version: '1.0.0',
  lockfileVersion: 3,
  packages: {
    '': { name: 'exit-code-test', version: '1.0.0', dependencies: {} },
  },
}, null, 2);

function withCaseDir<T>(name: string, fn: (dir: string) => T): T {
  const dir = path.join(WORK_ROOT, name);
  fs.rmSync(dir, { recursive: true, force: true });
  fs.mkdirSync(dir, { recursive: true });
  try {
    return fn(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function writeBaselinePair(dir: string): { before: string; after: string } {
  const before = path.join(dir, 'before.package-lock.json');
  const after = path.join(dir, 'after.package-lock.json');
  fs.writeFileSync(before, LOCKFILE);
  fs.writeFileSync(after, LOCKFILE);
  return { before, after };
}

function runCli(dir: string, args: string[]) {
  return spawnSync('node', [CLI, ...args], {
    cwd: dir,
    encoding: 'utf8',
    timeout: 60_000,
  });
}

describe('CLI exit code semantics', () => {
  it('returns 0 for a CLEAN verdict', () => {
    withCaseDir('clean', (dir) => {
      const { before, after } = writeBaselinePair(dir);
      const result = runCli(dir, ['diff', before, after, '--json', '--no-progress']);
      expect(result.status).toBe(0);
      expect(JSON.parse(result.stdout).verdict).toBe('CLEAN');
    });
  });

  it('returns 1 for a WARN verdict', () => {
    withCaseDir('warn', (dir) => {
      const { before, after } = writeBaselinePair(dir);
      fs.writeFileSync(path.join(dir, '.vetlock.json'), JSON.stringify({ version: 1 }));

      const result = runCli(dir, [
        'diff',
        before,
        after,
        '--json',
        '--no-progress',
        '--config',
        path.join(dir, '.vetlock.json'),
        '--config-allow-in-diff',
      ]);

      expect(result.status).toBe(1);
      const json = JSON.parse(result.stdout);
      expect(json.verdict).toBe('WARN');
      expect(json.findings.some((finding: { detector: string }) => finding.detector === 'config.in-diff-untrusted')).toBe(true);
    });
  });

  it('returns 2 for a BLOCK verdict', () => {
    withCaseDir('block', (dir) => {
      const { before, after } = writeBaselinePair(dir);
      fs.writeFileSync(path.join(dir, '.vetlock.json'), JSON.stringify({ version: 1 }));

      const result = runCli(dir, [
        'diff',
        before,
        after,
        '--json',
        '--no-progress',
        '--config',
        path.join(dir, '.vetlock.json'),
      ]);

      expect(result.status).toBe(2);
      const json = JSON.parse(result.stdout);
      expect(json.verdict).toBe('BLOCK');
      expect(json.findings[0].detector).toBe('config.in-diff-untrusted');
    });
  });

  it('uses exit code 3 only for unexpected/fatal errors', () => {
    withCaseDir('fatal', (dir) => {
      const before = path.join(dir, 'before.package-lock.json');
      const after = path.join(dir, 'after.package-lock.json');
      fs.writeFileSync(before, LOCKFILE);
      fs.writeFileSync(after, '{not valid json');

      const result = runCli(dir, ['diff', before, after, '--json', '--no-progress']);
      expect(result.status).toBe(3);
      expect(result.stderr).toMatch(/expected property name|failed to diff/i);
    });
  });
});
