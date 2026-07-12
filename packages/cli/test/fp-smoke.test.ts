import { describe, it, expect } from 'vitest';
import { promises as fs } from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runDiff } from '@vetlock/core';
import { runAll } from '@vetlock/detectors';

const CORPUS_DIR = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '..', '..', '..', 'corpus', 'fp-smoke',
);

const localFetch = async (ref: { resolved?: string | null; name: string; version: string }) => {
  if (ref.resolved?.startsWith('file://')) return new URL(ref.resolved).pathname;
  throw new Error(`test should not need to fetch ${ref.name}@${ref.version}`);
};

async function run(caseDir: string) {
  const before = await fs.readFile(path.join(caseDir, 'lockfile.before.json'), 'utf8');
  const after = await fs.readFile(path.join(caseDir, 'lockfile.after.json'), 'utf8');
  return runDiff(before, after, {
    runDetectors: (pair) => runAll(pair),
    fetchOverride: localFetch,
  });
}

describe('FP smoke — benign bumps must not fire WARN/BLOCK', () => {
  it('A. docs-only bump → CLEAN', async () => {
    const r = await run(path.join(CORPUS_DIR, 'a-docs-only'));
    expect(r.verdict).toBe('CLEAN');
    expect(r.findings).toHaveLength(0);
  });

  it('B. feature bump on a package that already used NET → no NET findings', async () => {
    const r = await run(path.join(CORPUS_DIR, 'b-feature-bump'));
    expect(r.verdict).toMatch(/CLEAN|INFO/);
    // No BLOCK / WARN — diff-framing must suppress "https already used" noise.
    for (const f of r.findings) {
      expect(f.severity).not.toBe('BLOCK');
      expect(f.severity).not.toBe('WARN');
    }
  });

  it('C. type-only bump → CLEAN', async () => {
    const r = await run(path.join(CORPUS_DIR, 'c-types-only'));
    expect(r.verdict).toBe('CLEAN');
    expect(r.findings).toHaveLength(0);
  });
});
