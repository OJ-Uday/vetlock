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

function makeLocalFetch(caseDir: string) {
  return async (ref: { resolved?: string | null; name: string; version: string }) => {
    const r = ref.resolved;
    if (!r) throw new Error(`test should not need to fetch ${ref.name}@${ref.version}`);
    // Absolute file:// or file:/// URL (original corpus format)
    if (r.startsWith('file://')) return new URL(r).pathname;
    // Relative file: ref — resolve against the case directory (portable corpus format)
    if (r.startsWith('file:')) {
      const raw = r.slice(5).replace(/^\.\//, '');
      return path.resolve(caseDir, raw);
    }
    throw new Error(`test should not need to fetch ${ref.name}@${ref.version}`);
  };
}

async function run(caseDir: string) {
  const before = await fs.readFile(path.join(caseDir, 'lockfile.before.json'), 'utf8');
  const after = await fs.readFile(path.join(caseDir, 'lockfile.after.json'), 'utf8');
  return runDiff(before, after, {
    runDetectors: (pair) => runAll(pair),
    fetchOverride: makeLocalFetch(caseDir),
  });
}

const CASES: Array<{ dir: string; description: string; allowed: 'CLEAN' | 'INFO' }> = [
  { dir: 'a-docs-only',      description: 'docs-only bump',                       allowed: 'CLEAN' },
  { dir: 'b-feature-bump',   description: 'feature bump on a package that already used NET', allowed: 'CLEAN' },
  { dir: 'c-types-only',     description: 'type-only bump',                       allowed: 'CLEAN' },
  { dir: 'd-refactor',       description: 'internal refactor — same public API',  allowed: 'CLEAN' },
  { dir: 'e-license-fix',    description: 'license/repository field correction',  allowed: 'CLEAN' },
  { dir: 'f-added-tests',    description: 'tests-only additions to tarball',      allowed: 'CLEAN' },
  { dir: 'g-bugfix',         description: 'minor bugfix — NaN edge case',         allowed: 'CLEAN' },
  { dir: 'h-peerdep-added',  description: 'peerDependency added in manifest',     allowed: 'CLEAN' },
];

describe('FP smoke — 8 benign bumps must not fire WARN/BLOCK', () => {
  it.each(CASES)(
    '$dir — $description → verdict at most $allowed',
    async ({ dir, allowed }) => {
      const r = await run(path.join(CORPUS_DIR, dir));
      // Never BLOCK or WARN.
      for (const f of r.findings) {
        expect(
          f.severity,
          `${dir}: unexpected ${f.severity} — ${f.detector}: ${f.message}`,
        ).not.toBe('BLOCK');
        expect(f.severity).not.toBe('WARN');
      }
      if (allowed === 'CLEAN') {
        expect(r.verdict, `${dir}: verdict should be CLEAN`).toBe('CLEAN');
      } else {
        // 'INFO' is the loosest allowed verdict.
        expect(['CLEAN', 'INFO']).toContain(r.verdict);
      }
    },
  );

  it('at least 8 FP cases in the corpus', () => {
    expect(CASES.length).toBeGreaterThanOrEqual(8);
  });
});
