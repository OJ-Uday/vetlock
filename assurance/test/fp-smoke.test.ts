import { describe, it, expect } from 'vitest';
import { promises as fs } from 'node:fs';
import * as fsSync from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runDiff } from '@vetlock/core';
import { runAll } from '@vetlock/detectors';

const CORPUS_DIR = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '..',
  '..',
  'corpus',
  'fp-smoke',
);

function resolveFileRef(resolved: string, fixtureDir: string): string {
  const raw = resolved.slice('file:'.length);
  if (raw.startsWith('///')) return raw.slice(2);
  if (raw.startsWith('//')) return raw.slice(raw.indexOf('/', 2));
  return path.resolve(fixtureDir, raw.replace(/^\.\//, ''));
}

async function runCase(caseDir: string) {
  const before = await fs.readFile(path.join(caseDir, 'lockfile.before.json'), 'utf8');
  const after = await fs.readFile(path.join(caseDir, 'lockfile.after.json'), 'utf8');
  return runDiff(before, after, {
    runDetectors: (pair) => runAll(pair),
    fetchOverride: async (ref) => {
      if (ref.resolved?.startsWith('file:')) return resolveFileRef(ref.resolved, caseDir);
      const stem = `${ref.name}-${ref.version}`;
      const candidates = [
        path.join(caseDir, stem, `${stem}.tar.gz`),
        path.join(caseDir, stem, `${stem}.tgz`),
        path.join(caseDir, `${stem}.tar.gz`),
        path.join(caseDir, `${stem}.tgz`),
      ];
      for (const candidate of candidates) {
        if (fsSync.existsSync(candidate)) return candidate;
      }
      throw new Error(`fp-smoke case should not need to fetch ${ref.name}@${ref.version}`);
    },
  });
}

const CASES = fsSync
  .readdirSync(CORPUS_DIR, { withFileTypes: true })
  .filter((entry) => entry.isDirectory())
  .map((entry) => entry.name)
  .sort();

describe('assurance fp-smoke corpus', () => {
  it('enumerates every benign corpus case', () => {
    expect(CASES.length).toBeGreaterThan(0);
  });

  it.each(CASES)('%s stays CLEAN or INFO-only', async (caseId: string) => {
    const result = await runCase(path.join(CORPUS_DIR, caseId));

    expect(['CLEAN', 'INFO']).toContain(result.verdict);
    for (const finding of result.findings) {
      expect(finding.severity, `${caseId}: unexpected ${finding.severity} — ${finding.detector}`).not.toBe('WARN');
      expect(finding.severity, `${caseId}: unexpected ${finding.severity} — ${finding.detector}`).not.toBe('BLOCK');
    }
  });
});
