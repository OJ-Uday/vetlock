import { describe, it, expect } from 'vitest';
import { promises as fs } from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runDiff, type Finding, type SnapshotPair } from '../src/index.js';

const CORPUS_DIR = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '..',
  '..',
  '..',
  'corpus',
  'hardened-evader-2026',
);

function resolveFileRef(resolved: string): string {
  const raw = resolved.slice('file:'.length);
  if (raw.startsWith('///')) return raw.slice(2);
  if (raw.startsWith('//')) return raw.slice(raw.indexOf('/', 2));
  return path.resolve(CORPUS_DIR, raw.replace(/^\.\//, ''));
}

const fetchOverride = async (ref: { resolved?: string | null; name: string; version: string }) => {
  if (ref.resolved?.startsWith('file:')) return resolveFileRef(ref.resolved);
  throw new Error(`test fixture should not need to fetch ${ref.name}@${ref.version}`);
};

const runDetectors = (pair: SnapshotPair, pkg: string): Finding[] => {
  if (!pair.old || !pair.new || pair.old.version === pair.new.version) return [];
  return [
    {
      detector: 'test.version-changed',
      category: 'META',
      package: pkg,
      from: pair.old.version,
      to: pair.new.version,
      direction: 'changed',
      severity: 'INFO',
      confidence: 'high',
      message: `${pair.old.version} → ${pair.new.version}`,
      evidence: [{ file: 'package.json', line: 1, snippet: pkg }],
      provenance: [],
    },
  ];
};

function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) =>
    a.detector.localeCompare(b.detector) ||
    a.package.localeCompare(b.package) ||
    (a.from ?? '').localeCompare(b.from ?? '') ||
    (a.to ?? '').localeCompare(b.to ?? ''),
  );
}

describe('runDiff determinism', () => {
  it('produces identical output on replayed input', async () => {
    const before = await fs.readFile(path.join(CORPUS_DIR, 'lockfile.before.json'), 'utf8');
    const after = await fs.readFile(path.join(CORPUS_DIR, 'lockfile.after.json'), 'utf8');

    const out1 = await runDiff(before, after, {
      runDetectors,
      fetchOverride,
    });
    const out2 = await runDiff(before, after, {
      runDetectors,
      fetchOverride,
    });

    expect(sortFindings(out1.findings)).toEqual(sortFindings(out2.findings));
    expect(out1.verdict).toBe(out2.verdict);
  });
});
