import { describe, it, expect } from 'vitest';
import { promises as fs } from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runDiff } from '@vetlock/core';
import { runAll } from '@vetlock/detectors';
import { makeLocalFetch } from '../src/corpus/fixture-runner.js';

const CORPUS_DIR = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '..', '..', '..', 'corpus', 'shai-hulud-2025',
);

describe('CORPUS ACCEPTANCE — Shai-Hulud 2025 (defanged)', () => {
  it('produces a BLOCK verdict for the chalk 5.3.0 → 5.3.1 malicious update', async () => {
    const before = await fs.readFile(path.join(CORPUS_DIR, 'lockfile.before.json'), 'utf8');
    const after = await fs.readFile(path.join(CORPUS_DIR, 'lockfile.after.json'), 'utf8');

    const result = await runDiff(before, after, {
      runDetectors: (pair) => runAll(pair),
      fetchOverride: makeLocalFetch(CORPUS_DIR),
    });

    // 1. Overall verdict must be BLOCK.
    expect(result.verdict).toBe('BLOCK');

    // 2. Exit-code semantics: at least one BLOCK finding present.
    const blocks = result.findings.filter((f) => f.severity === 'BLOCK');
    expect(blocks.length).toBeGreaterThan(0);

    // 3. Every one of the required detector categories must fire.
    const categories = new Set(result.findings.map((f) => f.category));
    expect(categories.has('INSTALL')).toBe(true);
    expect(categories.has('ENV')).toBe(true);
    expect(categories.has('NET')).toBe(true);
    expect(categories.has('EXEC')).toBe(true);
    expect(categories.has('META')).toBe(true);

    // 4. Specific detectors we advertise in DETECTIONS.md.
    const detectors = new Set(result.findings.map((f) => f.detector));
    expect(detectors.has('install.script-added')).toBe(true);
    expect(detectors.has('env.token-harvest')).toBe(true);
    expect(detectors.has('net.new-endpoint')).toBe(true);
    expect(detectors.has('exec.new-module')).toBe(true);
    expect(detectors.has('meta.maintainer-change')).toBe(true);

    // 5. The specific NPM_TOKEN read must be flagged (this is the core Shai-Hulud signature).
    const npmTokenFinding = result.findings.find(
      (f) => f.detector === 'env.token-harvest' && f.message.includes('NPM_TOKEN'),
    );
    expect(npmTokenFinding).toBeDefined();
    expect(npmTokenFinding?.severity).toBe('BLOCK');

    // 6. The exfil endpoint must be surfaced.
    const exfilFinding = result.findings.find(
      (f) => f.detector === 'net.new-endpoint' && f.message.includes('exfil.example.invalid'),
    );
    expect(exfilFinding).toBeDefined();

    // 7. Provenance for at least one finding must be root → chalk.
    const withProvenance = result.findings.find((f) => f.provenance.length > 0);
    expect(withProvenance).toBeDefined();
    expect(withProvenance!.provenance[0]).toEqual(['my-app', 'chalk']);

    // 8. Rollup: chalk direct dep max severity is BLOCK.
    expect(result.rollupByDirect['chalk']?.maxSeverity).toBe('BLOCK');
  });

  it('fixture is DEFANGED — no live-exfil banned patterns anywhere', async () => {
    const banned = [
      // Substrings that would indicate a real (not defanged) attack. If any of
      // these appear in the fixture we have a corpus-hygiene problem.
      /https:\/\/[^\s"']*(?<!\.invalid)(?<!\.example)(?<!localhost)\/[a-z0-9]*(?:webhook|hook|exfil|collect|beacon)/i,
      /discord\.com\/api\/webhooks/i,
      /pastebin\.com/i,
      /raw\.githubusercontent\.com\/[^\/]+\/[^\/]+\/[a-f0-9]{40}/i,
    ];
    async function scan(p: string): Promise<void> {
      const s = await fs.stat(p);
      if (s.isDirectory()) {
        for (const child of await fs.readdir(p)) await scan(path.join(p, child));
        return;
      }
      // Only text-ish files: JSON, JS, MD. Skip tarballs (they're compressed).
      if (!/\.(json|js|ts|md)$/i.test(p)) return;
      const content = await fs.readFile(p, 'utf8');
      for (const rex of banned) {
        expect(rex.test(content), `banned pattern ${rex} matched in ${p}`).toBe(false);
      }
    }
    await scan(CORPUS_DIR);
  });
});
