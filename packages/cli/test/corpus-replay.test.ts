/**
 * CORPUS REPLAY — data-driven acceptance test.
 *
 * Reads every corpus/<id>/manifest.json (built by build-all.js + build-shai-hulud.js),
 * runs vetlock against it, and asserts:
 *
 *   1. The overall verdict matches manifest.expect.verdict.
 *   2. Every id in manifest.expect.mustFire actually appears in findings.
 *   3. No id in manifest.expect.mustNotFire appears.
 *   4. Every category in manifest.expect.minCategories has at least one finding.
 *
 * Adding an 11th attack: drop a spec under packages/cli/src/corpus/fixtures/,
 * add it to ALL_FIXTURES in build-all.ts, rebuild the corpus, rerun. No new test.
 *
 * ALSO enforces defanged-corpus hygiene: no live-exfil pattern in any fixture.
 */

import { describe, it, expect } from 'vitest';
import { promises as fs } from 'node:fs';
import * as fsSync from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runDiff } from '@vetlock/core';
import { runAll } from '@vetlock/detectors';
import { makeLocalFetch, resolveFixtureLockfiles } from '../src/corpus/fixture-runner.js';

const CORPUS_ROOT = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '..', '..', '..', 'corpus',
);

interface CorpusManifest {
  id: string;
  title: string;
  year?: number;
  threatClass?: string;
  summary?: string;
  provenance?: string;
  topology?: string;
  defanged?: boolean;
  expect: {
    mustFire: string[];
    mustNotFire?: string[];
    verdict: 'BLOCK' | 'WARN' | 'INFO' | 'CLEAN';
    minCategories?: string[];
    known_limitation?: string;
  };
}

/** Load manifests synchronously — vitest's it.each needs the array up-front. */
function loadManifestsSync(): CorpusManifest[] {
  const entries = fsSync.readdirSync(CORPUS_ROOT, { withFileTypes: true });
  const out: CorpusManifest[] = [];
  for (const e of entries) {
    if (!e.isDirectory()) continue;
    if (e.name.startsWith('_') || e.name === 'fp-smoke') continue;
    const manifestPath = path.join(CORPUS_ROOT, e.name, 'manifest.json');
    try {
      const raw = fsSync.readFileSync(manifestPath, 'utf8');
      out.push(JSON.parse(raw) as CorpusManifest);
    } catch {
      // Skip dirs without a manifest.json.
    }
  }
  return out.sort((a, b) => a.id.localeCompare(b.id));
}

const MANIFESTS = loadManifestsSync();

describe('CORPUS REPLAY — 10+ known npm supply-chain attacks', () => {
  it('has at least 10 fixtures loaded', () => {
    expect(MANIFESTS.length).toBeGreaterThanOrEqual(10);
  });

  it.each(MANIFESTS)(
    '$id ($year) — $title',
    async (manifest: CorpusManifest) => {
      const dir = path.join(CORPUS_ROOT, manifest.id);
      const lockfiles = resolveFixtureLockfiles(dir);
      const before = await fs.readFile(lockfiles.beforePath, 'utf8');
      const after = await fs.readFile(lockfiles.afterPath, 'utf8');
      const result = await runDiff(before, after, {
        runDetectors: (pair) => runAll(pair),
        fetchOverride: makeLocalFetch(dir),
        oldLockfilePath: lockfiles.oldLockfilePath,
        newLockfilePath: lockfiles.newLockfilePath,
      });

      const detectors = new Set(result.findings.map((f) => f.detector));
      const categories = new Set(result.findings.map((f) => f.category));

      // 1. Verdict matches
      expect(result.verdict, `${manifest.id}: verdict`).toBe(manifest.expect.verdict);

      // 2. Every mustFire detector appears
      for (const req of manifest.expect.mustFire) {
        expect(
          detectors.has(req),
          `${manifest.id}: missing required detector "${req}". Fired: [${[...detectors].sort().join(', ')}]`,
        ).toBe(true);
      }

      // 3. No mustNotFire detectors appear
      for (const forbidden of manifest.expect.mustNotFire ?? []) {
        expect(
          detectors.has(forbidden),
          `${manifest.id}: forbidden detector "${forbidden}" fired`,
        ).toBe(false);
      }

      // 4. Every minCategory has at least one finding
      for (const cat of manifest.expect.minCategories ?? []) {
        expect(
          categories.has(cat as import('@vetlock/core').DetectorCategory),
          `${manifest.id}: missing required category "${cat}". Got: [${[...categories].sort().join(', ')}]`,
        ).toBe(true);
      }
    },
  );
});

describe('CORPUS DEFANGED — no fixture contains a live-exfil pattern', () => {
  // Banned patterns that would indicate a real (not defanged) attack payload.
  // A test failure here means someone slipped a real endpoint into a fixture.
  const banned = [
    // Real webhook / hook endpoints on live domains (allowlist .invalid/.example/.test)
    /https?:\/\/(?!.*\.(?:invalid|example|test|localhost)\b)[^\s"']*\/(webhook|hook|beacon|beacons?)\b/i,
    // Known drop hosts
    /discord\.com\/api\/webhooks/i,
    /pastebin\.com\//i,
    // RAW github commit-pinned scripts (a classic loader shape)
    /raw\.githubusercontent\.com\/[^\/]+\/[^\/]+\/[a-f0-9]{40}\//i,
    // Live blockchain drainer endpoints
    /drainer[\w-]*\.(?!invalid|example)[a-z]{2,}/i,
  ];

  it('scans every corpus dir for banned patterns', async () => {
    const roots = await fs.readdir(CORPUS_ROOT, { withFileTypes: true });
    async function scan(p: string): Promise<void> {
      const stat = await fs.stat(p);
      if (stat.isDirectory()) {
        for (const child of await fs.readdir(p)) await scan(path.join(p, child));
        return;
      }
      if (!/\.(json|js|ts|md)$/i.test(p)) return;
      const content = await fs.readFile(p, 'utf8');
      for (const rex of banned) {
        expect(rex.test(content), `banned pattern ${rex} matched in ${p}`).toBe(false);
      }
    }
    for (const r of roots) {
      if (!r.isDirectory() || r.name.startsWith('_')) continue;
      await scan(path.join(CORPUS_ROOT, r.name));
    }
  });
});
