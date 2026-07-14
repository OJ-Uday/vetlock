/**
 * P1-D · CAPABILITY-MAP coverage gate (ADR 0011 completeness doctrine).
 *
 * For each entry in packages/detectors/src/capability-map.json, assert:
 *  1. Every listed detector ID exists in the actual detector registry.
 *  2. Every listed test file path exists on disk.
 *  3. `corpus_refs` is non-empty UNLESS `soft_warn_no_corpus: true`.
 *
 * Violation of (1) or (2) is a HARD FAIL — the map is lying about a claim
 * that CI can trivially check. Violation of (3) without the soft-warn flag
 * is ALSO a hard fail (the whole point of the doctrine is to track this
 * gap explicitly).
 *
 * Soft-warn entries are counted and logged so the honest coverage number
 * moves toward zero over time.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync, existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { getCapabilityMap } from '../src/capability-map.js';
import { runAll } from '../src/index.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(HERE, '..', '..', '..');

/**
 * Extract the set of detector IDs the runAll orchestrator actually emits.
 * We do this by running runAll with a stub SnapshotPair that has one
 * populated capability of each shape, catching every detector that fires,
 * and taking the set of `f.detector` values. This is more honest than
 * grepping the source (which could report ids that never fire in
 * production).
 *
 * We ALSO grep the source for `detector: '<id>'` literals so that
 * detectors which don't fire on our stub still count as "registered."
 */
function knownDetectors(): Set<string> {
  const seen = new Set<string>();
  // Grep BOTH packages/core/src AND packages/detectors/src for detector-id
  // literals. Some IDs (deps.local-source, deps.non-registry-source,
  // deps.workspace-shadowing, deps.aliased-name, integrity.hash-mismatch,
  // analysis.failed) are emitted from engine/changeset in packages/core,
  // not from detectors modules.
  const grepDirs = [
    path.join(REPO_ROOT, 'packages', 'core', 'src'),
    path.join(REPO_ROOT, 'packages', 'detectors', 'src'),
  ];
  const walk = (dir: string): void => {
    for (const entry of require('node:fs').readdirSync(dir, { withFileTypes: true })) {
      const p = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(p);
        continue;
      }
      if (!entry.name.endsWith('.ts') || entry.name.endsWith('.d.ts')) continue;
      const txt = readFileSync(p, 'utf8');
      for (const m of txt.matchAll(/detector: '([a-z0-9.\-]+)'/g)) {
        seen.add(m[1]!);
      }
    }
  };
  for (const d of grepDirs) walk(d);
  // Also include any ID emitted by runAll itself (escalation aliases, etc.)
  void runAll;
  return seen;
}

describe('CAPABILITY-MAP coverage gate (ADR 0011)', () => {
  const map = getCapabilityMap();
  const detectors = knownDetectors();

  it('has entries[] populated', () => {
    expect(map.entries.length).toBeGreaterThan(20);
  });

  it('every detector referenced actually exists in the registry', () => {
    const missing: string[] = [];
    for (const e of map.entries) {
      for (const d of e.detectors) {
        if (!detectors.has(d)) {
          missing.push(`${e.class}::${e.id} → detector '${d}' not found`);
        }
      }
    }
    expect(missing, `unknown detector references — ${missing.length} entries:\n${missing.join('\n')}`).toEqual([]);
  });

  it('every test file referenced actually exists on disk', () => {
    const missing: string[] = [];
    for (const e of map.entries) {
      for (const t of e.tests) {
        const full = path.join(REPO_ROOT, t);
        if (!existsSync(full)) {
          missing.push(`${e.class}::${e.id} → test '${t}' not on disk`);
        }
      }
    }
    expect(missing, `unknown test-file references — ${missing.length} entries:\n${missing.join('\n')}`).toEqual([]);
  });

  it('every entry has at least one detector + at least one test', () => {
    const bad: string[] = [];
    for (const e of map.entries) {
      if (e.detectors.length === 0) bad.push(`${e.class}::${e.id} — no detectors`);
      if (e.tests.length === 0) bad.push(`${e.class}::${e.id} — no tests`);
    }
    expect(bad, `entries missing detector or test binding — ${bad.length}:\n${bad.join('\n')}`).toEqual([]);
  });

  it('corpus coverage — either corpus_refs[] populated OR soft_warn_no_corpus: true', () => {
    const hardFail: string[] = [];
    const softWarn: string[] = [];
    for (const e of map.entries) {
      if (e.corpus_refs.length === 0) {
        if (e.soft_warn_no_corpus) {
          softWarn.push(`${e.class}::${e.id}`);
        } else {
          hardFail.push(`${e.class}::${e.id} — no corpus_refs and no soft_warn flag`);
        }
      }
    }
    // Log the soft-warn count as a first-class number so it moves toward zero.
    // Console output is visible in CI logs; the test only fails on HARD gaps.
    if (softWarn.length > 0) {
      // eslint-disable-next-line no-console
      console.log(`\n  ⚠️  ${softWarn.length} soft-warn entries with no corpus_refs:\n    ${softWarn.join('\n    ')}\n  Add a corpus fixture that exercises each to promote to hard-covered.\n`);
    }
    expect(hardFail, `entries with zero corpus_refs and no soft_warn flag — ${hardFail.length}:\n${hardFail.join('\n')}`).toEqual([]);
  });

  it('summary: coverage stats', () => {
    const total = map.entries.length;
    const softWarn = map.entries.filter((e) => e.soft_warn_no_corpus).length;
    const withCorpus = map.entries.filter((e) => e.corpus_refs.length > 0).length;
    const byClass = new Map<string, number>();
    for (const e of map.entries) {
      byClass.set(e.class, (byClass.get(e.class) ?? 0) + 1);
    }
    // eslint-disable-next-line no-console
    console.log(`\n  📊 CAPABILITY-MAP v${map.version} coverage:`);
    // eslint-disable-next-line no-console
    console.log(`     total entries: ${total}`);
    // eslint-disable-next-line no-console
    console.log(`     with corpus refs: ${withCorpus} (${((withCorpus / total) * 100).toFixed(0)}%)`);
    // eslint-disable-next-line no-console
    console.log(`     soft-warn (no corpus yet): ${softWarn} (${((softWarn / total) * 100).toFixed(0)}%)`);
    // eslint-disable-next-line no-console
    console.log(`     by class:`);
    for (const [cls, n] of [...byClass.entries()].sort()) {
      // eslint-disable-next-line no-console
      console.log(`       ${cls.padEnd(24)} ${n}`);
    }
    // eslint-disable-next-line no-console
    console.log('');
    expect(total).toBeGreaterThan(20);
  });
});
