/**
 * differential-ledger-integration.test — end-to-end assertion that the seeded ledger is
 * populated, honestly classified, and byte-stably persistable.
 *
 * The packet §5 P3 done-gate says: **"differential ledger published + classified; deltas
 * triaged"**. The unit test in `differential-ledger.test.ts` covers ledger *mechanics* (add
 * → classify → clean invariants). This integration test covers the corpus-shaped invariants
 * you can only assert once the seeded content is applied:
 *
 *   1. Every seeded delta lands in the classified pool (no silent drops).
 *   2. Every real-incident corpus fixture is represented (packet §7: "no silent hits").
 *   3. `real-gap` is empty (or, if non-empty, this test flags it prominently — a real gap
 *      is a coverage finding, not a passing test).
 *   4. `isClean()` is true (packet §5 P3 done-gate).
 *   5. The persisted JSON round-trips through save() + load() and matches the in-memory
 *      state (already covered by the ledger unit test, but exercised here on the real
 *      seeded content to catch shape drift specific to the seeded fixtures).
 *   6. report() renders a non-trivial, well-structured markdown snapshot (H2 for section,
 *      per-class buckets, every fixture package name appears).
 */

import { describe, it, expect } from 'vitest';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  DifferentialLedger,
  populateLedgerFromSeededDeltas,
  seededCorpusIds,
  seededDeltas,
} from '../../src/differential/index.js';

/**
 * Build a fresh ledger populated with every seeded delta. Kept as a helper so each `it`
 * gets its own isolated instance — no cross-test state.
 */
function freshPopulatedLedger(): DifferentialLedger {
  const ledger = new DifferentialLedger();
  populateLedgerFromSeededDeltas(ledger);
  return ledger;
}

const NON_LEDGER_BACKED_CORPUS_IDS = new Set([
  'hardened-evader-2026',
  'integrity-tamper-synthetic',
  'typosquat-synthetic',
  // PyPI corpus wiring lands before seeded scanner deltas do; keep these in PR-tier replay
  // coverage without pretending the differential ledger already has corresponding rows.
  'ctx-2022',
  'ultralytics-2024',
  'aiocpa-2024',
  'pypi-install-hook-synthetic',
]);

const LEDGER_BACKED_CORPUS_IDS = seededCorpusIds.filter((id) => !NON_LEDGER_BACKED_CORPUS_IDS.has(id));

describe('differential-ledger integration — seeded historical content', () => {
  it('every seeded delta lands in the classified pool (no silent drops)', () => {
    const ledger = freshPopulatedLedger();
    expect(ledger.size).toBe(seededDeltas.length);
    expect(ledger.pendingCount).toBe(0);
  });

  it('populate is idempotent (calling twice yields the same size)', () => {
    const ledger = new DifferentialLedger();
    populateLedgerFromSeededDeltas(ledger);
    const firstSize = ledger.size;
    populateLedgerFromSeededDeltas(ledger);
    expect(ledger.size).toBe(firstSize);
    expect(ledger.pendingCount).toBe(0);
  });

  it('every ledger-backed corpus fixture is represented in the differential ledger', () => {
    const ledger = freshPopulatedLedger();
    // Concatenate every rationale — the seededDeltas records the fixture id in each row's
    // rationale via "corpus fixture <id>" wording. Cheaper than a separate mapping table
    // and keeps the assertion tied to the human-readable rationale, not a hidden index.
    const combinedText = ledger
      .deltas()
      .map((d) => `${d.finding.package} ${d.finding.title} ${d.rationale}`)
      .join('\n');
    for (const id of LEDGER_BACKED_CORPUS_IDS) {
      expect(combinedText, `fixture "${id}" is not represented in the ledger`).toContain(id);
    }
    // PR-tier assurance should cover both historical incidents and the three synthetic regressions.
    expect(seededCorpusIds.length).toBeGreaterThanOrEqual(11);
    expect(NON_LEDGER_BACKED_CORPUS_IDS.size).toBeGreaterThanOrEqual(3);
  });

  it('classification split: no real-gap findings surfaced (documented scope boundaries only)', () => {
    // If this ever fails, the seeded ledger has grown a real coverage bug — surface it
    // prominently in the failure message so a reviewer sees WHICH package/finding is the
    // gap, not just "count > 0".
    const ledger = freshPopulatedLedger();
    const realGaps = ledger.deltas().filter((d) => d.class === 'real-gap');
    expect(
      realGaps,
      `unexpected real-gap findings: ${realGaps
        .map((d) => `${d.finding.package} — ${d.rationale}`)
        .join('; ')}`,
    ).toHaveLength(0);
  });

  it('every classified delta uses one of the four canonical classes', () => {
    const ledger = freshPopulatedLedger();
    const allowed = new Set(['real-gap', 'intentional-non-goal', 'advisory-only', 'noise']);
    for (const delta of ledger.deltas()) {
      expect(allowed.has(delta.class), `unknown class: ${delta.class}`).toBe(true);
    }
  });

  it('isClean() is true (packet §5 P3 done-gate: ledger published + classified)', () => {
    const ledger = freshPopulatedLedger();
    expect(ledger.isClean()).toBe(true);
  });

  it('report() renders a non-trivial, well-structured markdown snapshot', () => {
    const ledger = freshPopulatedLedger();
    const md = ledger.report();
    // H2 section header.
    expect(md).toContain('## Differential ledger');
    // Clean-yes line.
    expect(md).toContain('**Clean:** yes');
    // At least the advisory-only bucket renders (the vast majority of seeded deltas).
    expect(md).toContain('advisory-only');
    // Only ledger-backed fixture ids appear in the markdown because some replay-only fixtures
    // deliberately have no seeded delta rows yet. Their coverage is tracked by seededCorpusIds,
    // not by report().
    for (const id of LEDGER_BACKED_CORPUS_IDS) {
      expect(md, `report is missing fixture "${id}"`).toContain(id);
    }
    // No pending / dirty language.
    expect(md).not.toContain('Pending deltas');
  });

  it('save() + load() round-trip preserves the seeded content byte-for-byte', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'vetlock-ledger-int-'));
    const path = join(dir, 'differential-ledger.json');
    try {
      const original = freshPopulatedLedger();
      await original.save(path);
      const loaded = await DifferentialLedger.load(path);
      expect(loaded.size).toBe(original.size);
      expect(loaded.pendingCount).toBe(original.pendingCount);
      expect(loaded.isClean()).toBe(true);
      // Report content is a stable representation — save/load must not perturb it.
      expect(loaded.report()).toBe(original.report());
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
