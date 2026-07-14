/**
 * GOLDEN DRIFT — determinism goldens.
 *
 * Each corpus/<id>/.golden.json is a committed, byte-stable snapshot of
 * vetlock's canonicalised output (findings, changes, errors, rollup, verdict
 * — everything except the VOLATILE `durationMs` wall-clock field) for that
 * fixture's before/after lockfile pair.
 *
 * This test replays every fixture end-to-end (same plumbing as
 * corpus-replay.test.ts) and diffs the canonicalised result against the
 * committed golden. A mismatch means one of two things:
 *
 *   1. Intentional: a detector/engine change altered output on purpose.
 *      → run `pnpm corpus:goldens` to refresh, review the diff, commit it.
 *   2. A determinism regression: the SAME inputs produced DIFFERENT output.
 *      → this is a real engine bug. Do not "fix" it by regenerating goldens.
 *
 * Corpus-replay.test.ts already asserts *which* detectors must fire; this
 * test asserts the *entire* output is byte-for-byte reproducible.
 */

import { describe, it, expect } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { CORPUS_ROOT, canonicalizeResult, listFixtureIds, runFixture } from '../src/corpus/fixture-runner.js';

const FIXTURE_IDS = listFixtureIds();

describe('GOLDEN DRIFT — committed .golden.json byte-stability', () => {
  it('has a golden fixture for every corpus id', () => {
    expect(FIXTURE_IDS.length).toBeGreaterThanOrEqual(10);
    for (const id of FIXTURE_IDS) {
      const goldenPath = path.join(CORPUS_ROOT, id, '.golden.json');
      expect(fs.existsSync(goldenPath), `missing corpus/${id}/.golden.json — run \`pnpm corpus:goldens\``).toBe(
        true,
      );
    }
  });

  it.each(FIXTURE_IDS)('%s matches its committed golden', async (id: string) => {
    const goldenPath = path.join(CORPUS_ROOT, id, '.golden.json');
    const goldenRaw = fs.readFileSync(goldenPath, 'utf8');
    const golden = JSON.parse(goldenRaw);

    const { result } = await runFixture(id);
    const actual = canonicalizeResult(result);

    const actualStr = JSON.stringify(actual, null, 2) + '\n';
    const goldenStr = JSON.stringify(golden, null, 2) + '\n';

    expect(
      actualStr,
      `corpus/${id}/.golden.json drifted from live output.\n` +
        `If this change is intentional, run \`pnpm corpus:goldens\` to refresh the golden and commit the diff.\n` +
        `If you did NOT intend to change detector/engine output, this is a determinism regression — do not paper over it.`,
    ).toBe(goldenStr);
  });
});
