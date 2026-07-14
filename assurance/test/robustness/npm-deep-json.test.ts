/**
 * npm-deep-json — robustness tests for parser-DoS shapes targeting the npm parser.
 *
 * Feeds pathological package-lock.json inputs through the bounded runner and asserts the
 * oracle set. Same KNOWN GAPS PROTOCOL as no-crash.test.ts (packet rule #6): pins the
 * engine's *current* behavior. When STARTUP hardens the engine, any assertion that flips
 * (from GAP crash-pin to fail-safe) makes the test surface the change.
 *
 * Current findings (assurance P1 wave 1-C, 2026-07-14, seed=42, wallMs=5000, heapMb=128):
 *   nested-dependencies @ 10       → ok (real npm graph depth)
 *   nested-dependencies @ 100      → ok (~270ms, well under bounds)
 *   wide-packages @ 10             → ok
 *   wide-packages @ 1000           → ok (~290ms, 100k entries text ~10MB fits under bound at 100k)
 *   escaped-unicode @ 10           → ok
 *   escaped-unicode @ 1000         → ok (~230ms)
 *
 * No engine crash gap was observed for these three axes at the tested scales. The tests
 * pin the survival — if a future engine change starts crashing, these fire immediately.
 *
 * NB: Import from the file directly (not from robustness/index.ts) because Wave 2 owns
 * the barrel — this generator is not yet registered there.
 */

import { describe, it, expect } from 'vitest';
import { runBounded } from '../../src/runner/index.js';
import {
  oracleNoCrash,
  oracleNoHang,
  oracleNoOom,
  type Bounds,
} from '../../src/oracles/index.js';
import { npmDeepJson } from '../../src/robustness/npm-deep-json.js';

const BOUNDS: Bounds = { wallMs: 5_000, heapMb: 128, seed: 42 };

/** Run the generator through the parseLockfileText scenario and assert no-crash survival. */
async function runAndAssertSurvival(
  mode: 'nested-dependencies' | 'wide-packages' | 'escaped-unicode',
  scale: number,
): Promise<void> {
  const input = npmDeepJson.generate(1, { mode, scale });
  const outcome = await runBounded(
    {
      kind: 'engine:parseLockfileText',
      enginePath: '@vetlock/core',
      text: input.text,
      filename: input.filename,
    },
    BOUNDS,
  );
  // oracleNoCrash is the soft slack the task specifies: ok / fail-safe / timeout / oom are all
  // acceptable (the engine or the runner handled the pathology). Crash is the one forbidden path.
  const noCrash = oracleNoCrash(outcome);
  if (!noCrash.pass) {
    throw new Error(
      `robustness failure for npm-deep-json ${mode}@${scale}: ${noCrash.reason}` +
        (noCrash.evidence ? ` (evidence: ${JSON.stringify(noCrash.evidence).slice(0, 200)})` : ''),
    );
  }
  expect(noCrash.pass).toBe(true);
  // Belt-and-suspenders on the other axes: hang and OOM are unrelated axes but if either
  // starts firing at these scales it's still a robustness signal worth surfacing.
  expect(oracleNoHang(outcome).pass).toBe(true);
  expect(oracleNoOom(outcome).pass).toBe(true);
}

describe('npm-deep-json — robustness (parseLockfileText)', () => {
  // --- generator-shape sanity --------------------------------------------------------------
  // Cheap up-front checks that the generator produces byte-identical output for the same
  // (seed, params) and rejects illegal scales. Cheap enough to run in-process; the actual
  // engine cost is in the runner-based tests below.

  it('is deterministic — same (seed, params) yields identical bytes', () => {
    const a = npmDeepJson.generate(1, { mode: 'wide-packages', scale: 5 });
    const b = npmDeepJson.generate(1, { mode: 'wide-packages', scale: 5 });
    expect(a.text).toBe(b.text);
    expect(a.filename).toBe('package-lock.json');
    expect(a.format).toBe('npm');
  });

  it('rejects illegal scales (negative / non-integer / oversized)', () => {
    expect(() =>
      npmDeepJson.generate(1, { mode: 'wide-packages', scale: -1 }),
    ).toThrow(/scale must be a non-negative integer/);
    expect(() =>
      npmDeepJson.generate(1, { mode: 'wide-packages', scale: 1.5 }),
    ).toThrow(/scale must be a non-negative integer/);
    expect(() =>
      npmDeepJson.generate(1, { mode: 'wide-packages', scale: 2_000_000 }),
    ).toThrow(/scale must be a non-negative integer/);
  });

  it('produces valid JSON for every mode at scale=1', () => {
    for (const mode of ['nested-dependencies', 'wide-packages', 'escaped-unicode'] as const) {
      const input = npmDeepJson.generate(1, { mode, scale: 1 });
      // No throw ⇒ syntactically valid JSON. We don't assert semantic shape here; the runner
      // tests below hit @vetlock/core's parser and would fail there if the shape were broken.
      expect(() => JSON.parse(input.text)).not.toThrow();
    }
  });

  // --- runner-based baseline (scale=10 for each mode) --------------------------------------
  // Real-world npm lockfiles reach these scales trivially; the parser MUST handle them safely.

  it('nested-dependencies @ depth=10 (baseline) is handled safely', async () => {
    await runAndAssertSurvival('nested-dependencies', 10);
  }, 15_000);

  it('wide-packages @ count=10 (baseline) is handled safely', async () => {
    await runAndAssertSurvival('wide-packages', 10);
  }, 15_000);

  it('escaped-unicode @ repetitions=10 (baseline) is handled safely', async () => {
    await runAndAssertSurvival('escaped-unicode', 10);
  }, 15_000);

  // --- runner-based stress ------------------------------------------------------------------
  // Pinning the engine's current survival. No gap observed at these scales — the engine's
  // O(depth^2) walk-up (nested) and O(count) iteration (wide) both stay well under the 5s
  // wall bound. If a future engine change flips any of these to crash / timeout / oom, this
  // test surfaces the regression.
  //
  // NB: nested-dependencies scale is 100 not 1000. depth=1000 was measured at ~4s wallMs
  //     (very close to the 5s bound) — depth=100 completes in ~270ms with plenty of margin
  //     for slower CI hardware. If we want a harder stress later, the runner needs the
  //     child-process fallback tracked in Wave 1-A (worker abort survivability).

  it('nested-dependencies @ depth=100 (stress) is handled safely (pins current engine survival)', async () => {
    await runAndAssertSurvival('nested-dependencies', 100);
  }, 20_000);

  it('wide-packages @ count=1000 (stress) is handled safely (pins current engine survival)', async () => {
    await runAndAssertSurvival('wide-packages', 1000);
  }, 20_000);

  it('escaped-unicode @ repetitions=1000 (stress) is handled safely (pins current engine survival)', async () => {
    await runAndAssertSurvival('escaped-unicode', 1000);
  }, 20_000);
});
