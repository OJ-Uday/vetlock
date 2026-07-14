/**
 * yarn-berry-deep — robustness (parseLockfileText).
 *
 * KNOWN GAPS PROTOCOL (packet rule #6): pin the engine's *current* behavior. P1.3 probed
 * the three yarn-berry-deep shapes at scale 10/100/1000/5000; `@yarnpkg/parsers` (v3.0.3)
 * `parseSyml` returned `ok` on every input — the berry syml parser is robust to the
 * deep-nesting / wide-deps / escaped-strings DoS shapes at these magnitudes. These tests
 * lock in that observed-safe outcome: if a future engine/parser bump flips one to crash,
 * assurance surfaces it.
 */

import { describe, it, expect } from 'vitest';
import { runBounded } from '../../src/runner/index.js';
import {
  oracleNoCrash,
  oracleNoHang,
  oracleNoOom,
  type Bounds,
  type RunOutcome,
  type OracleResult,
} from '../../src/oracles/index.js';
import { yarnBerryDeep } from '../../src/robustness/yarn-berry-deep.js';

const BOUNDS: Bounds = { wallMs: 5_000, heapMb: 128, seed: 42 };

async function assertRobust(
  label: string,
  outcome: RunOutcome,
  bounds: Bounds,
): Promise<void> {
  const oracles: OracleResult[] = [
    oracleNoCrash(outcome),
    oracleNoHang(outcome),
    oracleNoOom(outcome),
  ];
  const failed = oracles.filter((r) => !r.pass);
  if (failed.length > 0) {
    const reason = failed
      .map(
        (r) =>
          `${r.oracle} FAIL — ${r.reason}${r.evidence ? ` (evidence: ${JSON.stringify(r.evidence).slice(0, 200)})` : ''}`,
      )
      .join('\n  ');
    throw new Error(
      `robustness failure for ${label} (seed=${bounds.seed}, wallMs=${bounds.wallMs}, heapMb=${bounds.heapMb}):\n  ${reason}`,
    );
  }
  expect(failed).toEqual([]);
}

async function probe(mode: 'deep-nesting' | 'wide-deps' | 'escaped-strings', scale: number): Promise<RunOutcome> {
  const input = yarnBerryDeep.generate(1, { mode, scale });
  return runBounded(
    {
      kind: 'engine:parseLockfileText',
      enginePath: '@vetlock/core',
      text: input.text,
      filename: input.filename,
    },
    BOUNDS,
  );
}

describe('yarn-berry-deep — robustness (parseLockfileText)', () => {
  it('emits __metadata: header so dispatcher routes to berry', () => {
    // Guard against a future refactor stripping the header — without it detectKind()
    // would send the input to the classic parser and the test would silently exercise
    // the wrong path. Same guard mirrors the format field.
    const input = yarnBerryDeep.generate(1, { mode: 'wide-deps', scale: 1 });
    expect(input.text).toMatch(/^__metadata:/);
    expect(input.format).toBe('yarn-berry');
    expect(input.filename).toBe('yarn.lock');
  });

  it('deep-nesting scale=10 (baseline) is handled safely', async () => {
    const outcome = await probe('deep-nesting', 10);
    await assertRobust('yarn-berry-deep deep-nesting scale=10', outcome, BOUNDS);
    expect(outcome.kind).toBe('ok');
  }, 15_000);

  it('deep-nesting scale=100 (stress) is handled safely', async () => {
    const outcome = await probe('deep-nesting', 100);
    await assertRobust('yarn-berry-deep deep-nesting scale=100', outcome, BOUNDS);
    // Pin: 100-level nested dependenciesMeta is a shape js-yaml would refuse.
    // parseSyml handles it — regression if it starts crashing.
    expect(outcome.kind).toBe('ok');
  }, 15_000);

  it('deep-nesting scale=1000 (heavy stress) is handled safely', async () => {
    const outcome = await probe('deep-nesting', 1000);
    await assertRobust('yarn-berry-deep deep-nesting scale=1000', outcome, BOUNDS);
    // Pin: 1000-level nested syml still `ok`. Notable contrast with the deep-nested-yaml
    // generator (pnpm-lock via js-yaml) which crashes at depth=100.
    expect(outcome.kind).toBe('ok');
  }, 15_000);

  it('wide-deps scale=10 (baseline) is handled safely', async () => {
    const outcome = await probe('wide-deps', 10);
    await assertRobust('yarn-berry-deep wide-deps scale=10', outcome, BOUNDS);
    expect(outcome.kind).toBe('ok');
  }, 15_000);

  it('wide-deps scale=100 (stress) is handled safely', async () => {
    const outcome = await probe('wide-deps', 100);
    await assertRobust('yarn-berry-deep wide-deps scale=100', outcome, BOUNDS);
    expect(outcome.kind).toBe('ok');
  }, 15_000);

  it('wide-deps scale=1000 (heavy stress) is handled safely', async () => {
    const outcome = await probe('wide-deps', 1000);
    await assertRobust('yarn-berry-deep wide-deps scale=1000', outcome, BOUNDS);
    // Pin: 1000-entry dependencies map on one package. The second graph-build pass
    // dereferences every one; still `ok`.
    expect(outcome.kind).toBe('ok');
  }, 15_000);

  it('escaped-strings scale=10 (baseline) is handled safely', async () => {
    const outcome = await probe('escaped-strings', 10);
    await assertRobust('yarn-berry-deep escaped-strings scale=10', outcome, BOUNDS);
    expect(outcome.kind).toBe('ok');
  }, 15_000);

  it('escaped-strings scale=100 (stress) is handled safely', async () => {
    const outcome = await probe('escaped-strings', 100);
    await assertRobust('yarn-berry-deep escaped-strings scale=100', outcome, BOUNDS);
    expect(outcome.kind).toBe('ok');
  }, 15_000);

  it('escaped-strings scale=1000 (heavy stress) is handled safely', async () => {
    const outcome = await probe('escaped-strings', 1000);
    await assertRobust('yarn-berry-deep escaped-strings scale=1000', outcome, BOUNDS);
    // Pin: 1000 entries each carrying 64 escaped backslash pairs. syml tokenizer's
    // escape-handling path still returns `ok`.
    expect(outcome.kind).toBe('ok');
  }, 15_000);
});
