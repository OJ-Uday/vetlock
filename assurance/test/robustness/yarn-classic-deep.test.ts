/**
 * yarn-classic-deep — robustness (parseLockfileText).
 *
 * KNOWN GAPS PROTOCOL (packet rule #6): pin the engine's *current* behavior. When P1.3
 * probed the three yarn-classic-deep shapes at scale 10/100/1000/5000, `@yarnpkg/lockfile`
 * (v1.1.0) returned `ok` on every input — the classic parser is robust to the wide-spec /
 * long-spec-list / alias-chain DoS shapes at these magnitudes. Assurance's job is to
 * lock that in as a regression: if a future engine/parser bump introduces a crash under
 * one of these shapes, the test surfaces it immediately.
 *
 * These are NOT `expect(outcome.kind).toBe('crash')` gap-tests like the deep-nested-yaml
 * case — that shape *does* crash. These pin the *good* outcome.
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
import { yarnClassicDeep } from '../../src/robustness/yarn-classic-deep.js';

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

async function probe(mode: 'wide-specs' | 'long-spec-list' | 'alias-chain', scale: number): Promise<RunOutcome> {
  const input = yarnClassicDeep.generate(1, { mode, scale });
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

describe('yarn-classic-deep — robustness (parseLockfileText)', () => {
  it('wide-specs scale=10 (baseline) is handled safely', async () => {
    const outcome = await probe('wide-specs', 10);
    await assertRobust('yarn-classic-deep wide-specs scale=10', outcome, BOUNDS);
    expect(outcome.kind).toBe('ok');
  }, 15_000);

  it('wide-specs scale=100 (stress) is handled safely', async () => {
    const outcome = await probe('wide-specs', 100);
    await assertRobust('yarn-classic-deep wide-specs scale=100', outcome, BOUNDS);
    // Pin: classic parser handles 100 top-level entries without crash/hang/oom.
    expect(outcome.kind).toBe('ok');
  }, 15_000);

  it('wide-specs scale=1000 (heavy stress) is handled safely', async () => {
    const outcome = await probe('wide-specs', 1000);
    await assertRobust('yarn-classic-deep wide-specs scale=1000', outcome, BOUNDS);
    // Pin: 1000 top-level entries still `ok`. If this flips to timeout/crash, the parser
    // has regressed and the change author owes a look.
    expect(outcome.kind).toBe('ok');
  }, 15_000);

  it('long-spec-list scale=10 (baseline) is handled safely', async () => {
    const outcome = await probe('long-spec-list', 10);
    await assertRobust('yarn-classic-deep long-spec-list scale=10', outcome, BOUNDS);
    expect(outcome.kind).toBe('ok');
  }, 15_000);

  it('long-spec-list scale=100 (stress) is handled safely', async () => {
    const outcome = await probe('long-spec-list', 100);
    await assertRobust('yarn-classic-deep long-spec-list scale=100', outcome, BOUNDS);
    expect(outcome.kind).toBe('ok');
  }, 15_000);

  it('long-spec-list scale=1000 (heavy stress) is handled safely', async () => {
    const outcome = await probe('long-spec-list', 1000);
    await assertRobust('yarn-classic-deep long-spec-list scale=1000', outcome, BOUNDS);
    // Pin: 1000 comma-joined aliases on one line — a shape neither pnpm nor npm accept —
    // parses cleanly. If parseYarnAlias or rawKey.split(',') regresses, this breaks.
    expect(outcome.kind).toBe('ok');
  }, 15_000);

  it('alias-chain scale=10 (baseline) is handled safely', async () => {
    const outcome = await probe('alias-chain', 10);
    await assertRobust('yarn-classic-deep alias-chain scale=10', outcome, BOUNDS);
    expect(outcome.kind).toBe('ok');
  }, 15_000);

  it('alias-chain scale=100 (stress) is handled safely', async () => {
    const outcome = await probe('alias-chain', 100);
    await assertRobust('yarn-classic-deep alias-chain scale=100', outcome, BOUNDS);
    expect(outcome.kind).toBe('ok');
  }, 15_000);

  it('alias-chain scale=1000 (heavy stress) is handled safely', async () => {
    const outcome = await probe('alias-chain', 1000);
    await assertRobust('yarn-classic-deep alias-chain scale=1000', outcome, BOUNDS);
    // Pin: 1000-package chain (each depending on next) exercises the second-pass
    // dependency-edge builder in objectToGraph. Still `ok`.
    expect(outcome.kind).toBe('ok');
  }, 15_000);
});
