/**
 * robustness-no-crash — the PR-tier robustness smoke.
 *
 * Feeds every registered generator through the bounded runner and asserts the oracle set.
 * A passing test at PR-tier means every generator ran without crashing the harness itself,
 * and the engine either handled the input safely (ok/fail-safe) or the runner caught the
 * pathology (timeout/oom). The one thing forbidden is `crash` — an exception escaping the
 * engine's public surface.
 *
 * KNOWN GAPS PROTOCOL (packet rule #6): when a generator surfaces a real robustness gap
 * in the engine — a shape that currently crashes it — the test is written to *pin the
 * gap* (assert the specific crash + include a corpus fixture). When STARTUP fixes the
 * engine, the assertion flips to `expect(kind).toBe('fail-safe')` and the test flips
 * green. This is honest reporting: the harness documents what the engine actually does,
 * not what we wish it did.
 */

import { describe, it, expect } from 'vitest';
import { runBounded } from '../../src/runner/index.js';
import {
  oracleNoCrash,
  oracleNoHang,
  oracleNoOom,
  oracleFailSafe,
  type Bounds,
  type RunOutcome,
  type OracleResult,
} from '../../src/oracles/index.js';
import { deepNestedYaml } from '../../src/robustness/index.js';

const BOUNDS: Bounds = { wallMs: 5_000, heapMb: 128, seed: 42 };

/** Feed a generator's output through the runner and assert the oracle set. */
async function assertRobust(
  label: string,
  outcome: RunOutcome,
  bounds: Bounds,
): Promise<void> {
  const oracles: OracleResult[] = [
    oracleNoCrash(outcome),
    oracleNoHang(outcome),
    oracleNoOom(outcome),
    oracleFailSafe(outcome),
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

describe('deep-nested-yaml — robustness (parseLockfileText)', () => {
  it('depth=10 (baseline: real pnpm-lock nesting depth) is handled safely', async () => {
    // Sanity: a shallow YAML nesting that mirrors real pnpm-lock files must round-trip.
    const input = deepNestedYaml.generate(1, { depth: 10 });
    const outcome = await runBounded(
      {
        kind: 'engine:parseLockfileText',
        enginePath: '@vetlock/core',
        text: input.text,
        filename: input.filename,
      },
      BOUNDS,
    );
    await assertRobust('deep-nested-yaml depth=10', outcome, BOUNDS);
  }, 15_000);

  // ------------------------------------------------------------------------------------------
  // GAP CLOSED (wave 4-T): js-yaml threw YAMLException with `nesting exceeded maxDepth (100)`
  // for depth ≥ ~100. The engine's parseLockfileText did not wrap this — the exception escaped
  // to the caller, which the runner surfaced as `kind: 'crash'`. It was a real robustness gap:
  // a hostile pnpm-lock.yaml with modest nesting crashed the parser instead of triggering the
  // fail-safe path.
  //
  // STARTUP wrapped `js-yaml.load` in `packages/core/src/lockfile-pnpm.ts` (wave 4-T commit),
  // rewrapping any parse throw as `UnsupportedLockfileError` — the engine's documented
  // "can't parse this, block conservatively" signal. The assurance runner
  // (worker.ts + child-entry.ts) recognizes UnsupportedLockfileError on the
  // engine:parseLockfileText path and translates it to the `fail-safe` channel, mirroring
  // how it already treats `extractCapabilities` parseError and `runDiff` analysis.failed.
  // Both assertions below now expect `fail-safe`.

  it('depth=100 triggers the engine fail-safe (previously crashed via js-yaml maxDepth)', async () => {
    const input = deepNestedYaml.generate(1, { depth: 100 });
    const outcome = await runBounded(
      {
        kind: 'engine:parseLockfileText',
        enginePath: '@vetlock/core',
        text: input.text,
        filename: input.filename,
      },
      BOUNDS,
    );
    // What the engine NOW does (wave 4-T fix): catch the YAMLException in
    // parsePnpmLockText, rethrow as UnsupportedLockfileError, which the harness
    // routes to the fail-safe channel with an analysis-failed BLOCK finding.
    expect(outcome.kind).toBe('fail-safe');
    expect(oracleFailSafe(outcome).pass).toBe(true);
    expect(oracleNoCrash(outcome).pass).toBe(true);
    expect(oracleNoHang(outcome).pass).toBe(true);
    expect(oracleNoOom(outcome).pass).toBe(true);
  }, 15_000);

  it('depth=1000 also triggers fail-safe (same maxDepth mechanism as depth=100)', async () => {
    const input = deepNestedYaml.generate(1, { depth: 1000 });
    const outcome = await runBounded(
      {
        kind: 'engine:parseLockfileText',
        enginePath: '@vetlock/core',
        text: input.text,
        filename: input.filename,
      },
      BOUNDS,
    );
    expect(outcome.kind).toBe('fail-safe');
    expect(oracleFailSafe(outcome).pass).toBe(true);
  }, 15_000);

  // NB: A depth=10000 case was drafted but removed for P1 — at that depth Node's YAML
  // parser can trigger V8-level aborts (`abort()` / stack overflow) that escape the
  // worker_threads sandbox. The next runner iteration should offer a child_process fallback
  // for scenarios likely to abort the process; those cases can then land safely without
  // taking down the vitest fork. Tracked in the packet's P1 tail: "worker abort survivability".
});
