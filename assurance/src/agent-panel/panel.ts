/**
 * Panel driver (PACKET-VETLOCK-ASSURANCE §5 P4).
 *
 * The panel is the perpetual red-team: for every class in the CAPABILITY-MAP, ask the
 * agent for N evasion hypotheses, run each through the defang guard (rule #2), then
 * through the bounded runner (`engine:parseLockfileText` is the simplest surface — other
 * surfaces will graduate in later waves), then through the `finding-survives` oracle.
 *
 * FLOW:
 *   1. For each entry in `opts.capabilityMap.entries`:
 *      a. Ask `opts.agent.propose(entry, seed, max)` for hypotheses.
 *      b. For each hypothesis: scan `generatedFixture` with the defang guard.
 *         - clean → admit into the run set.
 *         - dirty → record in `rejected`, do NOT run.
 *      c. For each admitted hypothesis: run its fixture through the runner.
 *      d. Apply the finding-survives oracle. If the fixture cleanly parsed but the
 *         detector missed the target class, mark `evaded: true`.
 *   2. Return `PanelReport`.
 *
 * TIER: SCHEDULED (never blocking). This is packet §5 P4 — the panel files coverage gaps
 * as issues/PRs; it does not fail CI. The driver returns a report; consumers decide what
 * to do with `evasionsFound > 0` (in production: open an issue; in CI: log a summary).
 *
 * COVERAGE HONESTY: because the stub-agent proposes fixtures the CURRENT detector set does
 * not implement, EVERY admitted stub hypothesis is expected to evade the (empty) detector
 * set. That's not a bug — the panel is doing exactly what it should. The number of
 * evasions found is a floor, not a ceiling; the interesting number is time-to-close (how
 * fast confirmed evasions land as CAPABILITY-MAP entries + regressions).
 */

import { scanForDefangViolations } from '../defang/index.js';
import { runBounded } from '../runner/index.js';
import { oracleFindingSurvives } from '../oracles/index.js';
import type { Bounds, RunOutcome } from '../oracles/types.js';
import type {
  EvasionHypothesis,
  EvasionRun,
  PanelOptions,
  PanelReport,
  RejectedHypothesis,
} from './types.js';

/** Default bounds for panel runs. Wide enough that legit fixtures parse; narrow enough that
 *  a hostile fixture cannot hang the scheduled job. */
const DEFAULT_BOUNDS: Omit<Bounds, 'seed'> = {
  wallMs: 5_000,
  heapMb: 128,
};

/** Format the defang violations into a single-line reason for the report. */
function formatDefangReason(count: number, samples: readonly { readonly category: string; readonly match: string }[]): string {
  const sample = samples
    .slice(0, 3)
    .map((v) => `${v.category}:"${v.match.slice(0, 40)}"`)
    .join(', ');
  return `defang guard flagged ${count} violation(s) — ${sample}`;
}

/**
 * Run one hypothesis. Returns the EvasionRun (evaded flag included).
 *
 * The oracle applies only to verdict-bearing outcomes (ok / fail-safe). Crash / timeout /
 * OOM on a hypothesis mean the mutated input broke the parser — a robustness gap, a
 * different flavor of failure that gets recorded but not counted as an evasion. Confirmed
 * evasions require a clean parse whose findings are missing the target class.
 */
async function runOne(hypothesis: EvasionHypothesis, seed: number): Promise<EvasionRun> {
  const outcome: RunOutcome = await runBounded(
    {
      kind: 'engine:parseLockfileText',
      enginePath: '@vetlock/core',
      text: hypothesis.generatedFixture,
      filename: 'pnpm-lock.yaml',
    },
    { ...DEFAULT_BOUNDS, seed },
  );

  // Evasion classification. The finding-survives oracle needs a "before" (baseline hit)
  // and an "after" (mutated). The panel doesn't have a baseline of its own — the mutation
  // *is* the input. We test evasion directly: did the mutated fixture produce a finding of
  // the target class?
  //
  // If yes → detector caught the technique → NOT an evasion.
  // If no (verdict-bearing but wrong class or empty) → EVASION.
  // If crash/timeout/OOM → not an evasion (robustness failure category).
  let evaded = false;
  if (outcome.kind === 'ok' || outcome.kind === 'fail-safe') {
    // Construct a synthetic "before" with the required finding, and use finding-survives
    // to check the "after". This reuses the oracle instead of duplicating its logic.
    const syntheticBefore: RunOutcome = {
      kind: 'ok',
      findings: [
        {
          capabilityClass: hypothesis.targetClass,
          severity: 'FLAG',
          reason: 'synthetic baseline for panel evasion check',
        },
      ],
      wallMs: 0,
      peakRssBytes: 0,
      seed,
    };
    const oracleResult = oracleFindingSurvives(syntheticBefore, outcome, hypothesis.targetClass);
    // finding-survives fails when the mutation evaded — that's exactly the shape we want.
    evaded = !oracleResult.pass;
  }

  return { hypothesis, outcome, evaded };
}

/**
 * The panel entrypoint. Returns a `PanelReport`. Never throws for expected failure modes —
 * hypotheses that flunk the defang guard are recorded in `rejected`, hypotheses that
 * crash the parser are recorded in `runs` with `evaded: false`.
 */
export async function runPanel(opts: PanelOptions): Promise<PanelReport> {
  if (opts.maxHypothesesPerClass < 0) {
    throw new Error(`runPanel: maxHypothesesPerClass must be ≥ 0; got ${opts.maxHypothesesPerClass}`);
  }
  const now = opts.now ?? ((): Date => new Date());

  const runs: EvasionRun[] = [];
  const rejected: RejectedHypothesis[] = [];
  let proposed = 0;

  for (const entry of opts.capabilityMap.entries) {
    const hypotheses = await opts.agent.propose(entry, opts.seed, opts.maxHypothesesPerClass);
    proposed += hypotheses.length;
    for (const h of hypotheses) {
      const scan = scanForDefangViolations(h.generatedFixture);
      if (!scan.clean) {
        rejected.push({
          hypothesis: h,
          reason: formatDefangReason(scan.violations.length, scan.violations),
        });
        continue;
      }
      const run = await runOne(h, opts.seed);
      runs.push(run);
    }
  }

  // Preserve deterministic iteration order in the report — runs and rejected are already
  // built in traversal order, which is stable (agent.propose is required to be
  // deterministic for a given seed).
  const evasionsFound = runs.filter((r) => r.evaded).length;

  return {
    runAt: now().toISOString(),
    agent: opts.agent.id,
    seed: opts.seed,
    hypothesesProposed: proposed,
    hypothesesAdmitted: runs.length,
    hypothesesRejected: rejected.length,
    evasionsFound,
    runs,
    rejected,
  };
}
