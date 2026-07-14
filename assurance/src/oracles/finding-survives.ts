/**
 * oracleFindingSurvives — the completeness heart.
 *
 * `before` is the canonical (unmutated) run. It must contain at least one finding of the
 * target capability class; otherwise the test setup is broken and we say so loudly.
 *
 * `after` is the run of a semantics-preserving mutation of the same input. It must also
 * contain at least one finding of the target class (possibly moved / renamed / relocated).
 * If it doesn't, the mutation evaded the detector — a completeness hole.
 *
 * `after` is allowed to be `fail-safe` with a matching finding: the engine erroring
 * internally and blocking conservatively still counts as "the finding survived." It is NOT
 * allowed to be `crash`, `timeout`, or `oom` — those are different bugs (a mutation should
 * not be able to break the engine; if it can, the fixture is now a robustness input, not
 * a completeness input).
 */

import type { Findings, OracleResult, RunOutcome } from './types.js';

function findingsOfClass(
  outcome: RunOutcome,
  cls: string,
): Findings {
  if (outcome.kind === 'ok' || outcome.kind === 'fail-safe') {
    return outcome.findings.filter((f) => f.capabilityClass === cls);
  }
  return [];
}

export function oracleFindingSurvives(
  before: RunOutcome,
  after: RunOutcome,
  capabilityClass: string,
): OracleResult {
  // Baseline sanity: before must contain the class we're asserting survives.
  const baselineHits = findingsOfClass(before, capabilityClass);
  if (baselineHits.length === 0) {
    return {
      oracle: 'finding-survives',
      pass: false,
      reason: `baseline (before) has no finding of class ${capabilityClass} — fixture mislabeled?`,
      evidence: { class: capabilityClass, beforeKind: before.kind },
    };
  }

  // After must be a verdict-bearing outcome. crash/timeout/oom mean the mutation broke the
  // engine — that's a robustness failure, not a completeness pass.
  if (after.kind !== 'ok' && after.kind !== 'fail-safe') {
    return {
      oracle: 'finding-survives',
      pass: false,
      reason: `mutated variant did not produce a verdict (kind=${after.kind}) — not ok; mutation broke the engine`,
      evidence: { class: capabilityClass, afterKind: after.kind },
    };
  }

  const afterHits = findingsOfClass(after, capabilityClass);
  if (afterHits.length === 0) {
    return {
      oracle: 'finding-survives',
      pass: false,
      reason: `evasion: mutated variant is missing any finding of class ${capabilityClass}`,
      evidence: {
        class: capabilityClass,
        afterKind: after.kind,
        afterFindingClasses: (after.kind === 'ok' || after.kind === 'fail-safe')
          ? after.findings.map((f) => f.capabilityClass)
          : [],
      },
    };
  }

  return { oracle: 'finding-survives', pass: true };
}
