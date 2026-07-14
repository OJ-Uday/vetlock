/**
 * oracleFailSafe — the composite fail-open detector.
 *
 * The engine fails toward safety when a hostile input either (a) is caught with findings,
 * (b) triggers the engine's own fail-safe path (BLOCK with reason `analysis-failed`),
 * (c) trips the runner's timeout or OOM bounds (the runner caught it), or (d) is a benign
 * input the caller didn't assert malice about.
 *
 * The engine fails OPEN — the outcome the harness exists to prevent — when:
 *   - It crashes (an exception escaped).
 *   - It returns `ok` with empty findings when the caller signals the input is malicious
 *     (`mustFindClass: '*'`).
 *   - It returns `ok` with findings but none of the required class (`mustFindClass: <class>`
 *     specific). This is the "sink-sibling swap" pattern the completeness doctrine targets.
 *
 * If `expected.mustFindClass` is omitted, the caller is not asserting malice and the oracle
 * only rejects crashes — empty findings on a benign input is fine.
 */

import type { Finding, Findings, OracleResult, RunOutcome } from './types.js';

export interface FailSafeExpectation {
  /**
   * Signals the caller's assertion about the input:
   *   - undefined: input is not asserted malicious. Only crashes fail the oracle.
   *   - '*'      : input IS malicious; ok with empty findings is a silent-green regression.
   *   - '<class>': input exhibits capability `<class>`; ok findings must include that class.
   */
  readonly mustFindClass?: string;
}

function findingsWithClass(findings: Findings, cls: string): readonly Finding[] {
  return findings.filter((f) => f.capabilityClass === cls);
}

export function oracleFailSafe(
  outcome: RunOutcome,
  expected: FailSafeExpectation = {},
): OracleResult {
  const { mustFindClass } = expected;

  // Any crash is fail-open.
  if (outcome.kind === 'crash') {
    return {
      oracle: 'fail-safe',
      pass: false,
      reason: `engine let an exception escape (${outcome.error.name}: ${outcome.error.message})`,
      evidence: { kind: outcome.kind, errorName: outcome.error.name, errorMessage: outcome.error.message },
    };
  }

  // Timeouts and OOM are the runner catching a pathology — safe by construction.
  if (outcome.kind === 'timeout' || outcome.kind === 'oom') {
    return { oracle: 'fail-safe', pass: true };
  }

  // Fail-safe outcomes are the engine's give-up path with a BLOCK finding attached.
  if (outcome.kind === 'fail-safe') {
    // If a class was required, require it in the fail-safe's own findings.
    if (mustFindClass && mustFindClass !== '*') {
      const matched = findingsWithClass(outcome.findings, mustFindClass);
      if (matched.length === 0) {
        return {
          oracle: 'fail-safe',
          pass: false,
          reason: `fail-safe path did not attach a finding of required class ${mustFindClass}`,
          evidence: { kind: outcome.kind, mustFindClass, findingClasses: outcome.findings.map((f) => f.capabilityClass) },
        };
      }
    }
    return { oracle: 'fail-safe', pass: true };
  }

  // ok — the ordinary verdict path.
  // Case A: caller didn't assert malice → any findings shape is fine.
  if (!mustFindClass) {
    return { oracle: 'fail-safe', pass: true };
  }

  // Case B: caller asserted malice with wildcard → any finding at all is enough.
  if (mustFindClass === '*') {
    if (outcome.findings.length > 0) {
      return { oracle: 'fail-safe', pass: true };
    }
    return {
      oracle: 'fail-safe',
      pass: false,
      reason: 'silent-green: engine returned ok with no findings on a known-malicious input (fail-open)',
      evidence: { kind: outcome.kind, mustFindClass, findingCount: 0 },
    };
  }

  // Case C: caller asserted a specific class must appear.
  const matched = findingsWithClass(outcome.findings, mustFindClass);
  if (matched.length > 0) {
    return { oracle: 'fail-safe', pass: true };
  }
  return {
    oracle: 'fail-safe',
    pass: false,
    reason: `engine returned ok but missed the required capability class ${mustFindClass}`,
    evidence: {
      kind: outcome.kind,
      mustFindClass,
      findingClasses: outcome.findings.map((f) => f.capabilityClass),
    },
  };
}
