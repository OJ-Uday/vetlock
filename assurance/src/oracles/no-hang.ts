/**
 * oracleNoHang — fails only on `timeout`.
 *
 * All other outcomes are on different axes: ok is normal, oom is a heap trip, crash is a
 * different bug (caught by oracleNoCrash), fail-safe is the engine giving up cleanly.
 * A timeout means the runner terminated the worker at its wallMs bound. The whole point of
 * the bound is that a real hang looks like a hang, not an infinite CI job (ADR-0003).
 */

import type { OracleResult, RunOutcome } from './types.js';

export function oracleNoHang(outcome: RunOutcome): OracleResult {
  if (outcome.kind !== 'timeout') {
    return { oracle: 'no-hang', pass: true };
  }
  return {
    oracle: 'no-hang',
    pass: false,
    reason: `engine hung — timeout at ${outcome.wallMs}ms`,
    evidence: { wallMs: outcome.wallMs, seed: outcome.seed },
  };
}
