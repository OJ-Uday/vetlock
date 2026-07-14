/**
 * oracleNoCrash — fails only when the engine let an exception escape.
 *
 * Timeouts, OOM, and fail-safe are all *not* crashes — they're bounded or engine-signaled
 * give-ups that the harness accepts. A crash means the analyzer let an unhandled exception
 * cross the worker boundary, which violates ADR-0003's fail-safe convention.
 */

import type { OracleResult, RunOutcome } from './types.js';

export function oracleNoCrash(outcome: RunOutcome): OracleResult {
  if (outcome.kind !== 'crash') {
    return { oracle: 'no-crash', pass: true };
  }
  return {
    oracle: 'no-crash',
    pass: false,
    reason: `engine crashed with ${outcome.error.name}: ${outcome.error.message}`,
    evidence: {
      errorName: outcome.error.name,
      errorMessage: outcome.error.message,
      stack: outcome.error.stack,
      wallMs: outcome.wallMs,
    },
  };
}
