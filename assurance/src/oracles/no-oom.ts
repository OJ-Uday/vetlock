/**
 * oracleNoOom — fails only on `oom`.
 *
 * See oracleNoHang for the axis independence rationale. The runner passes
 * `resourceLimits.maxOldGenerationSizeMb` to `worker_threads.Worker`; when the worker's V8
 * heap blows past that cap, Node kills the worker and the runner reports `kind: 'oom'`.
 */

import type { OracleResult, RunOutcome } from './types.js';

export function oracleNoOom(outcome: RunOutcome): OracleResult {
  if (outcome.kind !== 'oom') {
    return { oracle: 'no-oom', pass: true };
  }
  return {
    oracle: 'no-oom',
    pass: false,
    reason: `engine exhausted the heap cap (peak ${outcome.peakRssBytes} bytes)`,
    evidence: { peakRssBytes: outcome.peakRssBytes, seed: outcome.seed },
  };
}
