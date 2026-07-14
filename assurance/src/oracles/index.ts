/**
 * The shared oracle set (ADR-0002 modality-agnostic assertion library).
 *
 * Every modality (property tests, corpus, generative fuzzers, agent panel) feeds its
 * bounded engine outcomes through these oracles. A gap found by any modality becomes an
 * oracle failure, which becomes a corpus regression, which becomes a permanent test.
 */

export type {
  Finding,
  Findings,
  SerializedError,
  Bounds,
  RunOutcome,
  OracleResult,
} from './types.js';

export { oracleNoCrash } from './no-crash.js';
export { oracleNoHang } from './no-hang.js';
export { oracleNoOom } from './no-oom.js';
export { oracleFailSafe, type FailSafeExpectation } from './fail-safe.js';
export { oracleFindingSurvives } from './finding-survives.js';
export { oracleIdentityInvariant } from './identity-invariant.js';
