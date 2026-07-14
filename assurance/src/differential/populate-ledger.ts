/**
 * populate-ledger — apply the seeded historical deltas to a DifferentialLedger.
 *
 * Called from:
 *   1. The differential-ledger-integration test (verifies every seeded delta lands in the
 *      classified pool and the ledger is clean).
 *   2. The report/differential-ledger.json committed snapshot script (`pnpm assurance:report`
 *      re-derives the on-disk ledger by calling this against a fresh instance and saving).
 *   3. Any future adapter integration: run the live adapter, then call this to fill in the
 *      known historical bucket, then classify anything new the live adapter surfaced. The
 *      ledger's `classify()` is idempotent per finding key so re-population is safe.
 *
 * The function is intentionally trivial — its value is documentary: it declares that the
 * ledger's content is the seeded-deltas table, nothing else.
 */

import type { DifferentialLedger } from './ledger.js';
import { seededDeltas } from './seeded-deltas.js';

/**
 * Load every seeded historical delta into `ledger`. Idempotent: calling twice on the same
 * ledger produces the same final state.
 *
 * The two-step pattern (`add` then `classify`) preserves the standard ledger workflow:
 * findings arrive as pending, then a classification decision moves them to classified.
 * A caller inspecting the ledger mid-population would see the same shape a live adapter
 * would produce.
 */
export function populateLedgerFromSeededDeltas(ledger: DifferentialLedger): void {
  for (const delta of seededDeltas) {
    ledger.add(delta.finding);
    ledger.classify(delta.finding, delta.rationale, delta.class);
  }
}
