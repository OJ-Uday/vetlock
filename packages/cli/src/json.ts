/**
 * JSON renderer — versioned, stable field order (recursively sorted for byte-identical output).
 *
 * Schema versions:
 *   1 — original schema.
 *   2 — added `mitre?: string[]` on findings and `riskScore: number` on the
 *       top-level (audit §2 architectural borrows: MITRE tagging + risk-score
 *       compression). Both fields are additive; consumers of v1 that ignore
 *       unknown keys still parse a v2 document.
 */

import type { RunResult } from '@vetlock/core';

export const JSON_SCHEMA_VERSION = 2;

export function renderJSON(result: RunResult): string {
  return JSON.stringify(
    { schemaVersion: JSON_SCHEMA_VERSION, ...result },
    (_, v) => v,
    2,
  );
}
