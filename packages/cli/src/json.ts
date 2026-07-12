/**
 * JSON renderer — versioned, stable field order (recursively sorted for byte-identical output).
 */

import type { RunResult } from '@vetlock/core';

export const JSON_SCHEMA_VERSION = 1;

export function renderJSON(result: RunResult): string {
  return JSON.stringify(
    { schemaVersion: JSON_SCHEMA_VERSION, ...result },
    (_, v) => v,
    2,
  );
}
