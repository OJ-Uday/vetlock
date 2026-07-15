/**
 * JSON renderer — versioned, stable field order (recursively sorted for byte-identical output).
 */

import type { RunResult } from '@vetlock/core';

export const JSON_SCHEMA_VERSION = 1;

function sortReplacer(_key: string, value: unknown): unknown {
  if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b)),
    );
  }
  return value;
}

export function renderJSON(result: RunResult): string {
  return JSON.stringify(
    { schemaVersion: JSON_SCHEMA_VERSION, ...result },
    sortReplacer,
    2,
  );
}
