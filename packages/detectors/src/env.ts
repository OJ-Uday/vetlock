/**
 * ENV detector — new sensitive-token reads or whole-object enumeration of
 * process.env.
 * BLOCK, high.
 */

import type { Detector, Finding, PackageSnapshot, SnapshotPair, EnvAccess } from '@vetlock/core';
import { SENSITIVE_ENV_KEYS } from '@vetlock/core';
import { directionFor } from './direction.js';

const SENSITIVE_SET = new Set(SENSITIVE_ENV_KEYS);

function isSensitive(keys: string[] | null): boolean {
  if (keys === null) return true; // whole-object enumeration is itself suspicious
  return keys.some((k) => SENSITIVE_SET.has(k));
}

function envKey(a: EnvAccess): string {
  return (a.keys ?? ['*']).sort().join(',');
}

function collectEnvKeys(snap: PackageSnapshot | null): Set<string> {
  const s = new Set<string>();
  if (!snap) return s;
  for (const f of snap.files) {
    for (const a of f.envAccesses) {
      if (isSensitive(a.keys)) s.add(envKey(a));
    }
  }
  return s;
}

export const envDetector: Detector = {
  id: 'env',
  category: 'ENV',
  run(pair: SnapshotPair): Finding[] {
    if (!pair.new) return [];
    const dir = directionFor(pair.old);
    const oldSensitive = collectEnvKeys(pair.old);
    const out: Finding[] = [];
    const seen = new Set<string>();
    for (const f of pair.new.files) {
      for (const a of f.envAccesses) {
        if (!isSensitive(a.keys)) continue;
        const k = envKey(a);
        if (oldSensitive.has(k) || seen.has(k)) continue;
        seen.add(k);
        const label =
          a.keys === null ? 'whole-object process.env enumeration' : a.keys.join(',');
        out.push({
          detector: 'env.token-harvest',
          category: 'ENV',
          package: pair.new.name,
          from: dir.from,
          to: pair.new.version,
          direction: dir.direction,
          severity: 'BLOCK',
          confidence: 'high',
          message: `Package started reading sensitive env: ${label}`,
          evidence: [{ file: f.path, line: a.line, snippet: a.snippet.slice(0, 240) }],
          provenance: [],
        });
      }
    }
    return out;
  },
};
