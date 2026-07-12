/**
 * CODE detector — new dynamic loading sinks.
 * WARN, medium. Fires when any dynamicCode entry is present in new but not old
 * (by file+kind+line — different lines count as different).
 */

import type { Detector, Finding, PackageSnapshot, SnapshotPair, DynamicCodeSite } from '@vetlock/core';
import { directionFor } from './direction.js';

function key(f: string, d: DynamicCodeSite): string {
  return `${f}:${d.line}:${d.kind}`;
}

function collectSites(snap: PackageSnapshot | null): Set<string> {
  const s = new Set<string>();
  if (!snap) return s;
  for (const f of snap.files) for (const d of f.dynamicCode) s.add(key(f.path, d));
  return s;
}

export const codeDetector: Detector = {
  id: 'code',
  category: 'CODE',
  run(pair: SnapshotPair): Finding[] {
    if (!pair.new) return [];
    const dir = directionFor(pair.old);
    const oldSet = collectSites(pair.old);
    const out: Finding[] = [];
    for (const f of pair.new.files) {
      for (const d of f.dynamicCode) {
        if (oldSet.has(key(f.path, d))) continue;
        out.push({
          detector: 'code.dynamic-loading-added',
          category: 'CODE',
          package: pair.new.name,
          from: dir.from,
          to: pair.new.version,
          direction: dir.direction,
          severity: 'WARN',
          confidence: 'medium',
          message: `Dynamic code sink introduced (${d.kind}).`,
          evidence: [{ file: f.path, line: d.line, snippet: d.snippet.slice(0, 240) }],
          provenance: [],
        });
      }
    }
    return out;
  },
};
