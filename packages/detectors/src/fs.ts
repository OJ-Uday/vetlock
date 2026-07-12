/**
 * FS detector — new writes to sensitive "hot" paths.
 * BLOCK, high. Only fires on ADDED fsWriteTargets whose literal matches a
 * curated hot-path pattern.
 */

import type { Detector, Finding, SnapshotPair } from '@vetlock/core';
import { directionFor } from './direction.js';
import { HOT_PATH_PATTERNS } from './fs-hotpaths.js';

function isHotpath(target: string): boolean {
  return HOT_PATH_PATTERNS.some((r) => r.test(target));
}

export const fsDetector: Detector = {
  id: 'fs',
  category: 'FS',
  run(pair: SnapshotPair): Finding[] {
    if (!pair.new) return [];
    const dir = directionFor(pair.old);
    const oldTargets = new Set<string>();
    if (pair.old) {
      for (const f of pair.old.files) for (const t of f.fsWriteTargets) oldTargets.add(t);
    }
    const out: Finding[] = [];
    const seen = new Set<string>();
    for (const f of pair.new.files) {
      for (const t of f.fsWriteTargets) {
        if (oldTargets.has(t) || seen.has(t)) continue;
        if (!isHotpath(t)) continue;
        seen.add(t);
        out.push({
          detector: 'fs.new-hotpath-write',
          category: 'FS',
          package: pair.new.name,
          from: dir.from,
          to: pair.new.version,
          direction: dir.direction,
          severity: 'BLOCK',
          confidence: 'high',
          message: `New file-system write to sensitive path: ${t}`,
          evidence: [{ file: f.path, line: 1, snippet: `fs.writeFile("${t}", ...)` }],
          provenance: [],
        });
      }
    }
    return out;
  },
};
