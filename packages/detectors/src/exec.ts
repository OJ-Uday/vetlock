/**
 * EXEC detector — new process/exec capability.
 * BLOCK, high. Fires when a new file (or a previously-existing file) references
 * a process/exec module that wasn't in the old snapshot.
 */

import type { Detector, Finding, SnapshotPair } from '@vetlock/core';
import { directionFor } from './direction.js';

export const execDetector: Detector = {
  id: 'exec',
  category: 'EXEC',
  run(pair: SnapshotPair): Finding[] {
    if (!pair.old || !pair.new) return [];
    const dir = directionFor(pair.old);
    const oldMods = new Set<string>();
    for (const f of pair.old.files) for (const m of f.execModules) oldMods.add(m);
    const out: Finding[] = [];
    const seen = new Set<string>();
    for (const f of pair.new.files) {
      for (const m of f.execModules) {
        if (oldMods.has(m) || seen.has(m)) continue;
        seen.add(m);
        out.push({
          detector: 'exec.new-module',
          category: 'EXEC',
          package: pair.new.name,
          from: dir.from,
          to: pair.new.version,
          direction: dir.direction,
          severity: 'BLOCK',
          confidence: 'high',
          message: `Package started using process/execution module "${m}".`,
          evidence: [{ file: f.path, line: 1, snippet: `imports ${m}` }],
          provenance: [],
        });
      }
    }
    return out;
  },
};
