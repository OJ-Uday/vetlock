/**
 * EXEC detector — new process/exec capability.
 *
 * v0.4.2 FP-STUDY §3d — severity downgraded from BLOCK to WARN.
 * Rationale: a legit library first-using `node:child_process` or
 * `node:worker_threads` is a real behavioral change but not on its own an
 * attack signal. commander@11→12 legitimately started using child_process
 * for its test infrastructure; that was BLOCK on v0.4.1, false positive.
 * Attack shapes (fetch-then-spawn, env-then-spawn) still promote to BLOCK
 * via compound-suspicion escalation in index.ts when co-occurring with
 * NET / INSTALL / ENV / FS findings.
 *
 * Fires when a new file (or a previously-existing file) references a
 * process/exec module that wasn't in the old snapshot.
 */

import type { Detector, Finding, SnapshotPair } from '@vetlock/core';
import { directionFor } from './direction.js';

export const execDetector: Detector = {
  id: 'exec',
  category: 'EXEC',
  run(pair: SnapshotPair): Finding[] {
    if (!pair.new) return [];
    const dir = directionFor(pair.old);
    const oldMods = new Set<string>();
    if (pair.old) for (const f of pair.old.files) for (const m of f.execModules) oldMods.add(m);
    const out: Finding[] = [];
    const seen = new Set<string>();
    for (const f of pair.new.files) {
      for (const m of f.execModules) {
        if (oldMods.has(m) || seen.has(m)) continue;
        seen.add(m);
        // On ADDED packages we mildly downgrade confidence — the mere presence
        // of child_process on a first-version package is common (build tools).
        const isAdded = pair.old === null;
        out.push({
          detector: 'exec.new-module',
          category: 'EXEC',
          package: pair.new.name,
          from: dir.from,
          to: pair.new.version,
          direction: dir.direction,
          severity: 'WARN',
          confidence: isAdded ? 'low' : 'medium',
          message: isAdded
            ? `Newly-installed package uses process/execution module "${m}".`
            : `Package started using process/execution module "${m}".`,
          evidence: [{ file: f.path, line: 1, snippet: `imports ${m}` }],
          provenance: [],
        });
      }
    }
    return out;
  },
};
