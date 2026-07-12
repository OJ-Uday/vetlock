/**
 * FS-READ detector — reads of sensitive hot-path files (secrets exfil).
 *
 * The eslint-scope 2018 attack signature: fs.readFileSync(~/.npmrc). Also
 * catches reads of id_rsa, .aws/credentials, .git-credentials, wallet files.
 *
 * BLOCK, high. Fires on new fsReadTargets literals matching the hot-path list.
 */

import type { Detector, Finding, SnapshotPair } from '@vetlock/core';
import { directionFor } from './direction.js';
import { HOT_PATH_PATTERNS } from './fs-hotpaths.js';

export const fsReadDetector: Detector = {
  id: 'fs-read',
  category: 'FS',
  run(pair: SnapshotPair): Finding[] {
    if (!pair.new) return [];
    const dir = directionFor(pair.old);
    const oldReads = new Set<string>();
    if (pair.old) for (const f of pair.old.files) for (const t of f.fsReadTargets) oldReads.add(t);
    const out: Finding[] = [];
    const seen = new Set<string>();
    for (const f of pair.new.files) {
      for (const t of f.fsReadTargets) {
        if (oldReads.has(t) || seen.has(t)) continue;
        if (!HOT_PATH_PATTERNS.some((r) => r.test(t))) continue;
        seen.add(t);
        out.push({
          detector: 'fs.new-hotpath-read',
          category: 'FS',
          package: pair.new.name,
          from: dir.from,
          to: pair.new.version,
          direction: dir.direction,
          severity: 'BLOCK',
          confidence: 'high',
          message: `New file-system read of sensitive path: ${t}`,
          evidence: [{ file: f.path, line: 1, snippet: `fs.readFile("${t}", …)` }],
          provenance: [],
        });
      }
    }
    return out;
  },
};
