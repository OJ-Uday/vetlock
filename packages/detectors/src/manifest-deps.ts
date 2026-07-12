/**
 * DEPS manifest detector — new direct dependency keys in package.json.
 * INFO, medium. This is a manifest-level detector; the ENGINE-level DEPS graph
 * detector (new transitive nodes across the whole tree) lives in the engine.
 */

import type { Detector, Finding, SnapshotPair } from '@vetlock/core';
import { directionFor } from './direction.js';

export const depsManifestDetector: Detector = {
  id: 'deps-manifest',
  category: 'DEPS',
  run(pair: SnapshotPair): Finding[] {
    if (!pair.old || !pair.new) return [];
    const dir = directionFor(pair.old);
    const oldDeps = { ...pair.old.manifest.dependencies };
    const newDeps = { ...pair.new.manifest.dependencies };
    const out: Finding[] = [];
    for (const [name, version] of Object.entries(newDeps)) {
      if (name in oldDeps) continue;
      out.push({
        detector: 'deps.new-direct-dep',
        category: 'DEPS',
        package: pair.new.name,
        from: dir.from,
        to: pair.new.version,
        direction: dir.direction,
        severity: 'INFO',
        confidence: 'medium',
        message: `New direct dependency added to package: ${name}@${version}`,
        evidence: [{ file: 'package.json', line: 1, snippet: `"${name}": "${version}"` }],
        provenance: [],
      });
    }
    return out;
  },
};
