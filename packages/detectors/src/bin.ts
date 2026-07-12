/**
 * BIN detector — new native binary artifacts appearing in the tarball.
 *
 * Real npm packages that ship native code (e.g. sharp, node-sass, better-sqlite3)
 * DO ship .node files. What we care about is:
 *   - A package that never shipped native code suddenly does.
 *   - A package added a NEW native artifact whose sha256 didn't exist before.
 *
 * BLOCK, high. Applies both to updated packages and (importantly) to newly-added
 * packages whose FIRST version already ships a native binary — a fresh package
 * with a native binary and no build-from-source workflow is a huge red flag.
 */

import type { Detector, Finding, PackageSnapshot, SnapshotPair } from '@vetlock/core';
import { directionFor } from './direction.js';

export const binDetector: Detector = {
  id: 'bin',
  category: 'INSTALL',
  run(pair: SnapshotPair): Finding[] {
    if (!pair.new) return [];
    const dir = directionFor(pair.old);
    const oldArts = collectArts(pair.old);
    const out: Finding[] = [];
    const seen = new Set<string>();
    for (const na of pair.new.nativeArtifacts) {
      const key = `${na.path}|${na.sha256}`;
      if (oldArts.has(key) || seen.has(key)) continue;
      seen.add(key);
      // Also skip if the same path existed with a different hash — that would
      // be reported by fs.new-hotpath-write / integrity anyway. Actually we
      // WANT to catch that here: a native artifact whose CONTENT changed is
      // itself a signal.
      out.push({
        detector: 'bin.new-native-artifact',
        category: 'INSTALL',
        package: pair.new.name,
        from: dir.from,
        to: pair.new.version,
        direction: dir.direction,
        severity: 'BLOCK',
        confidence: 'high',
        message: `New native binary artifact shipped in tarball: ${na.path} (${na.kind}, ${na.bytes} bytes)`,
        evidence: [
          {
            file: na.path,
            line: 1,
            snippet: `${na.kind} artifact, sha256=${na.sha256.slice(0, 16)}…`,
          },
        ],
        provenance: [],
      });
    }
    return out;
  },
};

function collectArts(snap: PackageSnapshot | null): Set<string> {
  const s = new Set<string>();
  if (!snap) return s;
  for (const na of snap.nativeArtifacts) s.add(`${na.path}|${na.sha256}`);
  return s;
}
