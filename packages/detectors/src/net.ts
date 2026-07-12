/**
 * NET detector — new network capability.
 *
 * Two sub-findings, both diff-only (skip when pair.old is null):
 *   - net.new-module    (WARN, medium) — a network module now imported that wasn't before
 *   - net.new-endpoint  (BLOCK, high)  — a URL literal now present that wasn't before
 *
 * URL literals dedup across files; first-seen evidence is used.
 */

import type { Detector, Finding, PackageSnapshot, SnapshotPair } from '@vetlock/core';
import { directionFor } from './direction.js';

export const netDetector: Detector = {
  id: 'net',
  category: 'NET',
  run(pair: SnapshotPair): Finding[] {
    if (!pair.old || !pair.new) return [];
    const dir = directionFor(pair.old);

    const out: Finding[] = [];
    const oldMods = collectModules(pair.old, (f) => f.networkModules);
    const newMods = collectModules(pair.new, (f) => f.networkModules);
    for (const [mod, evidence] of newMods.entries()) {
      if (oldMods.has(mod)) continue;
      out.push({
        detector: 'net.new-module',
        category: 'NET',
        package: pair.new.name,
        from: dir.from,
        to: pair.new.version,
        direction: dir.direction,
        severity: 'WARN',
        confidence: 'medium',
        message: `Package started using network module "${mod}".`,
        evidence: [evidence],
        provenance: [],
      });
    }

    const oldUrls = collectUrls(pair.old);
    const newUrls = collectUrls(pair.new);
    for (const [url, evidence] of newUrls.entries()) {
      if (oldUrls.has(url)) continue;
      out.push({
        detector: 'net.new-endpoint',
        category: 'NET',
        package: pair.new.name,
        from: dir.from,
        to: pair.new.version,
        direction: dir.direction,
        severity: 'BLOCK',
        confidence: 'high',
        message: `New network endpoint appeared: ${url}`,
        evidence: [evidence],
        provenance: [],
      });
    }

    return out;
  },
};

function collectModules(
  snap: PackageSnapshot,
  pick: (f: PackageSnapshot['files'][number]) => string[],
): Map<string, { file: string; line: number; snippet: string }> {
  const map = new Map<string, { file: string; line: number; snippet: string }>();
  for (const f of snap.files) {
    for (const m of pick(f)) {
      if (!map.has(m)) map.set(m, { file: f.path, line: 1, snippet: `imports ${m}` });
    }
  }
  return map;
}

function collectUrls(
  snap: PackageSnapshot,
): Map<string, { file: string; line: number; snippet: string }> {
  const map = new Map<string, { file: string; line: number; snippet: string }>();
  for (const f of snap.files) {
    for (const u of f.urlLiterals) {
      if (!map.has(u)) map.set(u, { file: f.path, line: 1, snippet: u.slice(0, 240) });
    }
  }
  return map;
}
