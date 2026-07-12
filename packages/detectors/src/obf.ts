/**
 * OBF detector — obfuscation-jump indicators.
 * WARN, medium. The engine may escalate to BLOCK when co-occurring with NET or
 * INSTALL findings (that's an engine-layer concern; here we just emit WARN).
 *
 * Triggers per (file present in both snapshots):
 *   - entropy jumped by > 1.5 bits/byte between old and new
 *   - source was not minified before but is now (readable → minified regression)
 *   - suspicious literals appear where none did before
 */

import type { Detector, Finding, PackageSnapshot, SnapshotPair } from '@vetlock/core';

function byPath(snap: PackageSnapshot | null) {
  const m = new Map<string, PackageSnapshot['files'][number]>();
  if (!snap) return m;
  for (const f of snap.files) m.set(f.path, f);
  return m;
}

export const obfDetector: Detector = {
  id: 'obf',
  category: 'OBF',
  run(pair: SnapshotPair): Finding[] {
    if (!pair.new) return [];
    if (!pair.old) return []; // no baseline for entropy jump; new-node full-scan is a different detector
    const oldByPath = byPath(pair.old);
    const out: Finding[] = [];
    for (const nf of pair.new.files) {
      const of = oldByPath.get(nf.path);
      if (!of) continue;
      const reasons: string[] = [];
      if (nf.entropy - of.entropy > 1.5) {
        reasons.push(`entropy ${of.entropy.toFixed(2)} → ${nf.entropy.toFixed(2)} bits/byte`);
      }
      if (!of.minified && nf.minified) {
        reasons.push('source was not minified before, is now');
      }
      const oldHadSusp = of.suspiciousLiterals.length > 0;
      if (!oldHadSusp && nf.suspiciousLiterals.length > 0) {
        reasons.push(`${nf.suspiciousLiterals.length} suspicious high-entropy literal(s) appeared`);
      }
      if (reasons.length === 0) continue;
      out.push({
        detector: 'obf.entropy-jump',
        category: 'OBF',
        package: pair.new.name,
        from: pair.old.version,
        to: pair.new.version,
        direction: 'changed',
        severity: 'WARN',
        confidence: 'medium',
        message: `Obfuscation indicators appeared in ${nf.path}: ${reasons.join('; ')}`,
        evidence: [{ file: nf.path, line: 1, snippet: reasons.join('; ').slice(0, 240) }],
        provenance: [],
      });
    }
    return out;
  },
};
