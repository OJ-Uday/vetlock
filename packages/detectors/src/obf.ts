/**
 * OBF detector — obfuscation indicators.
 * WARN, medium. Escalated to BLOCK by runAll when co-occurring with NET/INSTALL.
 *
 * Two paths:
 *   1) Diff-mode (both snapshots present): trigger per-file if entropy jumped,
 *      or minification appeared where none was, or suspicious literals showed up.
 *   2) Added-package mode (pair.old is null): trigger for any file that IS
 *      already minified OR contains suspicious literals. A first-version package
 *      shipping minified code with no source map is unusual for legitimate
 *      libraries and lines up with the ua-parser / rand-user-agent shape.
 */

import type { Detector, Finding, PackageSnapshot, SnapshotPair } from '@vetlock/core';
import { directionFor } from './direction.js';

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
    const dir = directionFor(pair.old);
    const out: Finding[] = [];

    if (pair.old) {
      // Diff mode
      const oldByPath = byPath(pair.old);
      for (const nf of pair.new.files) {
        const of = oldByPath.get(nf.path);
        if (of) {
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
        } else {
          // File is NEW inside an upgraded package — treat it like the added-package case
          if (nf.minified || nf.suspiciousLiterals.length > 0) {
            const reasons: string[] = [];
            if (nf.minified) reasons.push('shipped minified');
            if (nf.suspiciousLiterals.length > 0)
              reasons.push(`${nf.suspiciousLiterals.length} suspicious high-entropy literal(s)`);
            out.push({
              detector: 'obf.new-obfuscated-file',
              category: 'OBF',
              package: pair.new.name,
              from: pair.old.version,
              to: pair.new.version,
              direction: 'changed',
              severity: 'WARN',
              confidence: 'medium',
              message: `New file ${nf.path} appears obfuscated: ${reasons.join('; ')}`,
              evidence: [{ file: nf.path, line: 1, snippet: reasons.join('; ').slice(0, 240) }],
              provenance: [],
            });
          }
        }
      }
    } else {
      // Added-package mode
      for (const nf of pair.new.files) {
        if (!nf.minified && nf.suspiciousLiterals.length === 0) continue;
        const reasons: string[] = [];
        if (nf.minified) reasons.push('shipped minified');
        if (nf.suspiciousLiterals.length > 0)
          reasons.push(`${nf.suspiciousLiterals.length} suspicious high-entropy literal(s)`);
        out.push({
          detector: 'obf.new-obfuscated-file',
          category: 'OBF',
          package: pair.new.name,
          from: dir.from,
          to: pair.new.version,
          direction: dir.direction,
          severity: 'WARN',
          confidence: 'low',
          message: `Newly-installed package ships obfuscated file ${nf.path}: ${reasons.join('; ')}`,
          evidence: [{ file: nf.path, line: 1, snippet: reasons.join('; ').slice(0, 240) }],
          provenance: [],
        });
      }
    }

    return out;
  },
};
