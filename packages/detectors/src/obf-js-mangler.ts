// port from guarddog:threat-runtime-obfuscation-js-mangling
/**
 * OBF detector — JavaScript variable-name mangling fingerprint.
 *
 * Rationale (audit §1 G-01): commercial JS obfuscators (javascript-obfuscator,
 * obfuscator.io) rewrite every identifier as `_0x` + hex — e.g. `_0x1a2b3c`,
 * `_0x4d5e`. This mangling style is a tell-tale supply-chain-attack shape:
 * `obf.entropy-jump` catches the aggregate entropy increase but does not name
 * the specific mangler fingerprint, so a partially-mangled file that stays
 * under the entropy threshold slips today.
 *
 * DIFFERENCE FROM GUARDDOG'S PORT: the audit describes scanning raw file text
 * for `_0x[a-f0-9]{4,6}\b` identifiers. In vetlock's diff-native design,
 * detectors read the FileCapabilities surface — the raw file text is discarded
 * after `extractCapabilities` runs, so we can't grep it directly here. What we
 * CAN reach is the set of source-line snippets already captured for tracked
 * APIs: every `dynamicCode[].snippet`, `envAccesses[].snippet`, and
 * `suspiciousLiterals[].preview` field holds up-to-240-char slices of the
 * original source. Mangler-obfuscated files call MANY tracked APIs (require,
 * eval, process.env, Function, char-arithmetic decoders) so at least one such
 * snippet almost always carries the `_0x` fingerprint.
 *
 * We fire when ≥3 distinct `_0x[a-f0-9]{4,6}` identifiers show up across the
 * per-file snippet set AND the file is either NEW to `pair.new` or entirely
 * new in an ADDED package. This is diff-safe by construction: a file whose
 * old version already contained the same mangler fingerprint does NOT fire
 * (comparing per-file snippet sets between old and new).
 *
 * Severity WARN, medium confidence. Escalates to BLOCK when the same package
 * ships co-occurring NET/INSTALL/EXEC/ENV/FS findings — see runAll()
 * escalation rule 1.
 */

import type { Detector, Finding, FileCapabilities, PackageSnapshot, SnapshotPair } from '@vetlock/core';
import { directionFor } from './direction.js';

/** javascript-obfuscator's standard mangled-identifier signature. */
const MANGLED_ID_RE = /_0x[a-f0-9]{4,6}\b/g;

/** Minimum distinct mangled identifiers before we call it a mangler fingerprint. */
const MANGLER_THRESHOLD = 3;

/**
 * Return the set of distinct mangled identifiers reachable via the already-
 * captured snippets on a FileCapabilities record.
 */
function mangledIdsInFile(file: FileCapabilities): Set<string> {
  const ids = new Set<string>();
  const scan = (s: string | undefined | null): void => {
    if (!s) return;
    for (const m of s.matchAll(MANGLED_ID_RE)) ids.add(m[0]);
  };
  for (const site of file.dynamicCode) scan(site.snippet);
  for (const acc of file.envAccesses) scan(acc.snippet);
  for (const lit of file.suspiciousLiterals) scan(lit.preview);
  return ids;
}

/**
 * Only scan sources that could plausibly carry mangled identifiers — the
 * JS/TS family. JSON files have no identifiers; skip them so the detector
 * doesn't accidentally match unrelated `_0x` hex strings in data files.
 */
function isJsLikeSource(path: string): boolean {
  return /\.(m?js|cjs|jsx|ts|tsx)$/i.test(path);
}

function buildFilesByPath(snap: PackageSnapshot | null): Map<string, FileCapabilities> {
  const map = new Map<string, FileCapabilities>();
  if (!snap) return map;
  for (const f of snap.files) map.set(f.path, f);
  return map;
}

export const obfJsManglerSignatureDetector: Detector = {
  id: 'obf-js-mangler',
  category: 'OBF',
  run(pair: SnapshotPair): Finding[] {
    if (!pair.new) return [];
    const dir = directionFor(pair.old);
    const oldByPath = buildFilesByPath(pair.old);
    const isAdded = pair.old === null;
    const out: Finding[] = [];

    for (const nf of pair.new.files) {
      if (!isJsLikeSource(nf.path)) continue;
      const newIds = mangledIdsInFile(nf);
      if (newIds.size < MANGLER_THRESHOLD) continue;

      // Diff-safety: subtract identifiers already present in the OLD version
      // of this file (if any). Only NEW mangled identifiers count. A file
      // whose old version already had the mangler fingerprint does not
      // re-fire on a routine version bump.
      const oldFile = oldByPath.get(nf.path);
      let onlyNewIds = newIds;
      if (oldFile) {
        const oldIds = mangledIdsInFile(oldFile);
        onlyNewIds = new Set([...newIds].filter((id) => !oldIds.has(id)));
        if (onlyNewIds.size < MANGLER_THRESHOLD) continue;
      }

      const sample = [...onlyNewIds].slice(0, 5).join(', ');
      out.push({
        detector: 'obf.js-mangler-signature',
        category: 'OBF',
        package: pair.new.name,
        from: dir.from,
        to: pair.new.version,
        direction: dir.direction,
        severity: 'WARN',
        confidence: isAdded ? 'medium' : 'high',
        message: isAdded
          ? `Newly-installed package ships file ${nf.path} with JavaScript-obfuscator mangled identifiers (${onlyNewIds.size} distinct \`_0x\` names, e.g. ${sample}).`
          : `File ${nf.path} newly contains JavaScript-obfuscator mangled identifiers (${onlyNewIds.size} distinct \`_0x\` names, e.g. ${sample}).`,
        evidence: [
          {
            file: nf.path,
            line: 1,
            snippet: `mangled identifiers: ${sample}`.slice(0, 240),
          },
        ],
        provenance: [],
      });
    }

    return out;
  },
};

/** Exported for tests. */
export { MANGLED_ID_RE, MANGLER_THRESHOLD, mangledIdsInFile };
