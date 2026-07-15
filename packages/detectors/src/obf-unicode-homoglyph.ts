// port from guarddog:threat-runtime-obfuscation-unicode
/**
 * OBF detector — Unicode homoglyph obfuscation boundary in JS/TS source.
 *
 * Rationale (audit §1 G-04): commercial obfuscators and attackers use
 * Cyrillic / Greek / Cherokee letters that visually resemble ASCII letters
 * (`а` = Cyrillic small a, `е` = Cyrillic small e, `ο` = Greek small omicron)
 * inside identifiers, string literals, and URLs. A package that never shipped
 * a non-ASCII letter in code that suddenly starts to is exactly the shape a
 * diff-native scanner should catch. vetlock's `typo.ts` already normalizes
 * PACKAGE NAMES; this ports the SOURCE-CODE side.
 *
 * DIFFERENCE FROM GUARDDOG'S PORT: guarddog scans raw source bytes for the
 * ASCII↔non-ASCII boundary. vetlock detectors read the FileCapabilities
 * surface — no raw text. We scan the strings that ARE captured:
 *   - `urlLiterals[]` (a URL like `https://gοogle.com` with Greek `ο`)
 *   - `suspiciousLiterals[].preview` (40-char samples of long string literals)
 *   - `dynamicCode[].snippet` (240-char source lines of tracked API calls)
 *   - `envAccesses[].snippet` (240-char source lines of process.env reads)
 *
 * Detection rule (per audit): a boundary where an ASCII letter is IMMEDIATELY
 * adjacent to a non-ASCII letter from the confusable set. Legitimate multi-
 * language content (a Chinese docstring, a Russian error message) does NOT
 * trip this — those have whole non-ASCII spans with no ASCII adjacency
 * inside identifiers.
 *
 * We fire in both diff-mode (any new NEW/CHANGED file has a boundary
 * that wasn't in the old version's same-path file) and added-package mode.
 * Severity WARN, medium confidence. Escalates to BLOCK via runAll() rule 1.
 */

import type { Detector, Finding, FileCapabilities, PackageSnapshot, SnapshotPair } from '@vetlock/core';
import { directionFor } from './direction.js';

/**
 * Unicode ranges we treat as "confusable with ASCII" — used as the non-ASCII
 * side of the boundary check. Keeping the set tight (only the alphabetic
 * ranges most commonly abused) reduces false positives from legitimate CJK
 * or Arabic content that a legit i18n package might ship.
 *
 *   - U+0400–U+04FF  Cyrillic
 *   - U+0370–U+03FF  Greek and Coptic
 *   - U+13A0–U+13FF  Cherokee (used in known homoglyph attacks — 2024 GitHub)
 *   - U+1D400–U+1D7FF Mathematical Alphanumeric Symbols (𝐚 𝐛 𝐜…)
 */
const CONFUSABLE_RE =
  /(?:[A-Za-z][Ͱ-ϿЀ-ӿᎠ-᏿\u{1D400}-\u{1D7FF}])|(?:[Ͱ-ϿЀ-ӿᎠ-᏿\u{1D400}-\u{1D7FF}][A-Za-z])/u;

/**
 * Scan every source-adjacent string on a FileCapabilities record and return
 * the first sample that shows an ASCII↔confusable boundary, or null.
 */
function firstHomoglyphSample(file: FileCapabilities): string | null {
  for (const u of file.urlLiterals) {
    if (CONFUSABLE_RE.test(u)) return u;
  }
  for (const lit of file.suspiciousLiterals) {
    if (CONFUSABLE_RE.test(lit.preview)) return lit.preview;
  }
  for (const site of file.dynamicCode) {
    if (site.snippet && CONFUSABLE_RE.test(site.snippet)) return site.snippet;
  }
  for (const acc of file.envAccesses) {
    if (acc.snippet && CONFUSABLE_RE.test(acc.snippet)) return acc.snippet;
  }
  return null;
}

function isJsLikeSource(path: string): boolean {
  return /\.(m?js|cjs|jsx|ts|tsx)$/i.test(path);
}

function buildFilesByPath(snap: PackageSnapshot | null): Map<string, FileCapabilities> {
  const map = new Map<string, FileCapabilities>();
  if (!snap) return map;
  for (const f of snap.files) map.set(f.path, f);
  return map;
}

export const obfUnicodeHomoglyphDetector: Detector = {
  id: 'obf-unicode-homoglyph',
  category: 'OBF',
  run(pair: SnapshotPair): Finding[] {
    if (!pair.new) return [];
    const dir = directionFor(pair.old);
    const oldByPath = buildFilesByPath(pair.old);
    const isAdded = pair.old === null;
    const out: Finding[] = [];

    for (const nf of pair.new.files) {
      if (!isJsLikeSource(nf.path)) continue;
      const sample = firstHomoglyphSample(nf);
      if (!sample) continue;

      // Diff-safety: if the OLD version of this file already had a homoglyph
      // boundary in ANY of its captured samples, don't fire on the new one.
      // That's an old-state signal, not a diff-frame delta.
      const oldFile = oldByPath.get(nf.path);
      if (oldFile && firstHomoglyphSample(oldFile)) continue;

      out.push({
        detector: 'obf.unicode-homoglyph-boundary',
        category: 'OBF',
        package: pair.new.name,
        from: dir.from,
        to: pair.new.version,
        direction: dir.direction,
        severity: 'WARN',
        confidence: 'medium',
        message: isAdded
          ? `Newly-installed package ships file ${nf.path} with ASCII↔non-ASCII (Cyrillic / Greek / Cherokee / Math) letter adjacency — Unicode homoglyph obfuscation shape.`
          : `File ${nf.path} newly contains ASCII↔non-ASCII (Cyrillic / Greek / Cherokee / Math) letter adjacency — Unicode homoglyph obfuscation shape.`,
        evidence: [
          {
            file: nf.path,
            line: 1,
            snippet: `homoglyph sample: ${sample}`.slice(0, 240),
          },
        ],
        provenance: [],
      });
    }

    return out;
  },
};

/** Exported for tests. */
export { CONFUSABLE_RE, firstHomoglyphSample };
