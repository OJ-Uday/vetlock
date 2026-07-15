/**
 * OBF detector — obfuscation indicators.
 * WARN, medium. Escalated to BLOCK by runAll when co-occurring with NET/INSTALL/EXEC/ENV/FS.
 *
 * v0.4.2 FP-STUDY §3e — bundler-shipped minified entry files are DOWN-WEIGHTED.
 * A file that is the target of `package.json` `main`, `module`, `browser`, or
 * `exports.*` AND lives under a canonical build output directory (`dist/`,
 * `build/`, `lib/`, `es/`, `esm/`, `cjs/`, `umd/`) is expected to be minified —
 * that's how modern JS libraries ship. High-entropy literals inside a minified
 * bundle are the DEFAULT, not a signal.
 *
 * Effect: if a bundler-entry file trips the entropy/minified/suspicious-literal
 * heuristics AND ALSO is a declared entry AND lives in a canonical output dir,
 * the finding severity is downgraded to INFO and confidence to low. The
 * finding still emits (so audit trail is preserved), but doesn't drive
 * compound-suspicion escalation.
 *
 * A separately-shipped `.min.js` next to a readable source is still WARN.
 * A minified file NOT declared in the manifest (attacker slipping a bundle
 * in without declaring it) stays WARN.
 *
 * v0.4.1 measured impact: tsx / vite / webpack / vitest all trip
 * obf.new-obfuscated-file on their declared entry files (e.g. dist/index.mjs).
 * v0.4.2 target: those should be INFO not WARN.
 *
 * Two paths (both preserved from v0.4.0):
 *   1) Diff-mode (both snapshots present): trigger per-file if entropy jumped,
 *      or minification appeared where none was, or suspicious literals showed up.
 *   2) Added-package mode (pair.old is null): trigger for any file that IS
 *      already minified OR contains suspicious literals. A first-version package
 *      shipping minified code with no source map is unusual for legitimate
 *      libraries and lines up with the ua-parser / rand-user-agent shape.
 */

import type { Detector, Finding, PackageSnapshot, PackageManifest, SnapshotPair, Severity } from '@vetlock/core';
import { directionFor } from './direction.js';

function byPath(snap: PackageSnapshot | null) {
  const m = new Map<string, PackageSnapshot['files'][number]>();
  if (!snap) return m;
  for (const f of snap.files) m.set(f.path, f);
  return m;
}

/**
 * Extract the set of files declared as package entry points via
 * `main`, `module`, `browser`, `types`, or `exports`.
 * Paths are normalized (leading './' stripped) to match PackageSnapshot.files paths.
 *
 * Best-effort: `exports` can be a string, an object with subpath keys, or a nested
 * conditional-exports object. We walk it recursively and collect any string leaf
 * whose value looks like a relative path.
 */
function declaredEntryFiles(manifest: PackageManifest): Set<string> {
  const out = new Set<string>();
  const push = (v: unknown) => {
    if (typeof v !== 'string') return;
    // Normalize `./dist/index.js` → `dist/index.js` to match snapshot file paths.
    const norm = v.replace(/^\.?\//, '');
    if (norm) out.add(norm);
  };
  push(manifest.main);
  push((manifest as Record<string, unknown>).module);
  push((manifest as Record<string, unknown>).browser);
  push((manifest as Record<string, unknown>).types);
  push((manifest as Record<string, unknown>).typings);
  const walk = (v: unknown): void => {
    if (typeof v === 'string') { push(v); return; }
    if (!v || typeof v !== 'object') return;
    for (const child of Object.values(v as Record<string, unknown>)) walk(child);
  };
  walk((manifest as Record<string, unknown>).exports);
  // `bin` can be string or Record<string, string> — both are executable entry
  // points. Include them too; a minified bin file is expected in tools like
  // esbuild that ship compiled binaries.
  const bin = manifest.bin;
  if (typeof bin === 'string') push(bin);
  else if (bin && typeof bin === 'object') for (const p of Object.values(bin)) push(p);
  return out;
}

/**
 * A file is an "expected-minified bundler output" iff BOTH:
 *   (a) it's declared as an entry point in the package manifest, and
 *   (b) it lives under a canonical build output directory.
 * Either condition alone is insufficient — a `dist/setup.js` that isn't declared
 * is suspicious; a declared `src/index.js` in readable code has nothing to hide.
 */
const CANONICAL_BUILD_DIRS = /^(?:dist|build|lib|es|esm|cjs|mjs|umd|out|bundle|compiled)\//;
const PREEXISTING_BUILD_ENTROPY = 4.5;

function isExpectedMinified(filePath: string, declaredEntries: Set<string>): boolean {
  if (!declaredEntries.has(filePath)) return false;
  return CANONICAL_BUILD_DIRS.test(filePath);
}

function pickSeverity(baseSeverity: Severity, isExpected: boolean): { severity: Severity; confidence: 'low' | 'medium' | 'high' } {
  if (isExpected) return { severity: 'INFO', confidence: 'low' };
  return { severity: baseSeverity, confidence: baseSeverity === 'WARN' ? 'medium' : 'low' };
}

export const obfDetector: Detector = {
  id: 'obf',
  category: 'OBF',
  run(pair: SnapshotPair): Finding[] {
    if (!pair.new) return [];
    const dir = directionFor(pair.old);
    const out: Finding[] = [];
    const newEntries = declaredEntryFiles(pair.new.manifest);

    if (pair.old) {
      // Diff mode
      const oldByPath = byPath(pair.old);
      for (const nf of pair.new.files) {
        const of = oldByPath.get(nf.path);
        if (of) {
          const reasons: string[] = [];
          const suppressBuildEntropyDelta =
            CANONICAL_BUILD_DIRS.test(nf.path) && of.entropy >= PREEXISTING_BUILD_ENTROPY;
          if (nf.entropy - of.entropy > 1.5 && !suppressBuildEntropyDelta) {
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
          const expected = isExpectedMinified(nf.path, newEntries);
          const sev = pickSeverity('WARN', expected);
          out.push({
            detector: 'obf.entropy-jump',
            category: 'OBF',
            package: pair.new.name,
            from: pair.old.version,
            to: pair.new.version,
            direction: 'changed',
            severity: sev.severity,
            confidence: sev.confidence,
            message: expected
              ? `Obfuscation indicators appeared in ${nf.path} (declared bundler entry): ${reasons.join('; ')}`
              : `Obfuscation indicators appeared in ${nf.path}: ${reasons.join('; ')}`,
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
            const expected = isExpectedMinified(nf.path, newEntries);
            const sev = pickSeverity('WARN', expected);
            out.push({
              detector: 'obf.new-obfuscated-file',
              category: 'OBF',
              package: pair.new.name,
              from: pair.old.version,
              to: pair.new.version,
              direction: 'changed',
              severity: sev.severity,
              confidence: sev.confidence,
              message: expected
                ? `New file ${nf.path} appears obfuscated (declared bundler entry): ${reasons.join('; ')}`
                : `New file ${nf.path} appears obfuscated: ${reasons.join('; ')}`,
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
        const expected = isExpectedMinified(nf.path, newEntries);
        // Added-package mode already uses `low` confidence — we downgrade
        // severity from WARN to INFO for expected-minified, keep confidence.
        const severity: Severity = expected ? 'INFO' : 'WARN';
        out.push({
          detector: 'obf.new-obfuscated-file',
          category: 'OBF',
          package: pair.new.name,
          from: dir.from,
          to: pair.new.version,
          direction: dir.direction,
          severity,
          confidence: 'low',
          message: expected
            ? `Newly-installed package ships obfuscated file ${nf.path} (declared bundler entry): ${reasons.join('; ')}`
            : `Newly-installed package ships obfuscated file ${nf.path}: ${reasons.join('; ')}`,
          evidence: [{ file: nf.path, line: 1, snippet: reasons.join('; ').slice(0, 240) }],
          provenance: [],
        });
      }
    }

    return out;
  },
};
