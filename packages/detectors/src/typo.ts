/**
 * TYPO detector — new direct or transitive dep whose name is a very-near
 * typosquat of a popular npm package.
 *
 * WARN by default; escalates to BLOCK when the added package also has
 * BLOCK-tier capabilities (escalation lives in runAll()).
 *
 * Uses `damerau-levenshtein` — the correct algorithm for typo detection.
 * Damerau-Levenshtein counts adjacent-character transposition as ONE edit,
 * catching cases like:
 *   - `debgu`   vs `debug`    (steps: 1)
 *   - `axois`   vs `axios`    (steps: 1)
 *   - `chlak`   vs `chalk`    (steps: 1)
 *   - `expresss` vs `express`  (steps: 1)
 *
 * Plain Levenshtein would score all four as distance-2 (delete + insert),
 * pushing them above the maxDist threshold and missing every one. We do NOT
 * pick "fast Levenshtein" here — the perf difference is microseconds per
 * added package, and the correctness difference is the entire class of
 * transposition typosquats. This detector runs at most a few dozen times per
 * PR check; the algorithm choice is a security decision, not a perf decision.
 *
 * npm's own security researchers have documented transposition typosquats
 * ("nodeemailer" for "nodemailer", "expreess" for "express") as one of the
 * most common attack shapes — the algorithm has to see them.
 */

import dl from 'damerau-levenshtein';
import type { Detector, Finding, SnapshotPair } from '@vetlock/core';
import { TOP_NPM_NAMES } from './top-npm-names.js';

const TOP_SET = new Set<string>(TOP_NPM_NAMES);

/**
 * REDTEAM N4 FIX: scope-prefix typosquat.
 *
 * `closestTop` compares the FULL package name (including any `@scope/`
 * prefix) against the top-name list. An attacker who publishes
 * `@evil-org/react` under a scope nobody has ever registered gets a huge
 * whole-string edit distance against every top name — `@evil-org/react` is
 * nowhere near `react` — so the detector never fires, even though the base
 * name is an exact, shameless impersonation of the real unscoped `react`.
 *
 * Fix: for a scoped name, also compare the BASE name (the part after the
 * `/`) against every UNSCOPED top name, exact-match or within `maxDist`
 * edits. Skip when the scope itself is a known-legitimate scope so
 * `@babel/core` doesn't self-flag against unrelated top names.
 */
const UNSCOPED_TOP_NAMES = TOP_NPM_NAMES.filter((n) => !n.startsWith('@'));
const KNOWN_TRUSTED_SCOPES = new Set([
  '@babel', '@types', '@aws-sdk', '@microsoft', '@angular', '@vercel',
  '@nestjs', '@testing-library', '@rollup', '@emotion', '@reduxjs',
  '@tanstack', '@mui', '@chakra-ui', '@solana', '@prisma',
]);

/**
 * Return the closest top-name if within `maxDist` Damerau-Levenshtein edits.
 * The `dl(a, b)` call returns `{ steps, relative, similarity }`; we use
 * `steps` — the integer edit count, treating adjacent transposition as one.
 *
 * For scoped names (`@scope/base`) from a scope NOT on the trusted list,
 * also checks the base name against unscoped top names (N4 fix above).
 */
export function closestTop(name: string, maxDist = 2): { target: string; distance: number } | null {
  if (TOP_SET.has(name)) return null; // it IS a top package, not a squat of one
  let best: { target: string; distance: number } | null = null;
  for (const top of TOP_NPM_NAMES) {
    // Cheap prune: length difference alone can rule out.
    if (Math.abs(top.length - name.length) > maxDist) continue;
    const { steps } = dl(name, top);
    if (steps > 0 && steps <= maxDist && (!best || steps < best.distance)) {
      best = { target: top, distance: steps };
    }
  }
  if (best) return best;

  const slash = name.startsWith('@') ? name.indexOf('/') : -1;
  if (slash === -1) return null;
  const scope = name.slice(0, slash);
  const base = name.slice(slash + 1);
  if (KNOWN_TRUSTED_SCOPES.has(scope) || base.length === 0) return null;
  if (UNSCOPED_TOP_NAMES.includes(base)) return { target: base, distance: 0 };
  for (const top of UNSCOPED_TOP_NAMES) {
    if (Math.abs(top.length - base.length) > maxDist) continue;
    const { steps } = dl(base, top);
    if (steps > 0 && steps <= maxDist && (!best || steps < best.distance)) {
      best = { target: top, distance: steps };
    }
  }
  return best;
}

export const typosquatDetector: Detector = {
  id: 'typo',
  category: 'DEPS',
  run(pair: SnapshotPair): Finding[] {
    if (!pair.new) return [];
    // Only fires on ADDED packages (pair.old === null).
    if (pair.old) return [];
    const near = closestTop(pair.new.name);
    if (!near) return [];
    return [
      {
        detector: 'deps.typosquat-candidate',
        category: 'DEPS',
        package: pair.new.name,
        from: null,
        to: pair.new.version,
        direction: 'added',
        severity: 'WARN', // escalated to BLOCK in runAll if package also has BLOCK-tier capability
        confidence: near.distance <= 1 ? 'high' : 'medium',
        message: `Package name "${pair.new.name}" is edit-distance ${near.distance} from popular package "${near.target}" (Damerau-Levenshtein, adjacent-transposition counted as one edit). Typosquat candidate.`,
        evidence: [
          {
            file: 'package.json',
            line: 1,
            snippet: `"${pair.new.name}" (distance ${near.distance} from "${near.target}")`,
          },
        ],
        provenance: [],
      },
    ];
  },
};

// Re-exports for tests
export { TOP_NPM_NAMES };
