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
 * Scoped-name handling:
 *   - unscoped candidates only compare against unscoped popular packages
 *   - scoped candidates only compare against packages in the SAME scope
 *   - when both sides are scoped, distance is computed on the base name only
 *   - org-like unknown scopes (`@foo-org/react`) still compare their base name
 *     against unscoped popular packages to preserve the existing impersonation
 *     signal without flagging every short private namespace
 *
 * This preserves `@babel/cord` → `@babel/core` while avoiding cross-family
 * comparisons like `@evil/lodash` → `lodash`.
 */
interface ParsedPackageName {
  scope: string | null;
  base: string;
}

function parsePackageName(name: string): ParsedPackageName {
  if (!name.startsWith('@')) return { scope: null, base: name };
  const slash = name.indexOf('/');
  if (slash === -1) return { scope: null, base: name };
  return {
    scope: name.slice(0, slash),
    base: name.slice(slash + 1),
  };
}

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
  const candidate = parsePackageName(name);
  let best: { target: string; distance: number } | null = null;
  for (const top of TOP_NPM_NAMES) {
   const legit = parsePackageName(top);
   let left: string;
   let right: string;
   if (candidate.scope === null && legit.scope === null) {
     left = name;
     right = top;
   } else if (candidate.scope !== null && legit.scope !== null && candidate.scope === legit.scope) {
     left = candidate.base;
     right = legit.base;
   } else if (
     candidate.scope !== null &&
     legit.scope === null &&
     /[-._]/.test(candidate.scope) &&
     candidate.base.length > 0
   ) {
     left = candidate.base;
     right = top;
   } else {
     continue;
   }
   // Cheap prune: length difference alone can rule out.
   if (Math.abs(right.length - left.length) > maxDist) continue;
   const { steps } = dl(left, right);
   if (steps <= maxDist && (!best || steps < best.distance)) {
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
