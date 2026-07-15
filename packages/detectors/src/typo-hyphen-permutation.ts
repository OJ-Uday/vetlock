/**
 * TYPO hyphen-permutation — new package name whose hyphen-split token set matches
 * a top-1000 popular package but tokens are ADDED / DROPPED / REORDERED.
 *
 * Port from guarddog:typosquatting (hyphen-permutation branch) — audit §4 row 6.
 *
 * Motivation: an attacker publishes `node-express` (real: `express`),
 * `router-react` (real: `react-router`), `axios-http` (real: `axios`) — names
 * that are edit-distance FAR from any single top-name (Damerau-Levenshtein
 * misses these entirely) but that a distracted developer will `npm install`
 * anyway because the tokens are correct. Damerau-Levenshtein compares the WHOLE
 * name; hyphen-permutation compares the TOKEN SET after `split('-')`.
 *
 * Shape:
 *   1. Only fires on ADDED packages (pair.old === null) — same discipline as
 *      typo.ts.
 *   2. Split package name on `-`; ignore empty tokens; lowercase.
 *   3. If the name IS an exact top-1000 name, bail (it IS the popular package).
 *   4. For each top-1000 name that contains at least one hyphen, split into
 *      tokens and compare:
 *      a. EXACT token set match with DIFFERENT concatenation order → BLOCK
 *         (`router-react` vs `react-router` — same tokens, wrong order).
 *      b. SUBSET (dropped 1 token) OR SUPERSET (added 1 token) of a top name
 *         that has ≥ 2 tokens AND ≥ 2 tokens survive in common → WARN.
 *   5. Skip when the package name is itself a legitimately-scoped variant of
 *      a top name (same base after `/`), that's already covered by typo.ts N4.
 *
 * The @vetlock/core FileCapabilities surface is NOT read — this is a
 * name-only detector, identical to typo.ts in that regard. NEVER-EXECUTE
 * invariant (ADR 0005) is preserved.
 *
 * FP guardrails:
 *  - Requires the top name to have ≥ 2 tokens: single-token top names can't be
 *    "permuted", they'd just be the exact name (already bailed).
 *  - Requires ≥ 2 tokens in common: prevents fabric-lodash from matching lodash
 *    plus one extra generic word.
 *  - The candidate's token count must be within ±1 of the top's token count:
 *    a 5-token name like `my-cool-react-router-clone` should NOT flag react-router.
 */

import type { Detector, Finding, SnapshotPair } from '@vetlock/core';
import { getTop1000Names } from './data/top-1000-names.js';

/** Return sorted, lowercased, deduplicated, non-empty hyphen tokens of `name`. */
function tokens(name: string): string[] {
  // Strip scope prefix `@scope/`, per §4 row 6 spec: split newly-added name on `-`.
  const bare = name.startsWith('@') && name.includes('/')
    ? name.slice(name.indexOf('/') + 1)
    : name;
  const parts = bare.toLowerCase().split('-').filter((t) => t.length > 0);
  // Deduplicate: `my-my-cool` yields ['my','cool'] — otherwise a doubled-token
  // name would falsely "match" a 2-token top after dedup on the target side.
  return [...new Set(parts)].sort();
}

/**
 * Compute the token overlap between two sorted deduped token lists.
 * Returns { common, aOnly, bOnly } — sizes of intersection and each set diff.
 */
function overlap(a: string[], b: string[]): { common: number; aOnly: number; bOnly: number } {
  const bSet = new Set(b);
  let common = 0;
  let aOnly = 0;
  for (const t of a) {
    if (bSet.has(t)) common++;
    else aOnly++;
  }
  const aSet = new Set(a);
  let bOnly = 0;
  for (const t of b) {
    if (!aSet.has(t)) bOnly++;
  }
  return { common, aOnly, bOnly };
}

interface Match {
  target: string;
  kind: 'reorder' | 'add-token' | 'drop-token';
}

/** For test surface. */
export function nearestHyphenPermutation(name: string): Match | null {
  const cand = tokens(name);
  if (cand.length < 2) return null; // single-token names can't be hyphen-permuted
  const top1000 = getTop1000Names();
  // Fast exact-name bail — same discipline as closestTop() in typo.ts.
  if (top1000.exactSet.has(name)) return null;
  const candTokens = tokens(name).join(',');

  let best: Match | null = null;
  for (const top of top1000.hyphenated) {
    const tt = top.tokens;
    if (tt.length < 2) continue;
    // Length window: the candidate's token count must be within ±1 of top's.
    if (Math.abs(cand.length - tt.length) > 1) continue;
    const { common, aOnly, bOnly } = overlap(cand, tt);
    if (common < 2) continue; // FP guardrail — need at least 2 tokens in common
    // Reorder: same token multiset, different concatenation order (top.name !== name).
    if (aOnly === 0 && bOnly === 0 && cand.length === tt.length) {
      if (candTokens === tt.join(',') && top.name === name) continue;
      // Both sets equal but concatenation strings differ → this is a real reorder.
      if (top.name !== name) {
        best = { target: top.name, kind: 'reorder' };
        return best; // reorder is highest-signal — return immediately
      }
    }
    // Add-token: candidate has one extra token that top didn't.
    if (aOnly === 1 && bOnly === 0) {
      if (!best) best = { target: top.name, kind: 'add-token' };
    }
    // Drop-token: candidate is missing one token top has.
    if (aOnly === 0 && bOnly === 1) {
      if (!best) best = { target: top.name, kind: 'drop-token' };
    }
  }
  return best;
}

export const typoHyphenPermutationDetector: Detector = {
  id: 'typo-hyphen-permutation',
  category: 'DEPS',
  run(pair: SnapshotPair): Finding[] {
    if (!pair.new) return [];
    if (pair.old) return []; // ADDED packages only, same as typo.ts
    const near = nearestHyphenPermutation(pair.new.name);
    if (!near) return [];
    const isReorder = near.kind === 'reorder';
    // Reorder is the highest-signal shape: `router-react` vs `react-router` —
    // same tokens, transposed. BLOCK. Add/drop token is one edit away and more
    // often coincidental, so WARN.
    const severity = isReorder ? 'BLOCK' : 'WARN';
    const confidence: 'high' | 'medium' = isReorder ? 'high' : 'medium';
    const description = isReorder
      ? `hyphen-token reorder of "${near.target}"`
      : near.kind === 'add-token'
        ? `hyphen-token superset of "${near.target}" (one extra token)`
        : `hyphen-token subset of "${near.target}" (one dropped token)`;
    return [
      {
        detector: 'typo.hyphen-permutation',
        category: 'DEPS',
        package: pair.new.name,
        from: null,
        to: pair.new.version,
        direction: 'added',
        severity,
        confidence,
        message:
          `Package name "${pair.new.name}" is a ${description} — hyphen-permutation typosquat candidate. ` +
          'Ported from guarddog:typosquatting (hyphen-permutation branch).',
        evidence: [
          {
            file: 'package.json',
            line: 1,
            snippet: `"${pair.new.name}" — ${description}`,
          },
        ],
        provenance: [],
      },
    ];
  },
};
