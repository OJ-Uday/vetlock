// port from guarddog:metadata/typosquatting.py (hyphen-permutation branch)
/**
 * TYPO detector — hyphen-permutation typosquat against Top-1000 npm names.
 *
 * Rationale (audit §1 G-20): the existing `typo.ts` detector uses
 * Damerau-Levenshtein against the Top-1000 list. That algorithm treats
 * `foo-bar` and `bar-foo` as edit-distance 6 (delete `foo-`, insert `-foo`) —
 * well above the maxDist=2 threshold — so it misses the hyphen-permutation
 * class entirely. Dependency-confusion probes routinely try `<company>-cli`
 * vs `cli-<company>` and `react-native-x` vs `x-react-native`; the shape has
 * shipped in real npm-registry incidents (see guarddog's own eval samples).
 *
 * Algorithm (per audit): split the newly-added package name on `-`, sort the
 * resulting tokens, compare token-set equality with each top name. Runs at
 * most once per newly-added package on a small (~330 name) list, so cost is
 * negligible.
 *
 * We deliberately DO NOT fold underscores/dots in — that's the PyPI shape
 * covered by the separate `python-supply-chain::typosquat-underscore-hyphen`
 * capability entry. This detector is npm-registry-scoped where hyphens are
 * the only permutable delimiter that stays a valid package name.
 *
 * Fires only on ADDED packages (`pair.old === null`) — a package that was
 * already installed under this hyphen-permutation name and is only having its
 * version bumped is not a new attack signal here.
 *
 * Severity WARN, high confidence. The compound-suspicion escalator in
 * runAll() promotes to BLOCK when the added package also ships BLOCK-tier
 * capabilities or ≥2 WARN-tier signals across ≥2 categories.
 */

import type { Detector, Finding, SnapshotPair } from '@vetlock/core';
import { TOP_NPM_NAMES } from './top-npm-names.js';

/**
 * Build a permutation index for the top-name list once at module load.
 * Key = sorted-token joined by `|`; value = the canonical top name.
 * Scoped names (`@scope/foo`) are split into their base name for the compare —
 * a scope-prefix attack (`@evil-org/react-cli` vs `react-cli`) is handled by
 * the existing scope-prefix path in typo.ts, not here.
 */
function buildPermutationIndex(): Map<string, string> {
  const idx = new Map<string, string>();
  for (const top of TOP_NPM_NAMES) {
    const name = top.startsWith('@') ? top.slice(top.indexOf('/') + 1) : top;
    if (!name.includes('-')) continue;
    const key = name.split('-').filter(Boolean).sort().join('|');
    // If two top names permute to the same token set (unlikely on our list),
    // last-writer-wins is fine for the detector — we only need one match.
    idx.set(key, top);
  }
  return idx;
}

const PERMUTATION_INDEX: Map<string, string> = buildPermutationIndex();

/**
 * Return the top-name whose hyphen-split tokens are a permutation of `name`'s
 * tokens, else null. Excludes the identity (name === top) case so we don't
 * self-flag a legitimate top package.
 */
export function hyphenPermutationOf(name: string): string | null {
  // Handle scoped names — compare the base name against unscoped top names.
  const base = name.startsWith('@') ? name.slice(name.indexOf('/') + 1) : name;
  if (!base.includes('-')) return null;
  const tokens = base.split('-').filter(Boolean);
  if (tokens.length < 2) return null;
  const key = tokens.slice().sort().join('|');
  const match = PERMUTATION_INDEX.get(key);
  if (!match) return null;
  // Reject identity match — `react-dom` looking up `react-dom` is legit.
  const matchBase = match.startsWith('@') ? match.slice(match.indexOf('/') + 1) : match;
  if (base === matchBase) return null;
  return match;
}

export const typoHyphenPermutationDetector: Detector = {
  id: 'typo-hyphen-permutation',
  category: 'DEPS',
  run(pair: SnapshotPair): Finding[] {
    if (!pair.new) return [];
    // Only fires on ADDED packages (pair.old === null) — see module docstring.
    if (pair.old) return [];
    const match = hyphenPermutationOf(pair.new.name);
    if (!match) return [];
    return [
      {
        detector: 'deps.typosquat-hyphen-permutation',
        category: 'DEPS',
        package: pair.new.name,
        from: null,
        to: pair.new.version,
        direction: 'added',
        severity: 'WARN',
        confidence: 'high',
        message:
          `Package name "${pair.new.name}" is a hyphen-permutation of popular package "${match}" ` +
          '(same tokens, different order). Attackers use this shape to bypass edit-distance-based typosquat checks.',
        evidence: [
          {
            file: 'package.json',
            line: 1,
            snippet: `"${pair.new.name}" ↔ token-permutation of "${match}"`.slice(0, 240),
          },
        ],
        provenance: [],
      },
    ];
  },
};
