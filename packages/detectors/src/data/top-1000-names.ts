/**
 * Loader for the bundled top-1000-npm.json snapshot used by
 * typo.hyphen-permutation. Pre-computes hyphen-token splits so the detector
 * hot path can iterate without re-splitting on every call.
 *
 * Snapshot: packages/detectors/src/data/top-1000-npm.json. See that file's
 * $comment field for source + regeneration protocol.
 */

import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

interface Top1000Doc {
  names: string[];
}

export interface Top1000Cache {
  /** Every raw name in the snapshot. */
  all: string[];
  /** Set of every raw name for O(1) exact-match bail. */
  exactSet: Set<string>;
  /** Names that contain at least one hyphen, with pre-split tokens. */
  hyphenated: Array<{ name: string; tokens: string[] }>;
}

let cached: Top1000Cache | null = null;

function stripScope(name: string): string {
  if (name.startsWith('@') && name.includes('/')) {
    return name.slice(name.indexOf('/') + 1);
  }
  return name;
}

function tokenize(bareLower: string): string[] {
  const parts = bareLower.split('-').filter((t) => t.length > 0);
  return [...new Set(parts)].sort();
}

/**
 * Load and cache the top-1000 npm names snapshot.
 *
 * Locates the JSON in dev (next to this file in src/) OR in the built dist/
 * layout (also next to this file, because the build cp step copies data/
 * verbatim into dist/data/).
 */
export function getTop1000Names(): Top1000Cache {
  if (cached) return cached;
  const here = path.dirname(fileURLToPath(import.meta.url));
  // In dev: packages/detectors/src/data/top-1000-npm.json — sibling of this loader.
  // In dist: packages/detectors/dist/data/top-1000-npm.json — sibling after cp.
  const candidates = [
    path.join(here, 'top-1000-npm.json'),
    path.join(here, '..', '..', 'src', 'data', 'top-1000-npm.json'),
  ];
  let text: string | null = null;
  for (const p of candidates) {
    try { text = readFileSync(p, 'utf8'); break; } catch { /* try next */ }
  }
  if (text === null) {
    throw new Error(`could not locate top-1000-npm.json. Tried: ${candidates.join(', ')}`);
  }
  const parsed = JSON.parse(text) as Top1000Doc;
  if (!Array.isArray(parsed.names)) {
    throw new Error('top-1000-npm.json is malformed — missing names[]');
  }
  const hyphenated: Array<{ name: string; tokens: string[] }> = [];
  const exactSet = new Set<string>();
  for (const name of parsed.names) {
    exactSet.add(name);
    const bare = stripScope(name).toLowerCase();
    if (bare.includes('-')) {
      hyphenated.push({ name, tokens: tokenize(bare) });
    }
  }
  cached = { all: parsed.names, exactSet, hyphenated };
  return cached;
}
