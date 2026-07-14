/**
 * Deterministic PRNG — mulberry32 (32-bit LCG-style).
 *
 * Purity: same seed → same sequence, always. The generators pick from bounded lists
 * (identifier candidates, template variants) using this to keep pair output
 * byte-identical across runs and platforms.
 */

/**
 * Returns a next-uint32 function bound to the given seed.
 * Not cryptographic; not intended for security. Fine for fixture selection.
 */
export function makeRng(seed: number): () => number {
  // Coerce to a well-defined 32-bit unsigned integer state.
  let s = (seed >>> 0) || 0x9e3779b9;
  return function next(): number {
    s = (s + 0x6d2b79f5) >>> 0;
    let t = s;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0);
  };
}

/** Pick one element from a non-empty array by the PRNG. */
export function pick<T>(rng: () => number, arr: readonly T[]): T {
  if (arr.length === 0) throw new Error('pick: empty array');
  return arr[rng() % arr.length];
}

/** Return a bounded non-negative integer in [0, max). */
export function boundedInt(rng: () => number, max: number): number {
  if (max <= 0) return 0;
  return rng() % max;
}
