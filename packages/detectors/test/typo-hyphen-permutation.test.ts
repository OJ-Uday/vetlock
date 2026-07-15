/**
 * TYPO hyphen-permutation — token-set matching against top-1000 npm names.
 *
 * Test contract:
 *  - Reorder of tokens (`router-react` vs `react-router`) → BLOCK, high.
 *  - Add/drop of one token → WARN, medium.
 *  - Fires only on ADDED packages (pair.old === null).
 *  - Skips single-token names, the exact top name, and unrelated names.
 *
 * Ports from guarddog:typosquatting hyphen-permutation branch, per §4 row 6.
 */

import { describe, it, expect } from 'vitest';
import {
  typoHyphenPermutationDetector,
  nearestHyphenPermutation,
} from '../src/typo-hyphen-permutation.js';
import { mkSnap } from './helpers.js';

describe('typo.hyphen-permutation — token-set matcher', () => {
  it('detects reorder of a two-token top name', () => {
    // `router-react` reorders `react-router`.
    const near = nearestHyphenPermutation('router-react');
    expect(near, 'router-react should hit react-router').not.toBeNull();
    expect(near!.target).toBe('react-router');
    expect(near!.kind).toBe('reorder');
  });

  it('detects add-token permutation (superset of a top name)', () => {
    // `axios-http` = axios + one extra token. Top `axios` is single-token so
    // this test uses a hyphenated top: `date-fns` vs `date-fns-tz` — verify a
    // NEW hyphenated candidate that adds a token flags as add-token.
    const near = nearestHyphenPermutation('react-router-clone');
    expect(near).not.toBeNull();
    // Match `react-router` (2 tokens) via add-token, not `react-router-dom`
    // (also 3 tokens — subset match). Either target is acceptable; kind should
    // be add-token OR reorder depending on which fires first.
    expect(['add-token', 'reorder']).toContain(near!.kind);
  });

  it('detects drop-token permutation (subset of a top name)', () => {
    // `react-native-vector-icons` is a real top. `native-vector-icons` drops
    // `react` → subset match.
    const near = nearestHyphenPermutation('native-vector-icons');
    expect(near).not.toBeNull();
    expect(near!.target).toBe('react-native-vector-icons');
    expect(near!.kind).toBe('drop-token');
  });

  it('does NOT fire on the exact top-1000 name', () => {
    expect(nearestHyphenPermutation('react-router')).toBeNull();
    expect(nearestHyphenPermutation('body-parser')).toBeNull();
    expect(nearestHyphenPermutation('graceful-fs')).toBeNull();
  });

  it('does NOT fire on a single-token name', () => {
    // Single-token names cannot be hyphen-permuted by construction.
    expect(nearestHyphenPermutation('react')).toBeNull();
    expect(nearestHyphenPermutation('lodash')).toBeNull();
    expect(nearestHyphenPermutation('completely-unrelated')).toBeNull();
  });

  it('does NOT fire on completely unrelated hyphenated names', () => {
    // These have zero tokens in common with any top-1000 hyphenated name.
    expect(nearestHyphenPermutation('my-internal-utils')).toBeNull();
    expect(nearestHyphenPermutation('purple-elephant-1234')).toBeNull();
  });

  it('requires at least two tokens in common (FP guardrail)', () => {
    // Only ONE token overlap with `react-native` — `react-frobnicator` shares
    // just `react`. FP guardrail rejects (needs ≥ 2 in common).
    expect(nearestHyphenPermutation('react-frobnicator-xyz')).toBeNull();
  });

  it('emits BLOCK-tier finding for reorder shape', () => {
    const pair = {
      old: null,
      new: mkSnap({ name: 'router-react', version: '1.0.0' }),
    };
    const findings = typoHyphenPermutationDetector.run(pair, { direction: 'added' });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.detector).toBe('typo.hyphen-permutation');
    expect(findings[0]!.severity).toBe('BLOCK');
    expect(findings[0]!.confidence).toBe('high');
    expect(findings[0]!.message).toMatch(/react-router/);
    expect(findings[0]!.message).toMatch(/reorder/);
  });

  it('emits WARN-tier finding for add/drop shape', () => {
    const pair = {
      old: null,
      new: mkSnap({ name: 'native-vector-icons', version: '1.0.0' }),
    };
    const findings = typoHyphenPermutationDetector.run(pair, { direction: 'added' });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('WARN');
    expect(findings[0]!.confidence).toBe('medium');
  });

  it('does NOT fire on upgraded packages (pair.old present)', () => {
    const pair = {
      old: mkSnap({ name: 'router-react', version: '1.0.0' }),
      new: mkSnap({ name: 'router-react', version: '1.0.1' }),
    };
    expect(typoHyphenPermutationDetector.run(pair, { direction: 'changed' })).toHaveLength(0);
  });

  it('handles scoped names — strips scope before token comparison', () => {
    // `@evil-org/router-react` → tokens `router,react` → hits `react-router`.
    const near = nearestHyphenPermutation('@evil-org/router-react');
    expect(near).not.toBeNull();
    expect(near!.target).toBe('react-router');
  });
});
