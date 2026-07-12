/**
 * TYPOSQUAT — Damerau-Levenshtein locks.
 *
 * The core distinction between DL and plain Levenshtein: adjacent-character
 * transposition costs ONE edit under DL, TWO under plain L. If this test
 * regresses (someone swaps to fastest-levenshtein or similar for perf), the
 * whole class of transposition typosquats becomes invisible.
 *
 * This test exists specifically to prevent that regression.
 */

import { describe, it, expect } from 'vitest';
import { closestTop, typosquatDetector } from '../src/typo.js';
import { mkSnap } from './helpers.js';

describe('typosquat detector — Damerau-Levenshtein transposition cases', () => {
  it.each([
    ['debgu', 'debug'],
    ['axois', 'axios'],
    ['chlak', 'chalk'],
    ['expreess', 'express'],
    ['loadsh', 'lodash'],
    ['reactd', 'react'],
  ])('detects transposition typo: %s → %s (distance 1)', (typo, real) => {
    const near = closestTop(typo);
    expect(near, `${typo} should be detected as a typo of ${real}`).not.toBeNull();
    expect(near!.target).toBe(real);
    expect(near!.distance).toBe(1);
  });

  it('does not fire on the actual top-npm package', () => {
    expect(closestTop('debug')).toBeNull();
    expect(closestTop('axios')).toBeNull();
    expect(closestTop('chalk')).toBeNull();
  });

  it('does not fire on completely unrelated names', () => {
    expect(closestTop('my-internal-utils')).toBeNull();
    expect(closestTop('completely-original-package-2026')).toBeNull();
  });

  it('detects insertion/deletion typos too', () => {
    const near = closestTop('lodashh'); // extra char
    expect(near).not.toBeNull();
    expect(near!.target).toBe('lodash');
    expect(near!.distance).toBe(1);
  });

  it('emits a BLOCK-tier finding shape (before runAll escalation) when name is close', () => {
    // Direct call to typosquatDetector — no escalation yet, so it's WARN
    const pair = {
      old: null,
      new: mkSnap({ name: 'axois', version: '1.0.0' }),
    };
    const findings = typosquatDetector.run(pair, { direction: 'added' });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.detector).toBe('deps.typosquat-candidate');
    expect(findings[0]!.severity).toBe('WARN');
    expect(findings[0]!.confidence).toBe('high'); // distance-1 → high
    expect(findings[0]!.message).toMatch(/axios/);
  });

  it('does NOT fire on upgraded packages (only ADDED)', () => {
    const pair = {
      old: mkSnap({ name: 'axois', version: '1.0.0' }), // still a typo, but existing
      new: mkSnap({ name: 'axois', version: '1.0.1' }),
    };
    expect(typosquatDetector.run(pair, { direction: 'changed' })).toHaveLength(0);
  });
});
