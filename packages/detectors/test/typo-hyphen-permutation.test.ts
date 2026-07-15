import { describe, it, expect } from 'vitest';
import { validateFinding } from '@vetlock/core';
import {
  typoHyphenPermutationDetector,
  hyphenPermutationOf,
} from '../src/typo-hyphen-permutation.js';
import { mkSnap } from './helpers.js';

describe('deps.typosquat-hyphen-permutation (port from guarddog:metadata/typosquatting.py hyphen-permutation)', () => {
  it('POS: fires when an added package name is a hyphen-permutation of a top package', () => {
    // 'react-dom' is on the top-npm-names list; 'dom-react' permutes to the same
    // token set and should fire.
    const pair = {
      old: null,
      new: mkSnap({ name: 'dom-react', version: '1.0.0' }),
    };
    const findings = typoHyphenPermutationDetector.run(pair, { direction: 'added' });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.detector).toBe('deps.typosquat-hyphen-permutation');
    expect(findings[0]!.category).toBe('DEPS');
    expect(findings[0]!.severity).toBe('WARN');
    expect(findings[0]!.confidence).toBe('high');
    expect(findings[0]!.message).toMatch(/react-dom/);
    expect(validateFinding(findings[0]!)).toBeNull();
  });

  it('NEG: does not fire on the exact same top package name', () => {
    const pair = {
      old: null,
      new: mkSnap({ name: 'react-dom', version: '18.3.1' }),
    };
    const findings = typoHyphenPermutationDetector.run(pair, { direction: 'added' });
    expect(findings).toEqual([]);
  });

  it('NEG: does not fire on a name with no hyphen', () => {
    const pair = {
      old: null,
      new: mkSnap({ name: 'lodash', version: '4.17.21' }),
    };
    const findings = typoHyphenPermutationDetector.run(pair, { direction: 'added' });
    expect(findings).toEqual([]);
  });

  it('NEG: does not fire on version bumps (not an ADDED package)', () => {
    const pair = {
      old: mkSnap({ name: 'dom-react', version: '1.0.0' }),
      new: mkSnap({ name: 'dom-react', version: '1.0.1' }),
    };
    // Even though the name permutes to react-dom, this is not an ADDED package
    // — diff-framing says the added event happened in a prior scan.
    expect(typoHyphenPermutationDetector.run(pair, { direction: 'changed' })).toEqual([]);
  });

  it('NEG: unrelated hyphenated name does not fire', () => {
    const pair = {
      old: null,
      new: mkSnap({ name: 'my-utility-lib', version: '0.1.0' }),
    };
    const findings = typoHyphenPermutationDetector.run(pair, { direction: 'added' });
    expect(findings).toEqual([]);
  });

  it('helper: hyphenPermutationOf returns the matching top name or null', () => {
    // 'react-dom' is a canonical top-1000 entry.
    expect(hyphenPermutationOf('dom-react')).toBe('react-dom');
    // Identity match should be null (we don't flag the legit package).
    expect(hyphenPermutationOf('react-dom')).toBeNull();
    // Non-permutation should be null.
    expect(hyphenPermutationOf('lodash')).toBeNull();
    expect(hyphenPermutationOf('some-random-name')).toBeNull();
  });
});
