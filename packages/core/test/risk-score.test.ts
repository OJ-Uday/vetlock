/**
 * Risk-score compression 0.0-10.0 (audit §2.2 architectural borrow).
 *
 * Pins the exact numbers so downstream dashboards / CI thresholds have a
 * stable contract. Changing any weighting is a semver-visible break.
 *
 * Formula (see RunResult.riskScore docstring in engine.ts):
 *   base per finding = { BLOCK: 5, WARN: 2, INFO: 0 }[severity]
 *   confidence       = { high: 1.0, medium: 0.7, low: 0.5 }[confidence]
 *   direction        = { added: 1.0, changed: 0.8, absolute: 1.0, removed: 0.3 }[direction]
 *   riskScore        = clamp(round1(sum(base * confidence * direction)), 0, 10)
 */

import { describe, it, expect } from 'vitest';
import { computeRiskScore } from '../src/engine.js';
import type { Finding } from '../src/finding.js';

/** Minimal Finding builder — only the fields riskScore reads. */
function mk(
  overrides: Partial<Finding> & { severity: Finding['severity']; confidence: Finding['confidence']; direction: Finding['direction'] },
): Finding {
  return {
    detector: 'test',
    category: 'META',
    package: 'p',
    from: overrides.direction === 'added' ? null : 'x',
    to: overrides.direction === 'removed' ? null : 'y',
    message: '',
    evidence: [{ file: 'f', line: 1, snippet: 's' }],
    provenance: [],
    ...overrides,
  };
}

describe('computeRiskScore — 0.0-10.0 compression (audit §2.2)', () => {
  it('empty findings → 0.0', () => {
    expect(computeRiskScore([])).toBe(0.0);
  });

  it('single BLOCK high-confidence added → 5.0 (base 5 * conf 1.0 * dir 1.0)', () => {
    expect(
      computeRiskScore([mk({ severity: 'BLOCK', confidence: 'high', direction: 'added' })]),
    ).toBe(5.0);
  });

  it('two BLOCK high-confidence added → 10.0 (5 + 5, at ceiling)', () => {
    expect(
      computeRiskScore([
        mk({ severity: 'BLOCK', confidence: 'high', direction: 'added' }),
        mk({ severity: 'BLOCK', confidence: 'high', direction: 'added' }),
      ]),
    ).toBe(10.0);
  });

  it('three BLOCK high-confidence added → 10.0 (capped)', () => {
    expect(
      computeRiskScore([
        mk({ severity: 'BLOCK', confidence: 'high', direction: 'added' }),
        mk({ severity: 'BLOCK', confidence: 'high', direction: 'added' }),
        mk({ severity: 'BLOCK', confidence: 'high', direction: 'added' }),
      ]),
    ).toBe(10.0);
  });

  it('single WARN high-confidence added → 2.0 (base 2 * 1.0 * 1.0)', () => {
    expect(
      computeRiskScore([mk({ severity: 'WARN', confidence: 'high', direction: 'added' })]),
    ).toBe(2.0);
  });

  it('single INFO finding → 0.0 (INFO base is zero regardless of multipliers)', () => {
    expect(
      computeRiskScore([mk({ severity: 'INFO', confidence: 'high', direction: 'added' })]),
    ).toBe(0.0);
  });

  it('confidence multiplier: BLOCK medium → 3.5 (5 * 0.7)', () => {
    expect(
      computeRiskScore([mk({ severity: 'BLOCK', confidence: 'medium', direction: 'added' })]),
    ).toBe(3.5);
  });

  it('confidence multiplier: BLOCK low → 2.5 (5 * 0.5)', () => {
    expect(
      computeRiskScore([mk({ severity: 'BLOCK', confidence: 'low', direction: 'added' })]),
    ).toBe(2.5);
  });

  it('direction multiplier: BLOCK high changed → 4.0 (5 * 1.0 * 0.8)', () => {
    expect(
      computeRiskScore([mk({ severity: 'BLOCK', confidence: 'high', direction: 'changed' })]),
    ).toBe(4.0);
  });

  it('direction multiplier: BLOCK high absolute → 5.0 (scan-mode weights same as added)', () => {
    expect(
      computeRiskScore([mk({ severity: 'BLOCK', confidence: 'high', direction: 'absolute' })]),
    ).toBe(5.0);
  });

  it('direction multiplier: INFO high removed → 0.0 (INFO base zero + removed 0.3× = 0)', () => {
    // removals can only reach INFO by diff-framing invariant — and INFO base
    // is zero, so this composition rounds to 0.0. The 0.3 removed multiplier
    // matters only if a future taxonomy change permits a WARN/BLOCK removal.
    expect(
      computeRiskScore([mk({ severity: 'INFO', confidence: 'high', direction: 'removed' })]),
    ).toBe(0.0);
  });

  it('WARN medium changed contribution: 2 * 0.7 * 0.8 = 1.12 → rounds to 1.1', () => {
    expect(
      computeRiskScore([mk({ severity: 'WARN', confidence: 'medium', direction: 'changed' })]),
    ).toBe(1.1);
  });

  it('mixed report: BLOCK high added + WARN low absolute = 5 + 1 = 6.0', () => {
    // WARN low absolute = 2 * 0.5 * 1.0 = 1.0
    expect(
      computeRiskScore([
        mk({ severity: 'BLOCK', confidence: 'high', direction: 'added' }),
        mk({ severity: 'WARN', confidence: 'low', direction: 'absolute' }),
      ]),
    ).toBe(6.0);
  });

  it('mixed with rounding: BLOCK medium changed + WARN medium changed = 2.8 + 1.12 = 3.92 → 3.9', () => {
    // BLOCK medium changed = 5 * 0.7 * 0.8 = 2.8
    // WARN  medium changed = 2 * 0.7 * 0.8 = 1.12
    expect(
      computeRiskScore([
        mk({ severity: 'BLOCK', confidence: 'medium', direction: 'changed' }),
        mk({ severity: 'WARN', confidence: 'medium', direction: 'changed' }),
      ]),
    ).toBe(3.9);
  });

  it('never below 0.0', () => {
    // Structurally impossible today, but the clamp exists — guard it anyway.
    expect(computeRiskScore([])).toBeGreaterThanOrEqual(0);
  });

  it('never above 10.0 no matter how many BLOCKs', () => {
    const many: Finding[] = Array.from({ length: 100 }, () =>
      mk({ severity: 'BLOCK', confidence: 'high', direction: 'added' }),
    );
    expect(computeRiskScore(many)).toBe(10.0);
  });
});
