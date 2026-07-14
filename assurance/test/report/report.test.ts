/**
 * Report generator self-tests.
 *
 * The report is the public trust artifact — its shape and reproducibility are hard
 * contracts. These tests pin:
 *   - Byte-identical output given identical ReportInput (the reproducibility invariant).
 *   - Empty-metrics tier shows "no data" rather than a fabricated green.
 *   - Notes are sorted by title (deterministic order regardless of input order).
 *   - All stamp fields appear in the output verbatim.
 */

import { describe, it, expect } from 'vitest';
import { generateReport, type ReportInput } from '../../src/report/index.js';

const BASE_INPUT: ReportInput = {
  stamp: {
    timestampIso: '2026-07-14T12:00:00Z',
    gitSha: 'abcdef1234567890abcdef1234567890abcdef12',
    nodeVersion: 'v20.11.0',
    seed: 42,
    tier: 'foundations',
  },
  metrics: {
    robustnessPassRate: null,
    enumeratedCoverage: null,
    evasionCatchRate: null,
    metamorphicInvariance: null,
    differentialLedgerNote: null,
  },
};

describe('generateReport — reproducibility', () => {
  it('produces byte-identical output for identical input across two calls', () => {
    const a = generateReport(BASE_INPUT);
    const b = generateReport(BASE_INPUT);
    expect(a).toBe(b);
  });

  it('is a pure function — no observable time / random state', () => {
    // Same input, hundred calls; every one is byte-equal to the first.
    const first = generateReport(BASE_INPUT);
    for (let i = 0; i < 100; i++) {
      expect(generateReport(BASE_INPUT)).toBe(first);
    }
  });

  it('does not embed Date.now() or process.hrtime output', () => {
    // Guard against future drift: no digits sequence looks like a Unix millisecond timestamp
    // (13-digit number starting with 1 or 2). Substrings like SHA hex don't collide with this.
    const output = generateReport(BASE_INPUT);
    const suspicious = output.match(/\b[12]\d{12}\b/);
    if (suspicious) {
      throw new Error(`report embedded a timestamp-shaped number: ${suspicious[0]}`);
    }
  });
});

describe('generateReport — stamp field rendering', () => {
  it('renders every stamp field verbatim in the output', () => {
    const output = generateReport(BASE_INPUT);
    expect(output).toContain('2026-07-14T12:00:00Z');
    expect(output).toContain('abcdef1234567890abcdef1234567890abcdef12');
    expect(output).toContain('v20.11.0');
    expect(output).toContain('42');
    expect(output).toContain('foundations');
  });

  it('quotes the git SHA as inline code (`…`)', () => {
    const output = generateReport(BASE_INPUT);
    expect(output).toContain('`abcdef1234567890abcdef1234567890abcdef12`');
  });
});

describe('generateReport — empty-metrics tier', () => {
  it('renders every null metric as "no data" — never fabricates a green', () => {
    const output = generateReport(BASE_INPUT);
    // Five metric lines; every one should read "no data (tier not yet active)".
    const noDataCount = (output.match(/no data \(tier not yet active\)/g) ?? []).length;
    expect(noDataCount).toBe(5);
    // And no metric line should render a percentage.
    expect(output).not.toMatch(/\b\d+\.\d+%/);
  });

  it('renders a populated metric as a percentage', () => {
    const input: ReportInput = {
      ...BASE_INPUT,
      metrics: { ...BASE_INPUT.metrics, robustnessPassRate: 1.0 },
    };
    const output = generateReport(input);
    expect(output).toContain('100.0%');
  });

  it('renders differentialLedgerNote free-text when provided', () => {
    const input: ReportInput = {
      ...BASE_INPUT,
      metrics: { ...BASE_INPUT.metrics, differentialLedgerNote: '3 deltas, all classified' },
    };
    const output = generateReport(input);
    expect(output).toContain('3 deltas, all classified');
  });
});

describe('generateReport — notes ordering', () => {
  it('sorts notes by title alphabetically regardless of input order', () => {
    const input: ReportInput = {
      ...BASE_INPUT,
      notes: [
        { title: 'Zebra note', body: 'z' },
        { title: 'Alpha note', body: 'a' },
        { title: 'Mango note', body: 'm' },
      ],
    };
    const output = generateReport(input);
    const alphaIdx = output.indexOf('Alpha note');
    const mangoIdx = output.indexOf('Mango note');
    const zebraIdx = output.indexOf('Zebra note');
    expect(alphaIdx).toBeGreaterThan(-1);
    expect(alphaIdx).toBeLessThan(mangoIdx);
    expect(mangoIdx).toBeLessThan(zebraIdx);
  });

  it('renders each note as an H3 with its body below', () => {
    const input: ReportInput = {
      ...BASE_INPUT,
      notes: [{ title: 'A note', body: 'A body.' }],
    };
    const output = generateReport(input);
    expect(output).toContain('### A note');
    expect(output).toContain('A body.');
  });

  it('omits the "Gaps & follow-ups" section when notes are absent or empty', () => {
    const output = generateReport(BASE_INPUT);
    expect(output).not.toContain('Gaps & follow-ups');
  });
});

describe('generateReport — structural invariants', () => {
  it('has exactly one trailing newline (deterministic file endings)', () => {
    const output = generateReport(BASE_INPUT);
    expect(output.endsWith('\n')).toBe(true);
    expect(output.endsWith('\n\n')).toBe(false);
  });

  it('starts with the H1 "# ASSURANCE.md"', () => {
    const output = generateReport(BASE_INPUT);
    expect(output.split('\n')[0]).toBe('# ASSURANCE.md');
  });

  it('renders the honesty note about enumerated coverage', () => {
    const output = generateReport(BASE_INPUT);
    expect(output).toContain('is a floor, not a ceiling');
  });
});
