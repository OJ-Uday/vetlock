/**
 * Metamorphic pair-generator self-tests (packet §5 P3).
 *
 * These tests define the contract every pair generator must satisfy:
 *   • DETERMINISM — `generate(seed)` returns byte-identical output for the same seed.
 *   • NON-TRIVIALITY — A and B are distinct source strings (the transform actually did
 *     something; identity pairs are useless as invariance probes).
 *   • VALIDITY — both A and B parse to valid @babel/parser ASTs. If either side is
 *     unparseable JS, the pair can't feed the analyzer.
 *
 * The battery helper `generatePairBattery` is also exercised: it cycles through all
 * registered families and produces the requested number of pairs deterministically.
 */

import { describe, it, expect } from 'vitest';
import * as parser from '@babel/parser';
import {
  allPairGenerators,
  generatePairBattery,
  statementReorder,
  alphaRename,
  equivalentExpression,
  whitespaceComments,
  memberAccessForm,
  type PairGenerator,
  type MetamorphicPair,
} from '../../src/metamorphic/index.js';

/** Parse under the same tolerant options the engine's capability extractor uses. */
function tryParse(source: string): { ok: true } | { ok: false; error: string } {
  try {
    parser.parse(source, {
      sourceType: 'unambiguous',
      allowReturnOutsideFunction: true,
      allowImportExportEverywhere: true,
      allowAwaitOutsideFunction: true,
      allowSuperOutsideMethod: true,
      allowUndeclaredExports: true,
      errorRecovery: true,
      plugins: [
        'jsx',
        'typescript',
        ['decorators', { decoratorsBeforeExport: false }],
        'classProperties',
        'optionalChaining',
        'nullishCoalescingOperator',
        'topLevelAwait',
      ],
    });
    return { ok: true };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  }
}

const SEEDS: readonly number[] = [0, 1, 7, 42, 1337, 2_147_483_647];

const GENERATORS: readonly PairGenerator[] = [
  statementReorder,
  alphaRename,
  equivalentExpression,
  whitespaceComments,
  memberAccessForm,
];

describe('metamorphic pair generators — registry', () => {
  it('allPairGenerators contains all five expected families in a stable order', () => {
    expect(allPairGenerators.map((g) => g.family)).toEqual([
      'statement-reorder',
      'alpha-rename',
      'equivalent-expression',
      'whitespace-comments',
      'member-access-form',
    ]);
  });

  it('each generator declares a matching `family` field', () => {
    for (const gen of allPairGenerators) {
      const pair = gen.generate(0);
      expect(pair.family).toBe(gen.family);
    }
  });
});

describe.each(GENERATORS)(
  'pair generator: $family',
  (gen) => {
    it('is deterministic across seeds (byte-identical output for the same seed)', () => {
      for (const seed of SEEDS) {
        const p1 = gen.generate(seed);
        const p2 = gen.generate(seed);
        expect(p2).toEqual(p1);
        // Also assert the byte-level strings match (guards against object-identity vs value).
        expect(p2.a).toBe(p1.a);
        expect(p2.b).toBe(p1.b);
        expect(p2.id).toBe(p1.id);
      }
    });

    it('produces pairs where A and B are DIFFERENT source strings', () => {
      for (const seed of SEEDS) {
        const pair = gen.generate(seed);
        expect(pair.a).not.toBe(pair.b);
        expect(pair.a.length).toBeGreaterThan(0);
        expect(pair.b.length).toBeGreaterThan(0);
      }
    });

    it('both A and B parse as valid JS under babel', () => {
      for (const seed of SEEDS) {
        const pair = gen.generate(seed);
        const ra = tryParse(pair.a);
        const rb = tryParse(pair.b);
        if (!ra.ok) {
          throw new Error(
            `pair ${pair.id} seed=${seed}: A failed to parse (${ra.error})\nA:\n${pair.a}`,
          );
        }
        if (!rb.ok) {
          throw new Error(
            `pair ${pair.id} seed=${seed}: B failed to parse (${rb.error})\nB:\n${pair.b}`,
          );
        }
        expect(ra.ok).toBe(true);
        expect(rb.ok).toBe(true);
      }
    });

    it('reports id, family, and description fields', () => {
      const pair = gen.generate(0);
      expect(pair.id.length).toBeGreaterThan(0);
      expect(pair.family).toBe(gen.family);
      expect(pair.description.length).toBeGreaterThan(0);
    });
  },
);

describe('generatePairBattery', () => {
  it('produces exactly `count` pairs', () => {
    const battery = generatePairBattery(42, 10);
    expect(battery).toHaveLength(10);
  });

  it('cycles through families in registry order', () => {
    const battery = generatePairBattery(42, allPairGenerators.length * 2);
    for (let i = 0; i < battery.length; i++) {
      expect(battery[i].family).toBe(allPairGenerators[i % allPairGenerators.length].family);
    }
  });

  it('is deterministic: same (seed, count) returns byte-identical output', () => {
    const b1 = generatePairBattery(1337, 15);
    const b2 = generatePairBattery(1337, 15);
    expect(b2).toEqual(b1);
  });

  it('every pair in the battery is parseable on both sides', () => {
    const battery: readonly MetamorphicPair[] = generatePairBattery(2026, 20);
    for (const pair of battery) {
      const ra = tryParse(pair.a);
      const rb = tryParse(pair.b);
      expect(ra.ok, `A: ${pair.id}`).toBe(true);
      expect(rb.ok, `B: ${pair.id}`).toBe(true);
    }
  });

  it('accepts count=0 (returns empty array)', () => {
    expect(generatePairBattery(1, 0)).toEqual([]);
  });

  it('throws on non-integer or negative count', () => {
    expect(() => generatePairBattery(1, -1)).toThrow(/count must be/);
    expect(() => generatePairBattery(1, 1.5)).toThrow(/count must be/);
  });
});
