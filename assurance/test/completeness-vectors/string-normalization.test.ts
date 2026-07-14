/**
 * string-normalization — completeness-vector transform self-tests.
 *
 * Contract every transform satisfies:
 *   • PURITY / DETERMINISM — `transform(src, seed) === transform(src, seed)` byte-identical.
 *   • NON-TRIVIALITY       — when a watchlisted literal is present in `src`, `transform !== src`.
 *   • SYNTACTIC VALIDITY   — output parses under @babel/parser (valid JavaScript).
 *
 * These transforms are ECMAScript-spec equivalents: constant-folded output has the
 * same value as the original literal. The scanner's job is to fold; the test
 * exercises the "did the fold happen" surface without executing anything.
 */

import { describe, it, expect } from 'vitest';
import * as parser from '@babel/parser';
import {
  literalToConcat,
  literalToTemplate,
  literalToCharCodeRebuild,
  type CompletenessTransform,
} from '../../src/completeness-vectors/index.js';

const SEEDS: readonly number[] = [0, 1, 7, 42, 1337, 2_147_483_647];

function parsesCleanly(source: string): boolean {
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
    return true;
  } catch {
    return false;
  }
}

const TRANSFORMS: readonly CompletenessTransform[] = [
  literalToConcat,
  literalToTemplate,
  literalToCharCodeRebuild,
];

/** Source containing a watchlisted literal (`"child_process"`). Every transform
 *  in this family must widen it. */
const SOURCE_WITH_WATCHLIST = 'const cp = require("child_process"); cp.exec("echo hi");';

/** Source containing no watchlisted literal — every transform should be a no-op. */
const SOURCE_NO_WATCHLIST = 'const x = "not-a-sink"; console.log(x);';

describe('completeness-vectors — string-normalization', () => {
  describe.each(TRANSFORMS)(
    'transform: $id',
    (transform) => {
      it('declares the string-normalization family and metadata fields', () => {
        expect(transform.family).toBe('string-normalization');
        expect(transform.targetClass.length).toBeGreaterThan(0);
        expect(transform.id.length).toBeGreaterThan(0);
        expect(transform.description.length).toBeGreaterThan(0);
      });

      it('is pure/deterministic: same (source, seed) → byte-identical output', () => {
        for (const seed of SEEDS) {
          const a = transform.transform(SOURCE_WITH_WATCHLIST, seed);
          const b = transform.transform(SOURCE_WITH_WATCHLIST, seed);
          expect(b).toBe(a);
        }
      });

      it('is non-trivial: output DIFFERS from input when a watchlisted literal is present', () => {
        for (const seed of SEEDS) {
          const out = transform.transform(SOURCE_WITH_WATCHLIST, seed);
          expect(out).not.toBe(SOURCE_WITH_WATCHLIST);
        }
      });

      it('produces syntactically valid JavaScript output', () => {
        for (const seed of SEEDS) {
          const out = transform.transform(SOURCE_WITH_WATCHLIST, seed);
          expect(parsesCleanly(out), `seed=${seed} produced unparseable output:\n${out}`).toBe(true);
        }
      });

      it('is a no-op on source with no watchlisted literals', () => {
        for (const seed of SEEDS) {
          const out = transform.transform(SOURCE_NO_WATCHLIST, seed);
          expect(out).toBe(SOURCE_NO_WATCHLIST);
        }
      });

      it('the ORIGINAL literal shape is no longer present verbatim after transform', () => {
        // The original had `"child_process"` as a plain string; the transformed form
        // should have replaced it with something else (concat / template / call).
        // This guards against the "no-op-when-should-have-rewritten" regression.
        for (const seed of SEEDS) {
          const out = transform.transform(SOURCE_WITH_WATCHLIST, seed);
          expect(out).not.toContain('"child_process"');
        }
      });
    },
  );
});

// --- transform-specific structural assertions -------------------------------------------------
//
// Each transform's output has a shape we can check inexpensively — enough to prove
// the transform did what its id claims (concat contains `+`; template contains
// backticks; char-code contains `String.fromCharCode`).

describe('literalToConcat structural signature', () => {
  it('output contains a chained string concatenation (`+`)', () => {
    const out = literalToConcat.transform(SOURCE_WITH_WATCHLIST, 0);
    expect(out).toContain(' + ');
  });
});

describe('literalToTemplate structural signature', () => {
  it('output contains a template literal (backticks)', () => {
    const out = literalToTemplate.transform(SOURCE_WITH_WATCHLIST, 0);
    expect(out).toContain('`');
  });
});

describe('literalToCharCodeRebuild structural signature', () => {
  it('output contains a `String.fromCharCode(...)` call', () => {
    const out = literalToCharCodeRebuild.transform(SOURCE_WITH_WATCHLIST, 0);
    expect(out).toContain('String.fromCharCode(');
  });
});
