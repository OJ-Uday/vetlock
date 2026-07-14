/**
 * sink-family-widening — completeness-vector transform self-tests.
 *
 * Contract every transform satisfies:
 *   • PURITY / DETERMINISM — `transform(src, seed) === transform(src, seed)` byte-identical.
 *   • NON-TRIVIALITY       — when the target pattern is present in `src`, `transform !== src`.
 *   • SYNTACTIC VALIDITY   — output parses under @babel/parser (valid JavaScript).
 *   • SEMANTIC PRESERVATION MARKER — the output references the sibling API (static-content check).
 *
 * The transforms are pure functions from `(source, seed)` to a string, so seed is
 * exercised at multiple values to guard against accidental state.
 */

import { describe, it, expect } from 'vitest';
import * as parser from '@babel/parser';
import {
  execToExecFile,
  execToSpawn,
  httpRequestToHttpsRequest,
  type CompletenessTransform,
} from '../../src/completeness-vectors/index.js';

const SEEDS: readonly number[] = [0, 1, 7, 42, 1337, 2_147_483_647];

/** Parse under the tolerant options the engine's capability extractor uses. */
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

/**
 * Test case per transform: a source that CONTAINS the target pattern (so the
 * non-triviality check has something to compare) plus the sibling-marker string
 * to look for after transformation.
 */
interface WidenCase {
  readonly transform: CompletenessTransform;
  readonly sourceWithPattern: string;
  /** Substring the OUTPUT must contain to prove a sibling API was written. */
  readonly siblingMarker: string;
  /** Substring the INPUT must contain to prove the target pattern was present. */
  readonly originalMarker: string;
}

const CASES: readonly WidenCase[] = [
  {
    transform: execToExecFile,
    sourceWithPattern: 'child_process.exec("echo defanged");',
    siblingMarker: 'execFile',
    originalMarker: '.exec(',
  },
  {
    transform: execToSpawn,
    sourceWithPattern: 'require("child_process").exec("echo defanged");',
    siblingMarker: '.spawn(',
    originalMarker: '.exec(',
  },
  {
    transform: httpRequestToHttpsRequest,
    sourceWithPattern: 'const h = require("http"); h.request("http://example.com/p");',
    siblingMarker: '"https"',
    originalMarker: '"http"',
  },
];

describe('completeness-vectors — sink-family-widening', () => {
  describe.each(CASES)(
    'transform: $transform.id',
    ({ transform, sourceWithPattern, siblingMarker, originalMarker }) => {
      it('declares the sink-family-widening family and a non-empty targetClass', () => {
        expect(transform.family).toBe('sink-family-widening');
        expect(transform.targetClass.length).toBeGreaterThan(0);
        expect(transform.id.length).toBeGreaterThan(0);
        expect(transform.description.length).toBeGreaterThan(0);
      });

      it('is pure/deterministic: same (source, seed) → byte-identical output', () => {
        for (const seed of SEEDS) {
          const a = transform.transform(sourceWithPattern, seed);
          const b = transform.transform(sourceWithPattern, seed);
          expect(b).toBe(a);
        }
      });

      it('is non-trivial: output DIFFERS from input when the pattern is present', () => {
        // Baseline sanity: the source must actually contain the pattern the transform rewrites.
        // Any source that doesn't makes the non-triviality check vacuous.
        expect(sourceWithPattern).toContain(originalMarker);
        for (const seed of SEEDS) {
          const out = transform.transform(sourceWithPattern, seed);
          expect(out).not.toBe(sourceWithPattern);
        }
      });

      it('produces syntactically valid JavaScript output', () => {
        for (const seed of SEEDS) {
          const out = transform.transform(sourceWithPattern, seed);
          expect(parsesCleanly(out), `seed=${seed} produced unparseable output:\n${out}`).toBe(true);
        }
      });

      it('output contains the sibling API marker (semantic-preservation check)', () => {
        for (const seed of SEEDS) {
          const out = transform.transform(sourceWithPattern, seed);
          expect(out, `seed=${seed} output missing sibling marker "${siblingMarker}":\n${out}`).toContain(
            siblingMarker,
          );
        }
      });

      it('is a no-op on source that does NOT contain the target pattern', () => {
        // No child_process, no http, no exec — the transform should return the input unchanged.
        const benign = 'const x = 1;\nconsole.log(x);\n';
        for (const seed of SEEDS) {
          const out = transform.transform(benign, seed);
          expect(out).toBe(benign);
        }
      });
    },
  );
});
