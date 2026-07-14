/**
 * fs-write-widening — completeness-vector transform self-tests.
 *
 * Contract every transform satisfies (mirrors sink-family-widening.test.ts):
 *   • PURITY / DETERMINISM — `transform(src, seed) === transform(src, seed)` byte-identical.
 *   • NON-TRIVIALITY       — when the target pattern is present in `src`, `transform !== src`.
 *   • SYNTACTIC VALIDITY   — output parses under @babel/parser (valid JavaScript).
 *   • SEMANTIC PRESERVATION MARKER — the output references the sibling API.
 *
 * All fixture sources are defang-guard-clean: paths use `/tmp/foo.invalid`, data
 * is plain string literals, no real endpoints. The transforms don't execute code —
 * they parse and rewrite — but the fixtures avoid triggering any static scanner
 * that reads this test file as data.
 */

import { describe, it, expect } from 'vitest';
import * as parser from '@babel/parser';
import {
  writeFileToWriteFileSync,
  writeFileToCreateWriteStream,
} from '../../src/completeness-vectors/fs-write-widening.js';
import type { CompletenessTransform } from '../../src/completeness-vectors/types.js';

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
    transform: writeFileToWriteFileSync,
    sourceWithPattern:
      'const fs = require("fs"); fs.writeFile("/tmp/f.invalid", "data", (err) => {});',
    siblingMarker: 'writeFileSync',
    originalMarker: '.writeFile(',
  },
  {
    transform: writeFileToCreateWriteStream,
    sourceWithPattern:
      'const fs = require("fs"); fs.writeFile("/tmp/g.invalid", "data", (err) => {});',
    siblingMarker: 'createWriteStream',
    originalMarker: '.writeFile(',
  },
];

describe('completeness-vectors — fs-write-widening', () => {
  describe.each(CASES)(
    'transform: $transform.id',
    ({ transform, sourceWithPattern, siblingMarker, originalMarker }) => {
      it('declares the sink-family-widening family and fs-write targetClass', () => {
        expect(transform.family).toBe('sink-family-widening');
        expect(transform.targetClass).toBe('fs-write');
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
        expect(sourceWithPattern).toContain(originalMarker);
        for (const seed of SEEDS) {
          const out = transform.transform(sourceWithPattern, seed);
          expect(out).not.toBe(sourceWithPattern);
        }
      });

      it('produces syntactically valid JavaScript output', () => {
        for (const seed of SEEDS) {
          const out = transform.transform(sourceWithPattern, seed);
          expect(
            parsesCleanly(out),
            `seed=${seed} produced unparseable output:\n${out}`,
          ).toBe(true);
        }
      });

      it('output contains the sibling API marker (semantic-preservation check)', () => {
        for (const seed of SEEDS) {
          const out = transform.transform(sourceWithPattern, seed);
          expect(
            out,
            `seed=${seed} output missing sibling marker "${siblingMarker}":\n${out}`,
          ).toContain(siblingMarker);
        }
      });

      it('is a no-op on source that does NOT contain fs.writeFile', () => {
        const benign = 'const x = 1;\nconsole.log(x);\n';
        for (const seed of SEEDS) {
          const out = transform.transform(benign, seed);
          expect(out).toBe(benign);
        }
      });
    },
  );

  // ------- transform-specific structural assertions --------------------------
  describe('writeFileToWriteFileSync structural signature', () => {
    it('drops the trailing callback', () => {
      const src =
        'const fs = require("fs"); fs.writeFile("/tmp/x.invalid", "data", (err) => { throw err; });';
      const out = writeFileToWriteFileSync.transform(src, 0);
      // Callback body content must not survive.
      expect(out).not.toContain('throw err');
      // But path and data literals do.
      expect(out).toContain('/tmp/x.invalid');
      expect(out).toContain('"data"');
    });

    it('handles the no-callback form (fs.writeFile(path, data))', () => {
      const src = 'const fs = require("fs"); fs.writeFile("/tmp/y.invalid", "data");';
      const out = writeFileToWriteFileSync.transform(src, 0);
      expect(out).toContain('writeFileSync');
      expect(out).toContain('/tmp/y.invalid');
    });
  });

  describe('writeFileToCreateWriteStream structural signature', () => {
    it('emits a `.write(data)` call following the createWriteStream call', () => {
      const src =
        'const fs = require("fs"); fs.writeFile("/tmp/z.invalid", "data", () => {});';
      const out = writeFileToCreateWriteStream.transform(src, 0);
      expect(out).toContain('createWriteStream');
      expect(out).toContain('.write(');
      expect(out).toContain('/tmp/z.invalid');
      expect(out).toContain('"data"');
    });

    it('is a no-op when fewer than two args are supplied', () => {
      // `fs.writeFile("/tmp/w.invalid")` alone is nonsense but should not crash.
      const src = 'const fs = require("fs"); fs.writeFile("/tmp/w.invalid");';
      const out = writeFileToCreateWriteStream.transform(src, 0);
      expect(out).toBe(src);
    });
  });
});
