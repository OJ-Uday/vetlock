/**
 * obfuscation-normalization — completeness-vector transform self-tests.
 *
 * Contract every transform satisfies (mirrors sink-family-widening.test.ts):
 *   • PURITY / DETERMINISM — `transform(src, seed) === transform(src, seed)` byte-identical.
 *   • NON-TRIVIALITY       — when the target pattern is present in `src`, `transform !== src`.
 *   • SYNTACTIC VALIDITY   — output parses under @babel/parser (valid JavaScript).
 *   • SEMANTIC PRESERVATION MARKER — output references the sibling decoder shape.
 *
 * All fixture sources are defang-guard-clean: inputs to the decoders are plain
 * string literals or Identifier bindings; no encoded payloads that would
 * execute or leak anything.
 */

import { describe, it, expect } from 'vitest';
import * as parser from '@babel/parser';
import {
  base64DecodeToAtob,
  hexDecodeToParseInt,
} from '../../src/completeness-vectors/obfuscation-normalization.js';
import type { CompletenessTransform } from '../../src/completeness-vectors/types.js';

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

interface WidenCase {
  readonly transform: CompletenessTransform;
  readonly sourceWithPattern: string;
  readonly siblingMarker: string;
  readonly originalMarker: string;
}

const CASES: readonly WidenCase[] = [
  {
    transform: base64DecodeToAtob,
    sourceWithPattern: 'const raw = Buffer.from(payload, "base64").toString("utf8");',
    siblingMarker: 'atob(',
    originalMarker: 'Buffer.from(',
  },
  {
    transform: hexDecodeToParseInt,
    sourceWithPattern: 'const bytes = Buffer.from(hexInput, "hex");',
    siblingMarker: 'parseInt',
    originalMarker: 'Buffer.from(',
  },
];

describe('completeness-vectors — obfuscation-normalization', () => {
  describe.each(CASES)(
    'transform: $transform.id',
    ({ transform, sourceWithPattern, siblingMarker, originalMarker }) => {
      it('declares the sink-family-widening family and obfuscation-decode targetClass', () => {
        expect(transform.family).toBe('sink-family-widening');
        expect(transform.targetClass).toBe('obfuscation-decode');
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

      it('output contains the sibling decoder marker (semantic-preservation check)', () => {
        for (const seed of SEEDS) {
          const out = transform.transform(sourceWithPattern, seed);
          expect(
            out,
            `seed=${seed} output missing sibling marker "${siblingMarker}":\n${out}`,
          ).toContain(siblingMarker);
        }
      });

      it('is a no-op on source with no Buffer.from decoder call', () => {
        const benign = 'const x = 1;\nconsole.log(x);\n';
        for (const seed of SEEDS) {
          const out = transform.transform(benign, seed);
          expect(out).toBe(benign);
        }
      });
    },
  );

  // ------- transform-specific structural assertions --------------------------
  describe('base64DecodeToAtob structural signature', () => {
    it('rewrites to a bare atob() call over the same input expression', () => {
      const src = 'const raw = Buffer.from(payload, "base64").toString();';
      const out = base64DecodeToAtob.transform(src, 0);
      expect(out).toContain('atob(payload)');
      // The .toString() form should be gone.
      expect(out).not.toContain('.toString(');
    });

    it('leaves Buffer.from with a non-base64 encoding alone', () => {
      // Encoding is 'hex' → different transform's territory. This one is a no-op.
      const src = 'const raw = Buffer.from(payload, "hex").toString();';
      const out = base64DecodeToAtob.transform(src, 0);
      expect(out).toBe(src);
    });

    it('leaves Buffer.from without a following .toString() alone', () => {
      // Bytes-form: `Buffer.from(x, "base64")` returns a Buffer, but the
      // transform only fires on the outer `.toString(...)` call shape. Bail
      // conservatively rather than mangle unrelated usage.
      const src = 'const buf = Buffer.from(payload, "base64");';
      const out = base64DecodeToAtob.transform(src, 0);
      expect(out).toBe(src);
    });
  });

  describe('hexDecodeToParseInt structural signature', () => {
    it('emits a parseInt(_, 16) call and a Uint8Array constructor', () => {
      const src = 'const bytes = Buffer.from(hex, "hex");';
      const out = hexDecodeToParseInt.transform(src, 0);
      expect(out).toContain('parseInt');
      expect(out).toContain('16');
      expect(out).toContain('Uint8Array');
    });

    it('leaves Buffer.from with a non-hex encoding alone', () => {
      const src = 'const raw = Buffer.from(payload, "base64");';
      const out = hexDecodeToParseInt.transform(src, 0);
      expect(out).toBe(src);
    });

    it('leaves Buffer.from with a computed encoding alone (not statically hex)', () => {
      const src = 'const bytes = Buffer.from(payload, encoding);';
      const out = hexDecodeToParseInt.transform(src, 0);
      expect(out).toBe(src);
    });
  });
});
