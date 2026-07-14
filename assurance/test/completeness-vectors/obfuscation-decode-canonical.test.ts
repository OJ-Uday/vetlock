/**
 * obfuscation-decode-canonical — completeness-vector transform self-tests.
 *
 * The transform under test — `atobToBufferFrom` — targets the packet §3.5
 * canonical slash-form `obfuscation/decode` class. Tests mirror the shape of
 * obfuscation-normalization.test.ts.
 */

import { describe, it, expect } from 'vitest';
import * as parser from '@babel/parser';
import { atobToBufferFrom } from '../../src/completeness-vectors/obfuscation-decode-canonical.js';

const SEEDS: readonly number[] = [0, 1, 7, 42, 1337, 2_147_483_647];

function parsesCleanly(source: string): boolean {
  try {
    parser.parse(source, {
      sourceType: 'unambiguous',
      allowReturnOutsideFunction: true,
      errorRecovery: true,
    });
    return true;
  } catch {
    return false;
  }
}

const SOURCE_WITH_PATTERN = 'const decoded = atob("aGVsbG8=");\n';

describe('completeness-vectors — obfuscation-decode-canonical', () => {
  it('declares the packet-canonical obfuscation/decode targetClass', () => {
    expect(atobToBufferFrom.targetClass).toBe('obfuscation/decode');
    expect(atobToBufferFrom.family).toBe('sink-family-widening');
    expect(atobToBufferFrom.id.length).toBeGreaterThan(0);
    expect(atobToBufferFrom.description.length).toBeGreaterThan(0);
  });

  it('is pure/deterministic: same (source, seed) → byte-identical output', () => {
    for (const seed of SEEDS) {
      const a = atobToBufferFrom.transform(SOURCE_WITH_PATTERN, seed);
      const b = atobToBufferFrom.transform(SOURCE_WITH_PATTERN, seed);
      expect(b).toBe(a);
    }
  });

  it('is non-trivial when atob(...) is present', () => {
    for (const seed of SEEDS) {
      const out = atobToBufferFrom.transform(SOURCE_WITH_PATTERN, seed);
      expect(out).not.toBe(SOURCE_WITH_PATTERN);
    }
  });

  it('produces syntactically valid JavaScript output', () => {
    for (const seed of SEEDS) {
      const out = atobToBufferFrom.transform(SOURCE_WITH_PATTERN, seed);
      expect(parsesCleanly(out)).toBe(true);
    }
  });

  it('emits Buffer.from(...) with base64 encoding', () => {
    const out = atobToBufferFrom.transform(SOURCE_WITH_PATTERN, 0);
    expect(out).toContain('Buffer.from');
    expect(out).toContain('"base64"');
    expect(out).toContain('toString');
  });

  it('is a no-op on source without atob()', () => {
    const benign = 'const x = 1;\nconst y = String.fromCharCode(0x61);\n';
    for (const seed of SEEDS) {
      expect(atobToBufferFrom.transform(benign, seed)).toBe(benign);
    }
  });

  it('leaves `foo.atob(...)` (namespaced) alone', () => {
    // Guarded scope — only bare-identifier atob is rewritten, not member calls.
    const src = 'const y = foo.atob("abc");\n';
    const out = atobToBufferFrom.transform(src, 0);
    expect(out).toBe(src);
  });
});
