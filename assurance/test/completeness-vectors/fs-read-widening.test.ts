/**
 * fs-read-widening — completeness-vector transform self-tests.
 *
 * Contract every transform satisfies (mirrors fs-write-widening.test.ts):
 *   • PURITY / DETERMINISM — `transform(src, seed) === transform(src, seed)` byte-identical.
 *   • NON-TRIVIALITY       — when the target pattern is present in `src`, `transform !== src`.
 *   • SYNTACTIC VALIDITY   — output parses under @babel/parser (valid JavaScript).
 *   • SEMANTIC PRESERVATION MARKER — the output references the sibling API.
 *
 * All fixture paths use RFC 2606 reserved / *.invalid so scanForDefangViolations
 * clears them. The transforms only parse and rewrite — they never execute — so
 * the fixtures don't need to be runnable, only defang-clean.
 */

import { describe, it, expect } from 'vitest';
import * as parser from '@babel/parser';
import { readFileToReadFileSync } from '../../src/completeness-vectors/fs-read-widening.js';

const SEEDS: readonly number[] = [0, 1, 7, 42, 1337, 2_147_483_647];

function parsesCleanly(source: string): boolean {
  try {
    parser.parse(source, {
      sourceType: 'unambiguous',
      allowReturnOutsideFunction: true,
      allowImportExportEverywhere: true,
      errorRecovery: true,
    });
    return true;
  } catch {
    return false;
  }
}

const SOURCE_WITH_PATTERN =
  'const fs = require("fs"); fs.readFile("/tmp/f.invalid", (err, data) => {});';

describe('completeness-vectors — fs-read-widening', () => {
  it('declares the sink-family-widening family and fs-read targetClass', () => {
    expect(readFileToReadFileSync.family).toBe('sink-family-widening');
    expect(readFileToReadFileSync.targetClass).toBe('fs-read');
    expect(readFileToReadFileSync.id.length).toBeGreaterThan(0);
    expect(readFileToReadFileSync.description.length).toBeGreaterThan(0);
  });

  it('is pure/deterministic: same (source, seed) → byte-identical output', () => {
    for (const seed of SEEDS) {
      const a = readFileToReadFileSync.transform(SOURCE_WITH_PATTERN, seed);
      const b = readFileToReadFileSync.transform(SOURCE_WITH_PATTERN, seed);
      expect(b).toBe(a);
    }
  });

  it('is non-trivial when the fs.readFile pattern is present', () => {
    for (const seed of SEEDS) {
      const out = readFileToReadFileSync.transform(SOURCE_WITH_PATTERN, seed);
      expect(out).not.toBe(SOURCE_WITH_PATTERN);
    }
  });

  it('produces syntactically valid JavaScript output', () => {
    for (const seed of SEEDS) {
      const out = readFileToReadFileSync.transform(SOURCE_WITH_PATTERN, seed);
      expect(parsesCleanly(out), `seed=${seed} produced unparseable output`).toBe(true);
    }
  });

  it('emits readFileSync in place of readFile', () => {
    const out = readFileToReadFileSync.transform(SOURCE_WITH_PATTERN, 0);
    expect(out).toContain('readFileSync');
    expect(out).toContain('/tmp/f.invalid');
  });

  it('drops the trailing callback', () => {
    const src =
      'const fs = require("fs"); fs.readFile("/tmp/x.invalid", (err, data) => { throw err; });';
    const out = readFileToReadFileSync.transform(src, 0);
    expect(out).not.toContain('throw err');
    expect(out).toContain('/tmp/x.invalid');
  });

  it('is a no-op on source that does NOT contain fs.readFile', () => {
    const benign = 'const x = 1;\nconsole.log(x);\n';
    for (const seed of SEEDS) {
      expect(readFileToReadFileSync.transform(benign, seed)).toBe(benign);
    }
  });

  it('is a no-op on source with fs.writeFile (different sibling)', () => {
    const other = 'const fs = require("fs"); fs.writeFile("/tmp/y.invalid", "d", () => {});';
    expect(readFileToReadFileSync.transform(other, 0)).toBe(other);
  });
});
