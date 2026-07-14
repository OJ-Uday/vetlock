/**
 * crypto-mine-normalization — completeness-vector transform self-tests.
 *
 * Contract every transform satisfies:
 *   • PURITY / DETERMINISM — `transform(src, seed) === transform(src, seed)` byte-identical.
 *   • NON-TRIVIALITY       — when the target pattern is present in `src`, `transform !== src`.
 *   • SYNTACTIC VALIDITY   — output parses under @babel/parser (valid JavaScript).
 *   • SEMANTIC PRESERVATION MARKER — the output references the Node-crypto sibling API chain.
 */

import { describe, it, expect } from 'vitest';
import * as parser from '@babel/parser';
import { webcryptoToNode } from '../../src/completeness-vectors/crypto-mine-normalization.js';

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

/** Source containing a `crypto.subtle.digest(...)` call the transform must widen. */
const SOURCE_WITH_SUBTLE = 'const d = crypto.subtle.digest("SHA-256", data);';

/** Source with no subtle.digest — every transform should be a no-op. */
const SOURCE_NO_SUBTLE = 'const x = 1;\nconsole.log(x);\n';

describe('completeness-vectors — crypto-mine-normalization', () => {
  it('declares the crypto-mine targetClass and required metadata fields', () => {
    expect(webcryptoToNode.targetClass).toBe('crypto-mine');
    expect(webcryptoToNode.id.length).toBeGreaterThan(0);
    expect(webcryptoToNode.family.length).toBeGreaterThan(0);
    expect(webcryptoToNode.description.length).toBeGreaterThan(0);
  });

  it('is pure/deterministic: same (source, seed) → byte-identical output', () => {
    for (const seed of SEEDS) {
      const a = webcryptoToNode.transform(SOURCE_WITH_SUBTLE, seed);
      const b = webcryptoToNode.transform(SOURCE_WITH_SUBTLE, seed);
      expect(b).toBe(a);
    }
  });

  it('is non-trivial: output DIFFERS from input when subtle.digest is present', () => {
    for (const seed of SEEDS) {
      const out = webcryptoToNode.transform(SOURCE_WITH_SUBTLE, seed);
      expect(out).not.toBe(SOURCE_WITH_SUBTLE);
    }
  });

  it('produces syntactically valid JavaScript output', () => {
    for (const seed of SEEDS) {
      const out = webcryptoToNode.transform(SOURCE_WITH_SUBTLE, seed);
      expect(parsesCleanly(out), `seed=${seed} produced unparseable output:\n${out}`).toBe(true);
    }
  });

  it('output contains the Node-crypto sibling API chain (semantic-preservation)', () => {
    for (const seed of SEEDS) {
      const out = webcryptoToNode.transform(SOURCE_WITH_SUBTLE, seed);
      // The rewritten output must reference `createHash`, `.update(`, and `.digest(`.
      // That's the shape a Node-crypto hash chain takes.
      expect(out).toContain('createHash');
      expect(out).toContain('.update(');
      expect(out).toContain('.digest(');
    }
  });

  it('preserves the algorithm argument verbatim', () => {
    // "SHA-256" is the Web-Crypto canonical form; the transform forwards it as-is
    // rather than normalising case. Constant-folding is the scanner's job.
    const out = webcryptoToNode.transform(SOURCE_WITH_SUBTLE, 0);
    expect(out).toContain('"SHA-256"');
  });

  it('the original subtle.digest shape is no longer present verbatim after transform', () => {
    for (const seed of SEEDS) {
      const out = webcryptoToNode.transform(SOURCE_WITH_SUBTLE, seed);
      expect(out).not.toContain('.subtle.digest(');
    }
  });

  it('is a no-op on source with no subtle.digest call', () => {
    for (const seed of SEEDS) {
      const out = webcryptoToNode.transform(SOURCE_NO_SUBTLE, seed);
      expect(out).toBe(SOURCE_NO_SUBTLE);
    }
  });
});
