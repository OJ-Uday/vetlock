/**
 * integrity-normalization — completeness-vector transform self-tests.
 *
 * Contract every transform satisfies:
 *   • PURITY / DETERMINISM — `transform(src, seed) === transform(src, seed)` byte-identical.
 *   • NON-TRIVIALITY       — when the target pattern is present in `src`, `transform !== src`.
 *   • SYNTACTIC VALIDITY   — output parses under @babel/parser (valid JavaScript).
 *   • SEMANTIC PRESERVATION MARKER — the output uses the hex-encoded digest shape.
 */

import { describe, it, expect } from 'vitest';
import * as parser from '@babel/parser';
import { sha256Reimplement } from '../../src/completeness-vectors/integrity-normalization.js';

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

/** Source containing the canonical bare-digest sha256 chain. */
const SOURCE_WITH_SHA256_BARE =
  'const h = crypto.createHash("sha256").update(payload).digest();';

/** Source where digest already has an argument — the transform must NOT add another. */
const SOURCE_ALREADY_HEX =
  'const h = crypto.createHash("sha256").update(payload).digest("hex");';

/** Source with no sha256 chain — every transform should be a no-op. */
const SOURCE_NO_SHA256 = 'const x = 1;\nconsole.log(x);\n';

describe('completeness-vectors — integrity-normalization', () => {
  it('declares the integrity targetClass and required metadata fields', () => {
    expect(sha256Reimplement.targetClass).toBe('integrity');
    expect(sha256Reimplement.id.length).toBeGreaterThan(0);
    expect(sha256Reimplement.family.length).toBeGreaterThan(0);
    expect(sha256Reimplement.description.length).toBeGreaterThan(0);
  });

  it('is pure/deterministic: same (source, seed) → byte-identical output', () => {
    for (const seed of SEEDS) {
      const a = sha256Reimplement.transform(SOURCE_WITH_SHA256_BARE, seed);
      const b = sha256Reimplement.transform(SOURCE_WITH_SHA256_BARE, seed);
      expect(b).toBe(a);
    }
  });

  it('is non-trivial: output DIFFERS from input when the bare-digest chain is present', () => {
    for (const seed of SEEDS) {
      const out = sha256Reimplement.transform(SOURCE_WITH_SHA256_BARE, seed);
      expect(out).not.toBe(SOURCE_WITH_SHA256_BARE);
    }
  });

  it('produces syntactically valid JavaScript output', () => {
    for (const seed of SEEDS) {
      const out = sha256Reimplement.transform(SOURCE_WITH_SHA256_BARE, seed);
      expect(parsesCleanly(out), `seed=${seed} produced unparseable output:\n${out}`).toBe(true);
    }
  });

  it('output contains the hex-encoding digest argument (semantic-preservation)', () => {
    for (const seed of SEEDS) {
      const out = sha256Reimplement.transform(SOURCE_WITH_SHA256_BARE, seed);
      expect(out).toContain('.digest("hex")');
    }
  });

  it('preserves the createHash + update chain shape unchanged', () => {
    const out = sha256Reimplement.transform(SOURCE_WITH_SHA256_BARE, 0);
    // The chain leading up to the terminal digest call must be intact.
    expect(out).toContain('createHash("sha256")');
    expect(out).toContain('.update(payload)');
  });

  it('is a no-op when digest already has an argument (idempotent re-application)', () => {
    for (const seed of SEEDS) {
      const out = sha256Reimplement.transform(SOURCE_ALREADY_HEX, seed);
      expect(out).toBe(SOURCE_ALREADY_HEX);
    }
  });

  it('is a no-op on source with no sha256 chain', () => {
    for (const seed of SEEDS) {
      const out = sha256Reimplement.transform(SOURCE_NO_SHA256, seed);
      expect(out).toBe(SOURCE_NO_SHA256);
    }
  });
});
