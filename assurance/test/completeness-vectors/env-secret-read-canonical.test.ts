/**
 * env-secret-read-canonical — completeness-vector transform self-tests.
 *
 * The transform under test — `envToBracketedComputed` — targets the packet §3.5
 * canonical slash-form `env/secret-read` class. Semantically the same as
 * `envToProcessEnv`, distinct id, distinct targetClass string.
 */

import { describe, it, expect } from 'vitest';
import * as parser from '@babel/parser';
import { envToBracketedComputed } from '../../src/completeness-vectors/env-secret-read-canonical.js';

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

const SOURCE_WITH_PATTERN = 'const token = process.env.NPM_TOKEN;\n';

describe('completeness-vectors — env-secret-read-canonical', () => {
  it('declares the packet-canonical env/secret-read targetClass', () => {
    expect(envToBracketedComputed.targetClass).toBe('env/secret-read');
    expect(envToBracketedComputed.family).toBe('sink-family-widening');
    expect(envToBracketedComputed.id.length).toBeGreaterThan(0);
  });

  it('is pure/deterministic', () => {
    for (const seed of SEEDS) {
      const a = envToBracketedComputed.transform(SOURCE_WITH_PATTERN, seed);
      const b = envToBracketedComputed.transform(SOURCE_WITH_PATTERN, seed);
      expect(b).toBe(a);
    }
  });

  it('is non-trivial when process.env.<KEY> is present', () => {
    for (const seed of SEEDS) {
      const out = envToBracketedComputed.transform(SOURCE_WITH_PATTERN, seed);
      expect(out).not.toBe(SOURCE_WITH_PATTERN);
    }
  });

  it('produces syntactically valid JavaScript output', () => {
    for (const seed of SEEDS) {
      const out = envToBracketedComputed.transform(SOURCE_WITH_PATTERN, seed);
      expect(parsesCleanly(out)).toBe(true);
    }
  });

  it('emits computed-form access', () => {
    const out = envToBracketedComputed.transform(SOURCE_WITH_PATTERN, 0);
    // babel prints computed-form as [...]; the KEY should appear as a string literal.
    expect(out).toMatch(/process\.env\[["']NPM_TOKEN["']\]/);
  });

  it('is a no-op on source without process.env access', () => {
    const benign = 'const x = 1;\nconsole.log(x);\n';
    for (const seed of SEEDS) {
      expect(envToBracketedComputed.transform(benign, seed)).toBe(benign);
    }
  });

  it('is a no-op on already-computed forms', () => {
    // If input already has `process.env["FOO"]` (computed), the identifier-property
    // predicate rejects it — no rewrite needed.
    const src = 'const x = process.env["FOO"];\n';
    expect(envToBracketedComputed.transform(src, 0)).toBe(src);
  });
});
