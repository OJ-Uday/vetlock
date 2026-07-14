/**
 * python-code-exec-widening — completeness-vector transform self-tests.
 *
 * Contract: PURITY / NON-TRIVIALITY / NO-OP-ON-BENIGN. Output validity is
 * checked by shape (contains the expected sibling idiom string) rather than by
 * parsing — Python's grammar isn't ambient in Node, and the transform is a
 * regex rewrite of a specific idiom line.
 */

import { describe, it, expect } from 'vitest';
import { pyExecToEvalCompile } from '../../src/completeness-vectors/python-code-exec-widening.js';

const SEEDS: readonly number[] = [0, 1, 7, 42, 1337, 2_147_483_647];

const PY_WITH_EXEC = 'x = 1\nexec(user_input)\nprint(x)\n';
const PY_INDENTED = 'def run(u):\n    exec(u)\n';

describe('completeness-vectors — python-code-exec-widening', () => {
  it('declares the python-code-exec targetClass', () => {
    expect(pyExecToEvalCompile.targetClass).toBe('python-code-exec');
    expect(pyExecToEvalCompile.family).toBe('sink-family-widening');
    expect(pyExecToEvalCompile.id.length).toBeGreaterThan(0);
  });

  it('is pure/deterministic', () => {
    for (const seed of SEEDS) {
      const a = pyExecToEvalCompile.transform(PY_WITH_EXEC, seed);
      const b = pyExecToEvalCompile.transform(PY_WITH_EXEC, seed);
      expect(b).toBe(a);
    }
  });

  it('is non-trivial when exec(...) is present at line-head', () => {
    for (const seed of SEEDS) {
      const out = pyExecToEvalCompile.transform(PY_WITH_EXEC, seed);
      expect(out).not.toBe(PY_WITH_EXEC);
    }
  });

  it('emits the eval(compile(...)) sibling idiom', () => {
    const out = pyExecToEvalCompile.transform(PY_WITH_EXEC, 0);
    expect(out).toContain('eval(compile(user_input');
    expect(out).toContain('"exec"');
  });

  it('preserves indentation', () => {
    const out = pyExecToEvalCompile.transform(PY_INDENTED, 0);
    expect(out).toContain('    eval(compile(u');
  });

  it('is a no-op on Python without exec()', () => {
    const benign = 'print("hello")\nx = 42\n';
    for (const seed of SEEDS) {
      expect(pyExecToEvalCompile.transform(benign, seed)).toBe(benign);
    }
  });

  it('is a no-op on JavaScript source without matching line-heads', () => {
    const js = 'const cp = require("child_process"); cp.exec("echo hi");\n';
    // The regex requires `exec(` at the start of a line's non-whitespace content;
    // `cp.exec(...)` is a member call, not a line-head bare call, so this is a no-op.
    expect(pyExecToEvalCompile.transform(js, 0)).toBe(js);
  });
});
