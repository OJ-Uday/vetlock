/**
 * process-enum-widening — completeness-vector transform self-tests.
 *
 * Contract every transform satisfies:
 *   • PURITY / DETERMINISM — `transform(src, seed) === transform(src, seed)` byte-identical.
 *   • NON-TRIVIALITY       — when the target pattern is present in `src`, `transform !== src`.
 *   • SYNTACTIC VALIDITY   — output parses under @babel/parser (valid JavaScript).
 *   • SEMANTIC PRESERVATION MARKER — the output references the child_process shell-out shape.
 */

import { describe, it, expect } from 'vitest';
import * as parser from '@babel/parser';
import { psListToChildProcess } from '../../src/completeness-vectors/process-enum-widening.js';

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

/** Source containing the ps-list invocation shape (Case 1 in the transform). */
const SOURCE_WITH_PSLIST_CALL = 'const procs = require("ps-list")();';

/** Source with a bare require('ps-list') stored to a variable (Case 2). */
const SOURCE_WITH_PSLIST_BARE = 'const psList = require("ps-list");';

/** Source with no ps-list reference — every transform should be a no-op. */
const SOURCE_NO_PSLIST = 'const x = require("lodash");\nconsole.log(x);\n';

describe('completeness-vectors — process-enum-widening', () => {
  it('declares the process-enumeration targetClass and required metadata fields', () => {
    expect(psListToChildProcess.targetClass).toBe('process-enumeration');
    expect(psListToChildProcess.id.length).toBeGreaterThan(0);
    expect(psListToChildProcess.family.length).toBeGreaterThan(0);
    expect(psListToChildProcess.description.length).toBeGreaterThan(0);
  });

  it('is pure/deterministic: same (source, seed) → byte-identical output', () => {
    for (const seed of SEEDS) {
      const a = psListToChildProcess.transform(SOURCE_WITH_PSLIST_CALL, seed);
      const b = psListToChildProcess.transform(SOURCE_WITH_PSLIST_CALL, seed);
      expect(b).toBe(a);
    }
  });

  it('is non-trivial: output DIFFERS from input when ps-list is present', () => {
    for (const seed of SEEDS) {
      const out = psListToChildProcess.transform(SOURCE_WITH_PSLIST_CALL, seed);
      expect(out).not.toBe(SOURCE_WITH_PSLIST_CALL);
    }
  });

  it('produces syntactically valid JavaScript output', () => {
    for (const seed of SEEDS) {
      const out = psListToChildProcess.transform(SOURCE_WITH_PSLIST_CALL, seed);
      expect(parsesCleanly(out), `seed=${seed} produced unparseable output:\n${out}`).toBe(true);
    }
  });

  it('output references child_process.execSync with a ps invocation (semantic-preservation)', () => {
    for (const seed of SEEDS) {
      const out = psListToChildProcess.transform(SOURCE_WITH_PSLIST_CALL, seed);
      expect(out).toContain('child_process');
      expect(out).toContain('execSync');
      // The shell command body must be the defang-safe `ps aux` read-only enumeration.
      expect(out).toContain('"ps aux"');
    }
  });

  it('the original ps-list reference is no longer present verbatim after transform', () => {
    for (const seed of SEEDS) {
      const out = psListToChildProcess.transform(SOURCE_WITH_PSLIST_CALL, seed);
      expect(out).not.toContain('"ps-list"');
    }
  });

  it('rewrites the bare require(ps-list) reference to require(child_process)', () => {
    const out = psListToChildProcess.transform(SOURCE_WITH_PSLIST_BARE, 0);
    expect(out).not.toBe(SOURCE_WITH_PSLIST_BARE);
    expect(out).toContain('"child_process"');
    expect(out).not.toContain('"ps-list"');
  });

  it('is a no-op on source with no ps-list reference', () => {
    for (const seed of SEEDS) {
      const out = psListToChildProcess.transform(SOURCE_NO_PSLIST, seed);
      expect(out).toBe(SOURCE_NO_PSLIST);
    }
  });
});
