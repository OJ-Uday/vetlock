/**
 * secret-read-widening — completeness-vector transform self-tests.
 *
 * Contract every transform satisfies (mirrors sink-family-widening.test.ts):
 *   • PURITY / DETERMINISM — `transform(src, seed) === transform(src, seed)` byte-identical.
 *   • NON-TRIVIALITY       — when the target pattern is present in `src`, `transform !== src`.
 *   • SYNTACTIC VALIDITY   — output parses under @babel/parser (valid JavaScript).
 *   • SEMANTIC PRESERVATION MARKER — output references the sibling process.env spelling.
 *
 * All fixture sources are defang-guard-clean: no real endpoints, no credentials
 * assigned, and the env-var reads never leave the fixture (the transforms don't
 * execute — they parse and rewrite).
 */

import { describe, it, expect } from 'vitest';
import * as parser from '@babel/parser';
import {
  envToProcessEnv,
  envToDestructure,
} from '../../src/completeness-vectors/secret-read-widening.js';
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
    transform: envToProcessEnv,
    sourceWithPattern: 'const t = process.env.NPM_TOKEN;',
    siblingMarker: '["NPM_TOKEN"]',
    originalMarker: 'process.env.NPM_TOKEN',
  },
  {
    transform: envToDestructure,
    sourceWithPattern: 'const t = process.env.GITHUB_TOKEN;',
    siblingMarker: 'GITHUB_TOKEN',
    originalMarker: 'process.env.GITHUB_TOKEN',
  },
];

describe('completeness-vectors — secret-read-widening', () => {
  describe.each(CASES)(
    'transform: $transform.id',
    ({ transform, sourceWithPattern, siblingMarker, originalMarker }) => {
      it('declares the sink-family-widening family and secret-read targetClass', () => {
        expect(transform.family).toBe('sink-family-widening');
        expect(transform.targetClass).toBe('secret-read');
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

      it('output contains the sibling spelling marker (semantic-preservation check)', () => {
        for (const seed of SEEDS) {
          const out = transform.transform(sourceWithPattern, seed);
          expect(
            out,
            `seed=${seed} output missing sibling marker "${siblingMarker}":\n${out}`,
          ).toContain(siblingMarker);
        }
      });

      it('is a no-op on source that does NOT contain process.env access', () => {
        const benign = 'const x = 1;\nconsole.log(x);\n';
        for (const seed of SEEDS) {
          const out = transform.transform(benign, seed);
          expect(out).toBe(benign);
        }
      });
    },
  );

  // ------- transform-specific structural assertions --------------------------
  describe('envToProcessEnv structural signature', () => {
    it('replaces the dot-form NPM_TOKEN with the computed form', () => {
      const src = 'const t = process.env.NPM_TOKEN;';
      const out = envToProcessEnv.transform(src, 0);
      expect(out).toContain('process.env[');
      expect(out).toContain('"NPM_TOKEN"');
      // Dot-form access to the same key should no longer appear.
      expect(out).not.toMatch(/process\.env\.NPM_TOKEN(?![A-Za-z0-9_$])/);
    });

    it('rewrites multiple env accesses in the same source', () => {
      const src = 'const a = process.env.NPM_TOKEN; const b = process.env.GITHUB_TOKEN;';
      const out = envToProcessEnv.transform(src, 0);
      expect(out).toContain('"NPM_TOKEN"');
      expect(out).toContain('"GITHUB_TOKEN"');
    });

    it('is a no-op when process.env is not present', () => {
      const src = 'const config = require("./config.invalid"); const t = config.token;';
      const out = envToProcessEnv.transform(src, 0);
      expect(out).toBe(src);
    });
  });

  describe('envToDestructure structural signature', () => {
    it('produces an ObjectPattern destructure of process.env', () => {
      const src = 'const t = process.env.GITHUB_TOKEN;';
      const out = envToDestructure.transform(src, 0);
      expect(out).toContain('GITHUB_TOKEN');
      expect(out).toContain('process.env');
      // ObjectPattern markers: `{ NAME }` binding.
      expect(out).toMatch(/\{\s*GITHUB_TOKEN\s*\}/);
    });

    it('rewrites the computed-form spelling as well', () => {
      const src = 'const t = process.env["AWS_SECRET_ACCESS_KEY"];';
      const out = envToDestructure.transform(src, 0);
      expect(out).toContain('AWS_SECRET_ACCESS_KEY');
      expect(out).toMatch(/\{\s*AWS_SECRET_ACCESS_KEY\s*\}/);
    });

    it('leaves dynamic env keys alone (not a valid identifier binding)', () => {
      // A dynamic key like `process.env[getKey()]` can't be turned into a
      // destructure without evaluating the key — bail out.
      const src = 'const t = process.env[getKey()];';
      const out = envToDestructure.transform(src, 0);
      expect(out).toBe(src);
    });
  });
});
