/**
 * Babel loader helpers — resolve `@babel/traverse` and `@babel/generator` in a way
 * that works under both CJS and ESM (Node's NodeNext resolution wraps the default
 * export inconsistently, exactly like `@vetlock/core`'s capabilities.ts does).
 *
 * Callers use these helpers instead of importing the modules directly so every
 * transform lands on the same shape and every parse uses the same tolerant options
 * as the engine's capability extractor.
 */

import * as parser from '@babel/parser';
import * as babelTraverseNs from '@babel/traverse';
import * as babelGeneratorNs from '@babel/generator';
import type { NodePath } from '@babel/traverse';
import type * as t from '@babel/types';

type BabelTraverseCallable = (
  ast: t.Node,
  opts: Record<string, unknown>,
) => void;

type BabelGeneratorCallable = (ast: t.Node) => { code: string };

/** Resolve @babel/traverse's default-export shape at runtime. */
export const traverse: BabelTraverseCallable = (() => {
  const anyNs = babelTraverseNs as unknown as Record<string, unknown>;
  if (typeof anyNs === 'function') return anyNs as unknown as BabelTraverseCallable;
  if (typeof anyNs.default === 'function') return anyNs.default as BabelTraverseCallable;
  const nested = (anyNs.default as Record<string, unknown> | undefined)?.default;
  if (typeof nested === 'function') return nested as BabelTraverseCallable;
  throw new Error('Unable to resolve @babel/traverse callable export');
})();

/** Resolve @babel/generator's default-export shape at runtime. */
export const generate: BabelGeneratorCallable = (() => {
  const anyNs = babelGeneratorNs as unknown as Record<string, unknown>;
  if (typeof anyNs === 'function') return anyNs as unknown as BabelGeneratorCallable;
  if (typeof anyNs.default === 'function') return anyNs.default as BabelGeneratorCallable;
  const nested = (anyNs.default as Record<string, unknown> | undefined)?.default;
  if (typeof nested === 'function') return nested as BabelGeneratorCallable;
  throw new Error('Unable to resolve @babel/generator callable export');
})();

/** Parse under the tolerant options every transform expects. */
export function parseSource(source: string): parser.ParseResult<t.File> {
  return parser.parse(source, {
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
}

/** Serialize an AST back to source. Wraps @babel/generator's shape resolution. */
export function generateSource(ast: t.Node): string {
  return generate(ast).code;
}

/** Re-export a NodePath type alias for transform files. */
export type { NodePath };
