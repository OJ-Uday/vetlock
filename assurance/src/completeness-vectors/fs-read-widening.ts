/**
 * fs-read-widening — widen an `fs.readFile(path, ...)` call to the sync sibling
 * `fs.readFileSync(path)`, targeting sensitive hot-paths. The `fs-read` class
 * (STARTUP §3.5 sink: `fs-read-hotpath`) covers the family of file-system reads
 * against credential and secret paths. Detection in the engine keys on
 * `fsReadTargets` — a Set of path strings extracted from `fs.readFile*` calls —
 * and the fs-read detector flags any path matching HOT_PATH_PATTERNS.
 *
 * The transform shipped here — `readFileToReadFileSync` — is the fs-read
 * analog of `writeFileToWriteFileSync`: rewrite the async form to its sync
 * sibling. `fs.readFile(path, cb)` → `fs.readFileSync(path)`. The callback (if
 * any) is dropped — `readFileSync` returns the buffer directly. Semantically
 * identical from the fs-read class's perspective: the path is read; the
 * subsequent handling is orthogonal to the capability class.
 *
 * If the scanner keys on `readFile` but not `readFileSync` (unlikely for the
 * current engine, which enumerates both — this transform is the completeness
 * probe that PROVES it does), the class is incomplete. The transform's engine
 * finding surfaces as `env/secret-read` in `adaptFileCapabilities` (fsReadTargets
 * are bucketed there); the oracle's CLASS_ALIASES entry maps `fs-read` ↔
 * `env/secret-read` so the survives-check succeeds on either name.
 */

import * as t from '@babel/types';
import { parseSource, generateSource, traverse, type NodePath } from './babel-loader.js';
import type { CompletenessTransform } from './types.js';

/** fs module aliases — mirrors fs-write-widening.ts's list. */
const FS_MODULE_NAMES: readonly string[] = [
  'fs',
  'node:fs',
  'graceful-fs',
  'fs/promises',
];

function isFsRef(node: t.Node): boolean {
  if (t.isCallExpression(node)) {
    if (
      t.isIdentifier(node.callee, { name: 'require' }) &&
      node.arguments.length >= 1 &&
      t.isStringLiteral(node.arguments[0])
    ) {
      return FS_MODULE_NAMES.includes(node.arguments[0].value);
    }
  }
  if (t.isIdentifier(node)) {
    return node.name === 'fs' || node.name === 'graceful' || node.name === 'fsp';
  }
  return false;
}

/** Return the MemberExpression callee IF this CallExpression is `fs.readFile(...)`. */
function matchReadFileCall(node: t.CallExpression): t.MemberExpression | null {
  const callee = node.callee;
  if (!t.isMemberExpression(callee)) return null;
  if (!isFsRef(callee.object)) return null;
  const prop = callee.property;
  if (callee.computed) {
    if (t.isStringLiteral(prop) && prop.value === 'readFile') return callee;
    return null;
  }
  if (t.isIdentifier(prop) && prop.name === 'readFile') return callee;
  return null;
}

/** Drop a trailing callback arg. Mirror of fs-write-widening.ts. */
function stripTrailingCallback(args: readonly t.Node[]): t.Expression[] {
  if (args.length === 0) return [];
  const last = args[args.length - 1];
  const isCallable =
    t.isFunctionExpression(last) ||
    t.isArrowFunctionExpression(last) ||
    t.isIdentifier(last);
  const kept = isCallable ? args.slice(0, -1) : args;
  return kept.map((a) => a as t.Expression);
}

export const readFileToReadFileSync: CompletenessTransform = {
  id: 'readFile-to-readFileSync',
  family: 'sink-family-widening',
  targetClass: 'fs-read',
  description:
    'Rewrite fs.readFile(path, cb) to fs.readFileSync(path). Same class, sync sibling — fs-read capability preserved regardless of async/sync spelling.',
  transform(source, _seed): string {
    let ast: ReturnType<typeof parseSource>;
    try {
      ast = parseSource(source);
    } catch {
      return source;
    }
    let rewrote = false;
    traverse(ast, {
      CallExpression(path: NodePath<t.CallExpression>) {
        const callee = matchReadFileCall(path.node);
        if (!callee) return;
        if (callee.computed) {
          callee.property = t.stringLiteral('readFileSync');
        } else {
          callee.property = t.identifier('readFileSync');
        }
        path.node.arguments = stripTrailingCallback(path.node.arguments) as t.Expression[];
        rewrote = true;
      },
    });
    if (!rewrote) return source;
    return generateSource(ast);
  },
};
