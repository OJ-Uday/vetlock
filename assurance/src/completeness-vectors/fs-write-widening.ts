/**
 * fs-write-widening — widen an `fs.writeFile(...)` call to a documented sibling
 * write-path within the same capability class. If the scanner keys on
 * `fs.writeFile` but not on `fs.writeFileSync` or `fs.createWriteStream(...)`, the
 * class is incomplete: a malicious package can hit any of these and stash bytes
 * on disk without tripping the detector.
 *
 * Two transforms shipped here, mirroring `sink-family-widening.ts`:
 *
 *   • writeFileToWriteFileSync — rewrites the async form to its sync sibling.
 *       `fs.writeFile(path, data, cb)` → `fs.writeFileSync(path, data)`
 *     The callback (if any) is dropped — writeFileSync is synchronous and returns
 *     `undefined`. Semantically identical from the fs-write class's perspective:
 *     bytes at `path` end up equal to `data`.
 *
 *   • writeFileToCreateWriteStream — rewrites to a stream-based write.
 *       `fs.writeFile(path, data, cb?)` → `fs.createWriteStream(path).write(data)`
 *     Same fs-write class chokepoint (`capabilities.fsWriteTargets`), different
 *     API. A scanner that names writeFile/writeFileSync in its alias list but
 *     omits createWriteStream misses this variant.
 *
 * Both rewrites preserve argument order (path, data) and drop only the callback,
 * which never carries semantic content the scanner would key on for this class.
 * Module reference (`fs`, `node:fs`, `graceful-fs`, `fs/promises`) is preserved.
 */

import * as t from '@babel/types';
import { parseSource, generateSource, traverse, type NodePath } from './babel-loader.js';
import type { CompletenessTransform } from './types.js';

/** Module names counted as `fs`. Aligned with capability-map fs-write-hotpath aliases. */
const FS_MODULE_NAMES: readonly string[] = [
  'fs',
  'node:fs',
  'graceful-fs',
  'fs/promises',
];

/**
 * Does the given expression reference the fs module?  Handles two idioms:
 *   - `require("fs")`, `require("node:fs")`
 *   - a bare Identifier that plausibly aliases fs (e.g. `fs`, `graceful`, `fsp`).
 *
 * Mirrors `isModuleRef` in sink-family-widening.ts — kept private so the two
 * files can drift independently if fs aliases grow (they will).
 */
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
    // Loose alias match — the test fixtures use `fs` as the bare identifier so
    // this is enough. Broader alias resolution belongs in the scanner, not here.
    return node.name === 'fs' || node.name === 'graceful' || node.name === 'fsp';
  }
  return false;
}

/**
 * Return the `writeFile` call node at this path IF the callee is `fs.writeFile`
 * (or its computed-form spelling), else `null`. The transform runs against every
 * CallExpression, so this predicate is the single decision-point.
 */
function matchWriteFileCall(node: t.CallExpression): t.MemberExpression | null {
  const callee = node.callee;
  if (!t.isMemberExpression(callee)) return null;
  if (!isFsRef(callee.object)) return null;
  const prop = callee.property;
  if (callee.computed) {
    if (t.isStringLiteral(prop) && prop.value === 'writeFile') return callee;
    return null;
  }
  if (t.isIdentifier(prop) && prop.name === 'writeFile') return callee;
  return null;
}

/**
 * Drop a trailing callback argument if the last arg is a FunctionExpression /
 * ArrowFunctionExpression / plain Identifier that looks like a callback. The
 * heuristic is conservative — only strip trailing callables. Anything else
 * (options object, encoding string, absent arg) is preserved.
 */
function stripTrailingCallback(args: readonly t.Node[]): t.Expression[] {
  if (args.length === 0) return [];
  const last = args[args.length - 1];
  const isCallable =
    t.isFunctionExpression(last) ||
    t.isArrowFunctionExpression(last) ||
    t.isIdentifier(last); // `cb`, `next`, etc.
  const kept = isCallable ? args.slice(0, -1) : args;
  return kept.map((a) => a as t.Expression);
}

export const writeFileToWriteFileSync: CompletenessTransform = {
  id: 'writeFile-to-writeFileSync',
  family: 'sink-family-widening',
  targetClass: 'fs-write',
  description:
    'Rewrite fs.writeFile(path, data, cb) to fs.writeFileSync(path, data). Same class, sibling sink.',
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
        const callee = matchWriteFileCall(path.node);
        if (!callee) return;
        // Rewrite the member name in place. Both dot- and computed-form covered.
        if (callee.computed) {
          callee.property = t.stringLiteral('writeFileSync');
        } else {
          callee.property = t.identifier('writeFileSync');
        }
        path.node.arguments = stripTrailingCallback(path.node.arguments) as t.Expression[];
        rewrote = true;
      },
    });
    if (!rewrote) return source;
    return generateSource(ast);
  },
};

export const writeFileToCreateWriteStream: CompletenessTransform = {
  id: 'writeFile-to-createWriteStream',
  family: 'sink-family-widening',
  targetClass: 'fs-write',
  description:
    'Rewrite fs.writeFile(path, data, cb) to fs.createWriteStream(path).write(data). Same class, stream-based sibling.',
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
        const callee = matchWriteFileCall(path.node);
        if (!callee) return;
        // Extract path and data args, drop callback.
        const args = stripTrailingCallback(path.node.arguments) as t.Expression[];
        if (args.length < 2) return; // need at least (path, data)
        const pathArg = args[0];
        const dataArg = args[1];
        // Build fs.createWriteStream(path).write(data). The fs base (callee.object)
        // is preserved by reference so any local alias (`fs`, `graceful`) is kept.
        const createStreamCall = t.callExpression(
          t.memberExpression(callee.object as t.Expression, t.identifier('createWriteStream')),
          [pathArg],
        );
        const writeCall = t.callExpression(
          t.memberExpression(createStreamCall, t.identifier('write')),
          [dataArg],
        );
        path.replaceWith(writeCall);
        rewrote = true;
      },
    });
    if (!rewrote) return source;
    return generateSource(ast);
  },
};
