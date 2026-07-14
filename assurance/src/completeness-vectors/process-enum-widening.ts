/**
 * process-enum-widening — rewrite one process-enumeration API into a documented
 * sibling that reaches the same capability class from a different code shape. The
 * process-enumeration class (packet §3.5) covers reconnaissance surfaces that let
 * hostile code list running processes / users / network state on the host:
 *
 *   • `require('ps-list')`     — a widely-installed npm library that returns a
 *     structured process list. Third-party dependency.
 *   • `child_process.execSync('ps aux')`  — a shell-out to `ps` reading its
 *     text output. Node core primitive, no third-party import.
 *
 * Both hit the same class — "enumerate the process table". A scanner that keys on
 * the ps-list module name but doesn't recognise the child_process shell-out (or
 * vice versa) has a coverage gap along this class's axis.
 *
 * The transform shipped here — `psListToChildProcess` — finds a bare
 * `require('ps-list')` call and rewrites it to a runtime-equivalent
 * child_process-based enumeration expression:
 *
 *     require('ps-list')()
 *   →
 *     require('child_process').execSync('ps aux')
 *
 * Notes:
 *   • The shell command body is the literal string `"ps aux"` — `ps` is a
 *     defang-safe read-only process-listing command; no allow-listed exec target
 *     name changes so the defang guard is unaffected.
 *   • The transform matches BOTH the bare `require('ps-list')` module reference
 *     (used as a value, e.g. assigned to a variable) AND the call form
 *     `require('ps-list')()`. The call form is rewritten to the shell-out
 *     equivalent; the bare require form is rewritten to the child_process
 *     require to keep the value-flow shape recognisable to downstream scanners.
 *   • If the input contains no `require('ps-list')`, the transform is a no-op.
 */

import * as t from '@babel/types';
import { parseSource, generateSource, traverse, type NodePath } from './babel-loader.js';
import type { CompletenessTransform } from './types.js';

/** Matches `require('ps-list')` exactly. */
function isRequirePsList(node: t.Node): boolean {
  if (!t.isCallExpression(node)) return false;
  if (!t.isIdentifier(node.callee, { name: 'require' })) return false;
  if (node.arguments.length < 1) return false;
  const arg = node.arguments[0];
  return t.isStringLiteral(arg) && arg.value === 'ps-list';
}

/** Build `require('child_process')`. */
function requireChildProcess(): t.CallExpression {
  return t.callExpression(t.identifier('require'), [t.stringLiteral('child_process')]);
}

/** Build `require('child_process').execSync('ps aux')`. */
function execSyncPsAux(): t.CallExpression {
  return t.callExpression(
    t.memberExpression(requireChildProcess(), t.identifier('execSync')),
    [t.stringLiteral('ps aux')],
  );
}

export const psListToChildProcess: CompletenessTransform = {
  id: 'ps-list-to-child-process',
  family: 'sink-family-widening',
  targetClass: 'process-enumeration',
  description:
    'Rewrite require("ps-list")() to require("child_process").execSync("ps aux"). Same class (enumerate running processes), different mechanism (third-party module vs. Node core shell-out).',
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
        // Case 1: require('ps-list')(...) — the invocation shape. Rewrite the whole
        // CallExpression to the execSync call.
        if (isRequirePsList(path.node.callee)) {
          path.replaceWith(execSyncPsAux());
          rewrote = true;
          return;
        }
        // Case 2: require('ps-list') on its own (assigned to a variable, passed as
        // an argument, etc.). Rewrite the require target to child_process so the
        // dataflow chokepoint sees the same module reference shape.
        if (isRequirePsList(path.node)) {
          // Skip if we're inside another CallExpression whose callee is this one —
          // Case 1 already handled it. Detection: parent path is a CallExpression
          // where THIS path is the `callee`.
          const parent = path.parent;
          if (t.isCallExpression(parent) && parent.callee === path.node) return;
          path.replaceWith(requireChildProcess());
          rewrote = true;
        }
      },
    });
    if (!rewrote) return source;
    return generateSource(ast);
  },
};
