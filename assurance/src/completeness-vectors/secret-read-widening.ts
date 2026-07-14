/**
 * secret-read-widening — widen a `process.env.FOO` access to a documented sibling
 * shape within the same secret-read class. STARTUP's capability map defines the
 * class `secret-read` with sinks: `process-env-token`, `process-env-enumerate`,
 * `process-env-destructure`, `process-env-reflect`, `secret-file-read`. A scanner
 * that catches direct member access (`process.env.FOO`) but misses computed-form
 * or destructure spellings has a completeness gap.
 *
 * Two transforms shipped here:
 *
 *   • envToProcessEnv — rewrites `process.env.FOO` (member access) to
 *       `process.env['FOO']` (computed member access). Same class, different
 *       spelling. Some scanners key on Identifier property names and miss
 *       computed-property forms.
 *
 *   • envToDestructure — rewrites `process.env.FOO` (member access) to
 *       `(() => { const { FOO } = process.env; return FOO; })()`. Same class
 *       (`process-env-destructure` sink); different binding form. The IIFE wrap
 *       preserves the expression semantics (the whole thing still yields the
 *       env-var value) while turning the read into an ObjectPattern destructure.
 *
 * Both transforms are AST-based and target ONLY property accesses whose object
 * is exactly `process.env` (an Identifier `process` with member `env`). The
 * property must be an Identifier or a StringLiteral computed key — anything
 * dynamic (`process.env[getKey()]`) is left alone since the class is already
 * caught by `process-env-enumerate`.
 */

import * as t from '@babel/types';
import { parseSource, generateSource, traverse, type NodePath } from './babel-loader.js';
import type { CompletenessTransform } from './types.js';

/**
 * True iff `node` is the exact expression `process.env`. Dot-form only — a
 * `process["env"]` computed access is already the "widened" form we might
 * rewrite TO, so treating it as a source for further widening would be a no-op.
 */
function isProcessEnv(node: t.Node): boolean {
  if (!t.isMemberExpression(node)) return false;
  if (node.computed) return false;
  if (!t.isIdentifier(node.object, { name: 'process' })) return false;
  if (!t.isIdentifier(node.property, { name: 'env' })) return false;
  return true;
}

/**
 * Extract the key name from a `process.env.FOO` or `process.env["FOO"]`
 * property access. Returns null if the property isn't statically-known
 * (a dynamic key like `[getName()]`) — the transform bails on those since
 * they're outside the class this widening covers.
 */
function staticEnvKey(mem: t.MemberExpression): string | null {
  if (mem.computed) {
    if (t.isStringLiteral(mem.property)) return mem.property.value;
    return null;
  }
  if (t.isIdentifier(mem.property)) return mem.property.name;
  return null;
}

export const envToProcessEnv: CompletenessTransform = {
  id: 'env-to-process-env',
  family: 'sink-family-widening',
  targetClass: 'secret-read',
  description:
    'Rewrite process.env.FOO to process.env["FOO"] (computed-member form). Same class, sibling spelling.',
  transform(source, _seed): string {
    let ast: ReturnType<typeof parseSource>;
    try {
      ast = parseSource(source);
    } catch {
      return source;
    }
    let rewrote = false;
    traverse(ast, {
      MemberExpression(path: NodePath<t.MemberExpression>) {
        // Match `process.env.FOO`: object is `process.env` and property is a
        // static Identifier (not already computed, not dynamic).
        if (path.node.computed) return;
        if (!isProcessEnv(path.node.object)) return;
        if (!t.isIdentifier(path.node.property)) return;
        const keyName = path.node.property.name;
        // Rewrite in place: property becomes a StringLiteral and computed flips true.
        path.node.property = t.stringLiteral(keyName);
        path.node.computed = true;
        rewrote = true;
      },
    });
    if (!rewrote) return source;
    return generateSource(ast);
  },
};

export const envToDestructure: CompletenessTransform = {
  id: 'env-to-destructure',
  family: 'sink-family-widening',
  targetClass: 'secret-read',
  description:
    'Rewrite process.env.FOO to an IIFE that destructures {FOO} from process.env and returns FOO. Same class, sibling spelling (ObjectPattern).',
  transform(source, _seed): string {
    let ast: ReturnType<typeof parseSource>;
    try {
      ast = parseSource(source);
    } catch {
      return source;
    }
    let rewrote = false;
    traverse(ast, {
      MemberExpression(path: NodePath<t.MemberExpression>) {
        // Match any `process.env.FOO` or `process.env["FOO"]` static access.
        if (!isProcessEnv(path.node.object)) return;
        const keyName = staticEnvKey(path.node);
        if (!keyName) return;
        // Env-var key names in real code are ALL-CAPS identifiers. Reject anything
        // that isn't a plain identifier — a name like `my-key` wouldn't parse as
        // `const { my-key } = ...`. Conservative: only rewrite valid Identifier
        // spellings (typical for env vars: NPM_TOKEN, GITHUB_TOKEN, etc.).
        if (!/^[A-Za-z_$][A-Za-z0-9_$]*$/.test(keyName)) return;
        // Build IIFE: (() => { const { FOO } = process.env; return FOO; })()
        const objPattern = t.objectPattern([
          t.objectProperty(t.identifier(keyName), t.identifier(keyName), false, true),
        ]);
        const varDecl = t.variableDeclaration('const', [
          t.variableDeclarator(
            objPattern,
            t.memberExpression(t.identifier('process'), t.identifier('env')),
          ),
        ]);
        const returnStmt = t.returnStatement(t.identifier(keyName));
        const arrow = t.arrowFunctionExpression(
          [],
          t.blockStatement([varDecl, returnStmt]),
        );
        const iife = t.callExpression(arrow, []);
        path.replaceWith(iife);
        rewrote = true;
      },
    });
    if (!rewrote) return source;
    return generateSource(ast);
  },
};
