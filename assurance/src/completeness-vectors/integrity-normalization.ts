/**
 * integrity-normalization — rewrite a standard-library integrity-hash call into a
 * hex-output equivalent that scans to the same class from a different call shape.
 * The integrity class (STARTUP extension; packet §3.5 canonical §3.5.7 covers the
 * hash-mismatch axis) covers code that COMPUTES a cryptographic hash — anything a
 * malicious package could use to validate its own payload after decoding, sign
 * exfiltrated data, or self-modify while preserving a signature.
 *
 * Two equivalent shapes exist for computing a SHA-256 hash in Node's `crypto`:
 *
 *   • bare digest:    crypto.createHash('sha256').update(x).digest()
 *     — returns a Buffer.
 *   • hex-encoded:    crypto.createHash('sha256').update(x).digest('hex')
 *     — returns a hex string.
 *
 * A scanner that keys on the bare `.digest()` shape (no argument) may miss the
 * `.digest('hex')` variant, or vice versa. Both compute the same hash; the class
 * is the same; only the OUTPUT ENCODING differs. A completeness gap here is a
 * gap in the integrity class's coverage floor.
 *
 * The transform shipped here — `sha256Reimplement` — finds the bare
 * `crypto.createHash('sha256').update(x).digest()` chain and rewrites the final
 * `.digest()` call to add a hex-encoding argument: `.digest('hex')`. The chain
 * SHAPE is preserved; only the terminal call's argument changes.
 *
 * Notes:
 *   • The transform matches only the sha256 algorithm — other algorithms (sha1,
 *     sha512, md5) exist but the completeness-vector scope is one transform per
 *     class per wave, and sha256 is the packet's example.
 *   • If the chain already has `.digest('hex')` (or any argument to digest), the
 *     transform is a no-op. This keeps re-application idempotent.
 *   • If no matching chain is present, the transform is a no-op.
 */

import * as t from '@babel/types';
import { parseSource, generateSource, traverse, type NodePath } from './babel-loader.js';
import type { CompletenessTransform } from './types.js';

/** Does this CallExpression have a MemberExpression callee whose property is `name`?
 *  Returns the inner (base) expression if yes; null otherwise. */
function callWithProperty(node: t.CallExpression, name: string): t.Expression | null {
  const callee = node.callee;
  if (!t.isMemberExpression(callee)) return null;
  if (callee.computed) return null;
  if (!t.isIdentifier(callee.property, { name })) return null;
  const obj = callee.object;
  if (!t.isExpression(obj)) return null;
  return obj;
}

/** Matches a bare `crypto.createHash('sha256')` (or with the `node:crypto`
 *  bare-Identifier idiom — but the base check is on the ID name `crypto`). */
function isCreateHashSha256(node: t.Node): boolean {
  if (!t.isCallExpression(node)) return false;
  const callee = node.callee;
  if (!t.isMemberExpression(callee)) return false;
  if (!t.isIdentifier(callee.object, { name: 'crypto' })) return false;
  if (!t.isIdentifier(callee.property, { name: 'createHash' })) return false;
  if (node.arguments.length < 1) return false;
  const arg = node.arguments[0];
  return t.isStringLiteral(arg) && arg.value.toLowerCase() === 'sha256';
}

export const sha256Reimplement: CompletenessTransform = {
  id: 'sha256-reimplement',
  family: 'sink-family-widening',
  targetClass: 'integrity',
  description:
    'Rewrite crypto.createHash("sha256").update(x).digest() to add a hex-encoding argument: .digest("hex"). Same hash primitive, different output-encoding shape.',
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
        // Target: <chain>.digest()  with zero arguments.
        if (path.node.arguments.length !== 0) return;
        const digestBase = callWithProperty(path.node, 'digest');
        if (!digestBase) return;
        // digestBase must be `<chain>.update(x)` — a CallExpression whose callee
        // is a MemberExpression with property `update`.
        if (!t.isCallExpression(digestBase)) return;
        const updateBase = callWithProperty(digestBase, 'update');
        if (!updateBase) return;
        // updateBase must be `crypto.createHash('sha256')`.
        if (!isCreateHashSha256(updateBase)) return;
        // Rewrite: append `'hex'` argument to the digest call.
        path.node.arguments.push(t.stringLiteral('hex'));
        rewrote = true;
      },
    });
    if (!rewrote) return source;
    return generateSource(ast);
  },
};
