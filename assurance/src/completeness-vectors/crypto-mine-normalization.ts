/**
 * crypto-mine-normalization — rewrite one legitimate hash-API call into its
 * cross-platform sibling. Two hash APIs exist in the JavaScript ecosystem:
 *
 *   • Web Crypto — `crypto.subtle.digest(algo, data)` (returns a Promise<ArrayBuffer>).
 *     Available in browsers and in Node 15+.
 *   • Node crypto — `crypto.createHash(algo).update(data).digest()` (synchronous).
 *     Node-only, but reachable from any package that requires `crypto`.
 *
 * A miner (or any obfuscated-decode / integrity-computation payload — the packet
 * §3.5 crypto-mine class covers the "computes a hash / uses cryptographic
 * primitives" surface at large) can hit EITHER API. A scanner that keys on
 * `crypto.createHash` but doesn't recognise `crypto.subtle.digest` — or vice
 * versa — has a coverage gap along the exact axis this class describes.
 *
 * The transform shipped here — `webcryptoToNode` — walks the source, finds any
 * `crypto.subtle.digest(algo, data)` CallExpression, and replaces it with the
 * equivalent chained-call form `crypto.createHash(algo).update(data).digest()`.
 * The argument order is preserved; only the API shape changes.
 *
 * Notes:
 *   • The Web Crypto API's algo strings ("SHA-256") differ in canonical case from
 *     Node's ("sha256"). We forward the original string verbatim — either the
 *     scanner constant-folds capably or it doesn't, and a case-preserving rewrite
 *     is a stricter test of that fold path than a case-normalising one.
 *   • The runtime SEMANTICS are close-but-not-identical (Promise vs. sync return
 *     value). That's fine — the completeness axis is CAPABILITY-CLASS membership,
 *     not full runtime equivalence. Both APIs are "hash" primitives; a scanner
 *     that classifies one but not the other has a coverage gap.
 *   • If no `crypto.subtle.digest` call is present, the transform is a no-op.
 */

import * as t from '@babel/types';
import { parseSource, generateSource, traverse, type NodePath } from './babel-loader.js';
import type { CompletenessTransform } from './types.js';

/** Is this MemberExpression the pattern `crypto.subtle.digest`? */
function isSubtleDigestCallee(callee: t.Node): boolean {
  // Matches `<crypto>.subtle.digest` where <crypto> is any Identifier (typically `crypto`
  // or `globalThis.crypto`, but we accept any bare Identifier as the base since callers
  // may alias it). The KEY match is the two-level property chain: `.subtle.digest`.
  if (!t.isMemberExpression(callee)) return false;
  const inner = callee.object;
  const outerProp = callee.property;
  if (!t.isMemberExpression(inner)) return false;
  if (!t.isIdentifier(outerProp, { name: 'digest' })) return false;
  const innerProp = inner.property;
  if (!t.isIdentifier(innerProp, { name: 'subtle' })) return false;
  // Base must be an Identifier (bare name). We don't recurse deeper — that would
  // widen the transform beyond the completeness-vector's scoped intent.
  if (!t.isIdentifier(inner.object)) return false;
  return true;
}

export const webcryptoToNode: CompletenessTransform = {
  id: 'webcrypto-to-node',
  family: 'sink-family-widening',
  targetClass: 'crypto-mine',
  description:
    'Rewrite crypto.subtle.digest(algo, data) to the Node-crypto sibling form crypto.createHash(algo).update(data).digest(). Same capability class (hash), different API surface.',
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
        const callee = path.node.callee;
        if (!isSubtleDigestCallee(callee)) return;
        // Guaranteed by the check above.
        const memberCallee = callee as t.MemberExpression;
        const cryptoBase = (memberCallee.object as t.MemberExpression).object as t.Identifier;
        const args = path.node.arguments;
        // Expected shape: subtle.digest(algo, data). If the call is 0- or 1-arg
        // (spec-invalid), still rewrite what we have — a scanner in the wild would
        // see either shape and needs to catch both.
        const algoArg =
          args.length >= 1 && !t.isSpreadElement(args[0])
            ? (args[0] as t.Expression)
            : t.stringLiteral('sha256');
        const dataArg =
          args.length >= 2 && !t.isSpreadElement(args[1])
            ? (args[1] as t.Expression)
            : t.identifier('undefined');
        // Build: <cryptoBase>.createHash(algo).update(data).digest()
        const createHashCall = t.callExpression(
          t.memberExpression(t.identifier(cryptoBase.name), t.identifier('createHash')),
          [algoArg],
        );
        const updateCall = t.callExpression(
          t.memberExpression(createHashCall, t.identifier('update')),
          [dataArg],
        );
        const digestCall = t.callExpression(
          t.memberExpression(updateCall, t.identifier('digest')),
          [],
        );
        path.replaceWith(digestCall);
        rewrote = true;
      },
    });
    if (!rewrote) return source;
    return generateSource(ast);
  },
};
