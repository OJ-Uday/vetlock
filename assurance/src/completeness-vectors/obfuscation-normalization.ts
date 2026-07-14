/**
 * obfuscation-normalization — rewrite an obfuscation-decode call into a
 * documented equivalent that a scanner keying on one shape may miss. STARTUP's
 * capability map defines the `obfuscation-decode` class with the
 * `char-arithmetic-decoder` sink (String.fromCharCode + charCodeAt co-occurrence)
 * and the `entropy-jump` sink (post-facto entropy shift). A scanner that catches
 * `Buffer.from(x, 'base64').toString()` but not `atob(x)`, or catches
 * `Buffer.from(x, 'hex')` but not an inline hex parser, is class-incomplete.
 *
 * Two transforms shipped here:
 *
 *   • base64DecodeToAtob — rewrites `Buffer.from(x, 'base64').toString(...)` to
 *       `atob(x)`. Both are documented ways to decode base64 to bytes/string;
 *       `atob` is the browser-standard name and works in Node ≥ 16. Same class,
 *       sibling API.
 *
 *   • hexDecodeToParseInt — rewrites `Buffer.from(x, 'hex')` to an inline
 *       hex-string → Uint8Array parser that walks the string 2 chars at a time
 *       and calls `parseInt(pair, 16)` on each pair. Semantically identical:
 *       the output is a byte array with the same values. A scanner keying on
 *       `Buffer.from(_, 'hex')` alone misses the inline parser.
 *
 * Both transforms are AST-based and target ONLY the exact CallExpression shapes
 * described (predicate matches on callee + argument shape). Non-matching calls
 * are left alone.
 */

import * as t from '@babel/types';
import { parseSource, generateSource, traverse, type NodePath } from './babel-loader.js';
import type { CompletenessTransform } from './types.js';

/**
 * Match `Buffer.from(x, 'ENCODING')`. Returns the inner `x` expression and the
 * encoding StringLiteral value if the shape matches, else null. `Buffer.from`
 * with 1 arg, with a non-string encoding, or with a computed member is a mismatch.
 */
function matchBufferFrom(node: t.CallExpression): { input: t.Expression; encoding: string } | null {
  const callee = node.callee;
  if (!t.isMemberExpression(callee) || callee.computed) return null;
  if (!t.isIdentifier(callee.object, { name: 'Buffer' })) return null;
  if (!t.isIdentifier(callee.property, { name: 'from' })) return null;
  if (node.arguments.length < 2) return null;
  const inputArg = node.arguments[0];
  const encodingArg = node.arguments[1];
  if (!t.isStringLiteral(encodingArg)) return null;
  // Arg[0] must be an Expression, not a Spread. Bail on spread — it changes
  // semantics in ways this transform doesn't preserve.
  if (!t.isExpression(inputArg)) return null;
  return { input: inputArg, encoding: encodingArg.value };
}

export const base64DecodeToAtob: CompletenessTransform = {
  id: 'base64-decode-to-atob',
  family: 'sink-family-widening',
  targetClass: 'obfuscation-decode',
  description:
    "Rewrite Buffer.from(x, 'base64').toString() to atob(x). Same class, sibling decoder API.",
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
        // Match the OUTER `.toString(...)` call whose callee is a MemberExpression
        // over a `Buffer.from(x, 'base64')` call. Two-level shape.
        const callee = path.node.callee;
        if (!t.isMemberExpression(callee) || callee.computed) return;
        if (!t.isIdentifier(callee.property, { name: 'toString' })) return;
        const inner = callee.object;
        if (!t.isCallExpression(inner)) return;
        const bufferMatch = matchBufferFrom(inner);
        if (!bufferMatch) return;
        if (bufferMatch.encoding !== 'base64') return;
        // Replace the whole `.toString()` call with `atob(x)`.
        path.replaceWith(t.callExpression(t.identifier('atob'), [bufferMatch.input]));
        rewrote = true;
      },
    });
    if (!rewrote) return source;
    return generateSource(ast);
  },
};

/**
 * Build the inline hex-parser expression body:
 *   ((s) => new Uint8Array(s.match(/.{1,2}/g).map(b => parseInt(b, 16))))(x)
 *
 * The IIFE arrow captures the hex string as its parameter so the call site's
 * argument (which might be an expensive expression) is evaluated exactly once,
 * matching `Buffer.from(x, 'hex')`'s single-evaluation semantics.
 *
 * The regex `/.{1,2}/g` chunks the hex string into pairs; `parseInt(pair, 16)`
 * converts each to a byte (0–255); `new Uint8Array(...)` gives us the same
 * concrete byte array `Buffer.from(x, 'hex')` produces (Buffer extends
 * Uint8Array in Node, so any consumer that treats it as bytes gets the same
 * values).
 */
function buildHexParserIIFE(hexInput: t.Expression): t.CallExpression {
  const sParam = t.identifier('s');
  const bParam = t.identifier('b');
  // s.match(/.{1,2}/g)
  const matchCall = t.callExpression(
    t.memberExpression(sParam, t.identifier('match')),
    [t.regExpLiteral('.{1,2}', 'g')],
  );
  // .map(b => parseInt(b, 16))
  const mapCall = t.callExpression(
    t.memberExpression(matchCall, t.identifier('map')),
    [
      t.arrowFunctionExpression(
        [bParam],
        t.callExpression(t.identifier('parseInt'), [bParam, t.numericLiteral(16)]),
      ),
    ],
  );
  // new Uint8Array(mapCall)
  const arrayCtor = t.newExpression(t.identifier('Uint8Array'), [mapCall]);
  // (s) => arrayCtor
  const arrow = t.arrowFunctionExpression([sParam], arrayCtor);
  // (arrow)(hexInput)
  return t.callExpression(arrow, [hexInput]);
}

export const hexDecodeToParseInt: CompletenessTransform = {
  id: 'hex-decode-to-parseInt',
  family: 'sink-family-widening',
  targetClass: 'obfuscation-decode',
  description:
    "Rewrite Buffer.from(x, 'hex') to an inline hex-pair → parseInt(_, 16) → Uint8Array parser. Same class, hand-rolled sibling.",
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
        const bufferMatch = matchBufferFrom(path.node);
        if (!bufferMatch) return;
        if (bufferMatch.encoding !== 'hex') return;
        path.replaceWith(buildHexParserIIFE(bufferMatch.input));
        rewrote = true;
      },
    });
    if (!rewrote) return source;
    return generateSource(ast);
  },
};
