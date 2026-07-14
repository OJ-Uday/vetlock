/**
 * obfuscation-decode-canonical — a completeness-vector transform whose targetClass
 * is the packet §3.5 CANONICAL slash-form `obfuscation/decode`.
 *
 * WHY this file exists separately from `obfuscation-normalization.ts`:
 *
 * The existing Wave 6-X `base64DecodeToAtob` and `hexDecodeToParseInt` transforms
 * target the STARTUP-shape class name `obfuscation-decode` (no slash). STARTUP's
 * CAPABILITY-MAP loader adapter re-keys entries whose `class` field is
 * `obfuscation-decode` under `obfuscation/decode` (see STARTUP_CLASS_ALIAS in
 * assurance/src/capability-map/loader.ts). Consequence: `map.classes` has the
 * SLASH-form key, and the collector's strict set-intersection coverage math
 * (`hits = coveredClasses ∩ Object.keys(map.classes)`) counts a transform only
 * when its `targetClass` string is a byte-identical match against a map key.
 *
 * The oracle's CLASS_ALIASES already treats `obfuscation-decode` and
 * `obfuscation/decode` as siblings when checking finding survival, so the pre-existing
 * transforms are FUNCTIONALLY covering the same capability — but the coverage
 * METRIC doesn't see them as covering `obfuscation/decode` because the string is
 * different.
 *
 * This transform closes that gap along the same axis (base64/atob decode-family
 * widening) but declares the canonical slash-form `targetClass`. It's a distinct
 * transform id so the barrel enumeration is exhaustive and every canonical class
 * is intentionally, explicitly covered.
 *
 * The transform shape mirrors `base64DecodeToAtob`'s inverse: convert `atob(x)`
 * to the Node-idiomatic `Buffer.from(x, 'base64').toString('utf8')` — both are
 * documented base64 decoders, and either form should be caught by an
 * obfuscation-decode-aware detector. If the scanner catches Buffer.from but
 * not atob, it's incomplete on the `obfuscation/decode` class.
 */

import * as t from '@babel/types';
import { parseSource, generateSource, traverse, type NodePath } from './babel-loader.js';
import type { CompletenessTransform } from './types.js';

export const atobToBufferFrom: CompletenessTransform = {
  id: 'atob-to-buffer-from',
  family: 'sink-family-widening',
  targetClass: 'obfuscation/decode',
  description:
    "Rewrite atob(x) to Buffer.from(x, 'base64').toString('utf8'). Same class (base64 decode), sibling API — targets the packet §3.5 canonical `obfuscation/decode` slash-form key that the map's alias adapter emits.",
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
        // Match the exact bare-identifier `atob(x)` call. Skip `foo.atob(x)` (namespaced
        // form) — that would already be an intentional obfuscation shape and outside
        // this transform's scope.
        if (!t.isIdentifier(path.node.callee, { name: 'atob' })) return;
        if (path.node.arguments.length < 1) return;
        const inputArg = path.node.arguments[0];
        if (!t.isExpression(inputArg)) return;
        // Build Buffer.from(x, 'base64').toString('utf8'). The nested call is one
        // MemberExpression on top of another CallExpression — the same shape the
        // matchBufferFrom predicate in obfuscation-normalization.ts recognises.
        const bufferFromCall = t.callExpression(
          t.memberExpression(t.identifier('Buffer'), t.identifier('from')),
          [inputArg, t.stringLiteral('base64')],
        );
        const toStringCall = t.callExpression(
          t.memberExpression(bufferFromCall, t.identifier('toString')),
          [t.stringLiteral('utf8')],
        );
        path.replaceWith(toStringCall);
        rewrote = true;
      },
    });
    if (!rewrote) return source;
    return generateSource(ast);
  },
};
