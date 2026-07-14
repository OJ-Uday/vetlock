/**
 * env-secret-read-canonical — a completeness-vector transform whose targetClass
 * is the packet §3.5 CANONICAL slash-form `env/secret-read`.
 *
 * WHY this file exists separately from `secret-read-widening.ts`:
 *
 * STARTUP's CAPABILITY-MAP splits the packet's `env/secret-read` class into
 * two STARTUP-shape sinks: `secret-read` (process-env access) and `fs-read`
 * (credential-file access). The STARTUP-shape loader adapter doesn't RENAME
 * `secret-read` to the packet slash-form (unlike `obfuscation-decode` →
 * `obfuscation/decode`) — it lets both live in the map. Consequence:
 * `map.classes` has THREE keys along this axis:
 *
 *   • `env/secret-read` — the packet §3.5 canonical form, present because the
 *     loader ensures every KNOWN_CLASS_IDS entry is at least present with
 *     empty sinks[].
 *   • `secret-read` — STARTUP's process-env split.
 *   • `fs-read` — STARTUP's credential-file split.
 *
 * The pre-existing Wave 6-X `envToProcessEnv` and `envToDestructure` transforms
 * target `secret-read`. Wave 7-HH `readFileToReadFileSync` targets `fs-read`. But
 * the packet slash-form `env/secret-read` is a distinct key nothing intentionally
 * covers, so the strict-intersection coverage math misses it.
 *
 * This transform closes that gap. It's a small, semantics-preserving widening on
 * `process.env` access that DECLARES the canonical slash-form target class. The
 * pattern rewrites `process.env.FOO` (dot-access) to `process.env['FOO']` (computed
 * form) — the exact same widening `envToProcessEnv` performs — with a distinct
 * `id` and canonical `targetClass` so the barrel enumeration remains exhaustive.
 *
 * Since dot-form and computed-form both surface as an `envAccess` in the engine's
 * capability extractor (both go through the same MemberExpression visitor), the
 * finding survives the transform — mirroring the `envToProcessEnv` positive
 * survives test with a different alias path through the oracle's CLASS_ALIASES.
 */

import * as t from '@babel/types';
import { parseSource, generateSource, traverse, type NodePath } from './babel-loader.js';
import type { CompletenessTransform } from './types.js';

/** True iff `node` is the exact expression `process.env`. Mirror of secret-read-widening.ts. */
function isProcessEnv(node: t.Node): boolean {
  if (!t.isMemberExpression(node)) return false;
  if (node.computed) return false;
  if (!t.isIdentifier(node.object, { name: 'process' })) return false;
  if (!t.isIdentifier(node.property, { name: 'env' })) return false;
  return true;
}

export const envToBracketedComputed: CompletenessTransform = {
  id: 'env-to-bracketed-computed',
  family: 'sink-family-widening',
  targetClass: 'env/secret-read',
  description:
    "Rewrite process.env.FOO to process.env['FOO']. Same class, sibling spelling — targets the packet §3.5 canonical `env/secret-read` slash-form key.",
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
        // Match `process.env.FOO`: object is `process.env`, property is a plain
        // Identifier (not yet computed). This is intentionally the same predicate
        // as envToProcessEnv — the two transforms cover the same axis under
        // different targetClass strings so the coverage math counts both
        // packet-canonical AND STARTUP-shape spellings.
        if (path.node.computed) return;
        if (!isProcessEnv(path.node.object)) return;
        if (!t.isIdentifier(path.node.property)) return;
        const keyName = path.node.property.name;
        path.node.property = t.stringLiteral(keyName);
        path.node.computed = true;
        rewrote = true;
      },
    });
    if (!rewrote) return source;
    return generateSource(ast);
  },
};
