/**
 * string-normalization — convert a string literal into an equivalent syntactic
 * form. A capable scanner CONSTANT-FOLDS (evaluates the constant expression
 * statically) before matching sensitive names against its watchlist. A weak
 * scanner only matches the literal *shape* of the string and misses these variants.
 *
 * Every variant is spec-preserving: per ECMAScript 2024 §12, the following are all
 * evaluated to the string `"exec"` at parse-time or in a constant-fold pass:
 *
 *   • concatenation of char literals:  "e" + "x" + "e" + "c"
 *   • template literal (untagged):     `exec`
 *   • template literal with expr:      `ex${'e'}c`
 *   • String.fromCharCode reconstruct: String.fromCharCode(101, 120, 101, 99)
 *
 * The transforms target StringLiteral nodes whose VALUE matches a small set of
 * capability-relevant names (the "watchlist"). This keeps the transforms scoped
 * — we don't turn every string in a file into a `String.fromCharCode` blob, only
 * the ones the scanner should have caught in the first place.
 *
 * Watchlist rationale: these strings are the *arguments* to require() and the
 * MemberExpression names most scanners key on. Widening them exercises the exact
 * fold path a capable scanner must implement.
 */

import * as t from '@babel/types';
import { parseSource, generateSource, traverse, type NodePath } from './babel-loader.js';
import type { CompletenessTransform } from './types.js';

/** Capability-relevant string values worth widening. Any occurrence of one of
 *  these AS A StringLiteral gets rewritten. */
const WATCHLIST: readonly string[] = [
  // capability-execution module names
  'child_process', 'node:child_process', 'worker_threads', 'vm', 'node:vm',
  // capability-execution member names
  'exec', 'execFile', 'execSync', 'spawn', 'spawnSync', 'fork',
  'runInThisContext', 'runInNewContext',
  // net-egress module names
  'http', 'https', 'node:http', 'node:https', 'net', 'dns', 'node:dns',
  // net-egress member names
  'request', 'get', 'connect',
  // fs-write module names + member names (subset)
  'fs', 'node:fs', 'writeFile', 'writeFileSync', 'appendFile', 'appendFileSync',
  // env / secret reads
  'NPM_TOKEN', 'GITHUB_TOKEN', 'AWS_SECRET_ACCESS_KEY',
];

/** Should we rewrite this StringLiteral value? */
function isWatchlisted(value: string): boolean {
  return WATCHLIST.includes(value);
}

/** Build a chained `+` expression from an array of substrings, at least length 1. */
function buildConcat(parts: readonly string[]): t.Expression {
  if (parts.length === 0) return t.stringLiteral('');
  let expr: t.Expression = t.stringLiteral(parts[0]);
  for (let i = 1; i < parts.length; i++) {
    expr = t.binaryExpression('+', expr, t.stringLiteral(parts[i]));
  }
  return expr;
}

/** Split a string into single-character parts. `"exec"` → `["e", "x", "e", "c"]`. */
function chars(s: string): string[] {
  return Array.from(s);
}

/** Walk the AST and replace every watchlisted StringLiteral by `replacer(value)`.
 *  Returns the number of literals replaced. */
function transformWatchlisted(
  source: string,
  replacer: (value: string) => t.Expression,
): string {
  let ast: ReturnType<typeof parseSource>;
  try {
    ast = parseSource(source);
  } catch {
    return source;
  }
  let rewrote = false;
  traverse(ast, {
    StringLiteral(path: NodePath<t.StringLiteral>) {
      if (!isWatchlisted(path.node.value)) return;
      // Don't rewrite object property keys — that would change the property NAME,
      // not a string value the scanner reads. Only rewrite when the literal is
      // used as an expression value (call arg, RHS of assignment, computed member
      // property, template placeholder, etc.).
      if (
        t.isObjectProperty(path.parent) &&
        path.parent.key === path.node &&
        !path.parent.computed
      ) {
        return;
      }
      const replacement = replacer(path.node.value);
      path.replaceWith(replacement);
      rewrote = true;
    },
  });
  if (!rewrote) return source;
  return generateSource(ast);
}

export const literalToConcat: CompletenessTransform = {
  id: 'literal-to-concat',
  family: 'string-normalization',
  targetClass: 'code-execution',
  description:
    'Rewrite a capability-watchlisted string literal into a chained `+` concat: "exec" → "e" + "x" + "e" + "c". Constant-fold equivalent.',
  transform(source, _seed): string {
    return transformWatchlisted(source, (value) => buildConcat(chars(value)));
  },
};

export const literalToTemplate: CompletenessTransform = {
  id: 'literal-to-template',
  family: 'string-normalization',
  targetClass: 'code-execution',
  description:
    'Rewrite a capability-watchlisted string literal into a template with a single interpolated middle char: "exec" → `ex${"e"}c`. Semantically identical.',
  transform(source, _seed): string {
    return transformWatchlisted(source, (value) => {
      // Split into `prefix` + `${middle}` + `suffix`. Middle is exactly one char.
      // Edge cases: empty string → template literal ``; 1-char → `${value}`.
      if (value.length === 0) {
        return t.templateLiteral([t.templateElement({ raw: '', cooked: '' }, true)], []);
      }
      if (value.length === 1) {
        return t.templateLiteral(
          [
            t.templateElement({ raw: '', cooked: '' }, false),
            t.templateElement({ raw: '', cooked: '' }, true),
          ],
          [t.stringLiteral(value)],
        );
      }
      // For length >= 2, split at index 1: prefix = value[0], middle = value[1],
      // suffix = value[2..]. Yields `p${m}s` where m is a StringLiteral expression.
      const prefix = value[0];
      const middle = value[1];
      const suffix = value.slice(2);
      return t.templateLiteral(
        [
          t.templateElement({ raw: prefix, cooked: prefix }, false),
          t.templateElement({ raw: suffix, cooked: suffix }, true),
        ],
        [t.stringLiteral(middle)],
      );
    });
  },
};

export const literalToCharCodeRebuild: CompletenessTransform = {
  id: 'literal-to-char-code-rebuild',
  family: 'string-normalization',
  targetClass: 'code-execution',
  description:
    'Rewrite a capability-watchlisted string literal into `String.fromCharCode(...)` with the same char codes. Semantically identical per ECMAScript §21.1.',
  transform(source, _seed): string {
    return transformWatchlisted(source, (value) => {
      const codes = chars(value).map((ch) => t.numericLiteral(ch.charCodeAt(0)));
      return t.callExpression(
        t.memberExpression(t.identifier('String'), t.identifier('fromCharCode')),
        codes,
      );
    });
  },
};
