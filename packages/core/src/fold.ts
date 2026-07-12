/**
 * Constant-folding pass — walk the AST, resolve as many strings as possible.
 *
 * Handles:
 *   - String literals (identity).
 *   - Template literals with no expressions or with all-literal expressions.
 *   - String + concatenation between resolvable operands.
 *   - String.fromCharCode(n, n, n, ...) with resolvable numeric args.
 *   - Buffer.from(literal, 'base64' | 'hex').toString([enc]).
 *   - Buffer.from([n, n, n]).toString() — charcode-array construction.
 *   - atob(literal) — browser base64 decode.
 *   - decodeURIComponent(literal) / unescape(literal) — URL-encoded strings.
 *   - Array.prototype.join(sep) on all-literal arrays.
 *   - Variable references to `const/let/var name = <foldable>` in the same file.
 *
 * Not handled — DELIBERATE gaps, each documented so we're honest about it:
 *   - Function-call return values whose body we'd need to interpret. Adding
 *     this requires actual interpretation, which is a large surface. We flag
 *     the CALL itself as dynamic-code, which is the right escalation path.
 *   - Multi-file constants. Requires cross-file linking, roadmap.
 *   - ROT13 / custom XOR / Base32 / etc. Attackers who write custom decoders
 *     get flagged instead by the dynamic-code detector + the entropy-jump
 *     detector on the encoded blob. If we ever see ROT13 in a real corpus
 *     attack, add a pattern for it — TDD via the corpus, not speculation.
 *
 * PRINCIPLE (see docs/SECURITY-DECISIONS.md): every fold we add closes an
 * evasion. Every fold we skip is a hole. When adding, keep it deterministic,
 * side-effect free, and read-only against the AST.
 */

import * as t from '@babel/types';
import type { NodePath } from '@babel/traverse';

export type FoldMap = WeakMap<t.Node, string>;

/**
 * Runs a fixed-point pass: fold every declarator that can be resolved, then
 * repeat until no more values can be resolved (references-to-references).
 * The number of passes is bounded — cheap in practice.
 */
export function foldConstants(ast: t.File, traverseFn: (ast: t.Node, opts: unknown) => void): FoldMap {
  const folds: FoldMap = new WeakMap();
  const varValues = new Map<string, string>();
  // Reference from Identifier node → the variable name it resolves.
  // We store this so second-pass folding of e.g. `process.env[K]` can look up K.

  const MAX_PASSES = 5;
  for (let pass = 0; pass < MAX_PASSES; pass++) {
    let changed = false;

    traverseFn(ast, {
      // Fold each expression node bottom-up when visited.
      enter(path: NodePath) {
        // Skip nodes we've already folded.
        if (folds.has(path.node)) return;
        const value = tryFold(path.node, folds, varValues);
        if (value !== null) {
          folds.set(path.node, value);
          changed = true;
        }
      },
      VariableDeclarator: {
        exit(path: NodePath<t.VariableDeclarator>) {
          if (!t.isIdentifier(path.node.id)) return;
          const name = path.node.id.name;
          const init = path.node.init;
          if (!init) return;
          const value = folds.get(init) ?? tryFold(init, folds, varValues);
          if (value !== null && !varValues.has(name)) {
            varValues.set(name, value);
            changed = true;
          }
        },
      },
    });

    if (!changed) break;
  }
  return folds;
}

/**
 * Try to resolve a single expression to a string. Returns null when it can't.
 */
function tryFold(node: t.Node, folds: FoldMap, vars: Map<string, string>): string | null {
  if (folds.has(node)) return folds.get(node)!;

  // Literals
  if (t.isStringLiteral(node)) return node.value;
  if (t.isNumericLiteral(node)) return String(node.value);
  if (t.isBooleanLiteral(node)) return String(node.value);
  if (t.isNullLiteral(node)) return null; // deliberate — we want string data
  if (t.isTemplateLiteral(node)) {
    if (node.quasis.length === 1 && node.expressions.length === 0) {
      return node.quasis[0]!.value.cooked ?? node.quasis[0]!.value.raw;
    }
    // Try to fold each expression, splice with quasis
    const parts: string[] = [];
    for (let i = 0; i < node.quasis.length; i++) {
      parts.push(node.quasis[i]!.value.cooked ?? '');
      if (i < node.expressions.length) {
        const e = node.expressions[i]!;
        const v = folds.get(e as t.Node) ?? tryFold(e as t.Node, folds, vars);
        if (v === null) return null;
        parts.push(v);
      }
    }
    return parts.join('');
  }

  // Identifier — look up the variable value.
  if (t.isIdentifier(node)) {
    const v = vars.get(node.name);
    return v ?? null;
  }

  // BinaryExpression: string concat (+)
  if (t.isBinaryExpression(node) && node.operator === '+') {
    const l = folds.get(node.left as t.Node) ?? tryFold(node.left as t.Node, folds, vars);
    const r = folds.get(node.right as t.Node) ?? tryFold(node.right as t.Node, folds, vars);
    if (l !== null && r !== null) return l + r;
    return null;
  }

  // CallExpression — a couple of known folds
  if (t.isCallExpression(node)) {
    return tryFoldCall(node, folds, vars);
  }

  // Member access — special: `undefined` global → string 'undefined'.
  // Everything else: unresolvable.

  return null;
}

function tryFoldCall(
  call: t.CallExpression,
  folds: FoldMap,
  vars: Map<string, string>,
): string | null {
  const callee = call.callee;
  const args = call.arguments;

  // String.fromCharCode(n, n, n, ...) with resolvable numeric args
  if (
    t.isMemberExpression(callee) &&
    t.isIdentifier(callee.object, { name: 'String' }) &&
    t.isIdentifier(callee.property, { name: 'fromCharCode' })
  ) {
    const codes: number[] = [];
    for (const a of args) {
      if (t.isNumericLiteral(a)) {
        codes.push(a.value);
      } else {
        const v = folds.get(a as t.Node) ?? tryFold(a as t.Node, folds, vars);
        if (v === null) return null;
        const n = Number(v);
        if (Number.isNaN(n)) return null;
        codes.push(n);
      }
    }
    try {
      return String.fromCharCode(...codes);
    } catch {
      return null;
    }
  }

  // atob(literal) — global browser-ish, but real payloads sometimes reach for it
  if (t.isIdentifier(callee, { name: 'atob' })) {
    const a = args[0];
    if (!a) return null;
    const v = folds.get(a as t.Node) ?? tryFold(a as t.Node, folds, vars);
    if (v === null) return null;
    try {
      return Buffer.from(v, 'base64').toString('binary');
    } catch {
      return null;
    }
  }

  // decodeURIComponent(literal) — URL-encoded exfil URL evasion.
  //   decodeURIComponent('https%3A%2F%2Fevil.example.invalid%2F') → 'https://evil.example.invalid/'
  if (t.isIdentifier(callee, { name: 'decodeURIComponent' })) {
    const a = args[0];
    if (!a) return null;
    const v = folds.get(a as t.Node) ?? tryFold(a as t.Node, folds, vars);
    if (v === null) return null;
    try {
      return decodeURIComponent(v);
    } catch {
      return null;
    }
  }

  // unescape(literal) — legacy alias for decodeURIComponent; still works in Node.
  if (t.isIdentifier(callee, { name: 'unescape' })) {
    const a = args[0];
    if (!a) return null;
    const v = folds.get(a as t.Node) ?? tryFold(a as t.Node, folds, vars);
    if (v === null) return null;
    try {
      return decodeURIComponent(v);
    } catch {
      return null;
    }
  }

  // Buffer.from(literal | array-of-charcodes, [enc]).toString([enc]).
  //
  // Two shapes we handle:
  //   Buffer.from('aGVsbG8=', 'base64').toString()           — b64 string
  //   Buffer.from('68656c6c6f', 'hex').toString()             — hex string
  //   Buffer.from([104, 105]).toString()                       — charcode array
  //
  // The array-of-charcodes shape is a real evasion technique. If we don't
  // resolve it, attackers get a free pass by writing their exfil URL as an
  // array of integers.
  if (
    t.isMemberExpression(callee) &&
    t.isIdentifier(callee.property, { name: 'toString' }) &&
    t.isCallExpression(callee.object)
  ) {
    const inner = callee.object;
    if (
      t.isMemberExpression(inner.callee) &&
      t.isIdentifier(inner.callee.object, { name: 'Buffer' }) &&
      t.isIdentifier(inner.callee.property, { name: 'from' })
    ) {
      const dataArg = inner.arguments[0];
      const encArg = inner.arguments[1];
      // Case 1: array-of-charcodes
      if (t.isArrayExpression(dataArg)) {
        const codes: number[] = [];
        for (const el of dataArg.elements) {
          if (el === null) return null;
          if (t.isNumericLiteral(el)) {
            codes.push(el.value);
          } else {
            const v = folds.get(el as t.Node) ?? tryFold(el as t.Node, folds, vars);
            if (v === null) return null;
            const n = Number(v);
            if (Number.isNaN(n)) return null;
            codes.push(n);
          }
        }
        try {
          return Buffer.from(codes).toString('utf8');
        } catch {
          return null;
        }
      }
      // Case 2/3: string data with encoding hint
      const data = dataArg ? (folds.get(dataArg as t.Node) ?? tryFold(dataArg as t.Node, folds, vars)) : null;
      if (data === null) return null;
      let enc: BufferEncoding = 'utf8';
      if (t.isStringLiteral(encArg)) {
        const e = encArg.value;
        if (e === 'base64' || e === 'hex' || e === 'utf8' || e === 'ascii' || e === 'binary') {
          enc = e as BufferEncoding;
        }
      }
      try {
        return Buffer.from(data, enc).toString('utf8');
      } catch {
        return null;
      }
    }
  }

  // Array.prototype.join — handles ['a', 'b', 'c'].join('') and similar
  if (
    t.isMemberExpression(callee) &&
    t.isIdentifier(callee.property, { name: 'join' }) &&
    t.isArrayExpression(callee.object)
  ) {
    const elts = callee.object.elements;
    const resolved: string[] = [];
    for (const el of elts) {
      if (el === null) return null;
      if (t.isSpreadElement(el)) return null;
      const v = folds.get(el as t.Node) ?? tryFold(el as t.Node, folds, vars);
      if (v === null) return null;
      resolved.push(v);
    }
    const sepArg = args[0];
    let sep = ',';
    if (!sepArg) {
      // .join() default separator is ','
      sep = ',';
    } else {
      const v = folds.get(sepArg as t.Node) ?? tryFold(sepArg as t.Node, folds, vars);
      if (v === null) return null;
      sep = v;
    }
    return resolved.join(sep);
  }

  // parseInt(literal, 16) — used by hex-decoding loops. We don't fold the
  // full loop; the standalone parseInt is only useful for very small chains
  // and would trip fewer real evasions than it's worth. Skipping.

  return null;
}
