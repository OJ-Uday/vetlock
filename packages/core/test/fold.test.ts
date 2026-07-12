import { describe, it, expect } from 'vitest';
import * as parser from '@babel/parser';
import * as babelTraverseNs from '@babel/traverse';
import * as t from '@babel/types';
import { foldConstants } from '../src/fold.js';

const traverse: (n: t.Node, opts: unknown) => void = (() => {
  const anyNs = babelTraverseNs as unknown as Record<string, unknown>;
  if (typeof anyNs === 'function') return anyNs as never;
  if (typeof anyNs.default === 'function') return anyNs.default as never;
  const nested = (anyNs.default as Record<string, unknown> | undefined)?.default;
  if (typeof nested === 'function') return nested as never;
  throw new Error('unable to load @babel/traverse');
})();

function parse(src: string): t.File {
  return parser.parse(src, { sourceType: 'unambiguous', errorRecovery: true });
}

function foldedValueFor(src: string, matcher: (n: t.Node) => boolean): string | undefined {
  const ast = parse(src);
  const folds = foldConstants(ast, traverse);
  let found: string | undefined;
  traverse(ast, {
    enter(path: { node: t.Node }) {
      if (matcher(path.node)) {
        const v = folds.get(path.node);
        if (v !== undefined && found === undefined) found = v;
      }
    },
  });
  return found;
}

describe('constant folding', () => {
  it('folds a string literal on the RHS of a declarator', () => {
    // Bare `"hello"` as an ExpressionStatement isn't interesting to fold —
    // it's never an argument. We test folding as it's actually used: on the
    // RHS of a variable declaration, which resolves the identifier.
    const v = foldedValueFor(
      "const s = 'hello';",
      (n) => t.isBinaryExpression(n) || (t.isIdentifier(n) && (n as t.Identifier).name === 's'),
    );
    // The Identifier reference to `s` should fold to 'hello' via the varValues map.
    expect(v).toBe('hello');
  });

  it('folds a template literal with no expressions', () => {
    const v = foldedValueFor('`hello world`', (n) => t.isTemplateLiteral(n));
    expect(v).toBe('hello world');
  });

  it('folds string + concat', () => {
    const v = foldedValueFor(
      "const s = 'child_' + 'process';",
      (n) => t.isBinaryExpression(n) && n.operator === '+',
    );
    expect(v).toBe('child_process');
  });

  it('folds String.fromCharCode chain', () => {
    // 'NPM_TOKEN' = [78,80,77,95,84,79,75,69,78]
    const src = 'const k = String.fromCharCode(78,80,77,95,84,79,75,69,78);';
    const v = foldedValueFor(src, (n) => t.isCallExpression(n));
    expect(v).toBe('NPM_TOKEN');
  });

  it('folds Buffer.from(x, "base64").toString()', () => {
    // 'https://evil.com' base64 = 'aHR0cHM6Ly9ldmlsLmNvbQ=='
    const src = "const u = Buffer.from('aHR0cHM6Ly9ldmlsLmNvbQ==', 'base64').toString();";
    const v = foldedValueFor(src, (n) => t.isCallExpression(n) && t.isMemberExpression(n.callee) && t.isIdentifier(n.callee.property, { name: 'toString' }));
    expect(v).toBe('https://evil.com');
  });

  it('folds Buffer.from(array-of-charcodes).toString()', () => {
    // 'hi' = [104, 105]
    const src = "const s = Buffer.from([104, 105]).toString();";
    const v = foldedValueFor(src, (n) => t.isCallExpression(n) && t.isMemberExpression(n.callee) && t.isIdentifier(n.callee.property, { name: 'toString' }));
    expect(v).toBe('hi');
  });

  it('folds decodeURIComponent(literal)', () => {
    // 'https://evil/' URL-encoded
    const src = "const u = decodeURIComponent('https%3A%2F%2Fevil.example.invalid%2Fx');";
    const v = foldedValueFor(src, (n) => t.isCallExpression(n) && t.isIdentifier(n.callee, { name: 'decodeURIComponent' }));
    expect(v).toBe('https://evil.example.invalid/x');
  });

  it('folds unescape(literal) — legacy alias', () => {
    const src = "const u = unescape('a%3Db');";
    const v = foldedValueFor(src, (n) => t.isCallExpression(n) && t.isIdentifier(n.callee, { name: 'unescape' }));
    expect(v).toBe('a=b');
  });

  it('folds Buffer.from hex.toString()', () => {
    // 'AB' = 4142
    const src = "const s = Buffer.from('4142', 'hex').toString();";
    const v = foldedValueFor(src, (n) => t.isCallExpression(n) && t.isMemberExpression(n.callee) && t.isIdentifier(n.callee.property, { name: 'toString' }));
    expect(v).toBe('AB');
  });

  it('folds atob() calls', () => {
    // 'hi' base64 = 'aGk='
    const src = "const s = atob('aGk=');";
    const v = foldedValueFor(src, (n) => t.isCallExpression(n) && t.isIdentifier(n.callee, { name: 'atob' }));
    expect(v).toBe('hi');
  });

  it('folds ["a", "b"].join("")', () => {
    const src = "const s = ['ab', 'cd'].join('');";
    const v = foldedValueFor(src, (n) => t.isCallExpression(n) && t.isMemberExpression(n.callee) && t.isIdentifier(n.callee.property, { name: 'join' }));
    expect(v).toBe('abcd');
  });

  it('resolves references-to-references (multi-pass fixed-point)', () => {
    const src = `
      const a = 'foo';
      const b = a + 'bar';
      const c = b + 'baz';
    `;
    const v = foldedValueFor(src, (n) => t.isVariableDeclarator(n) && t.isIdentifier((n as t.VariableDeclarator).id) && ((n as t.VariableDeclarator).id as t.Identifier).name === 'c'
      ? true
      : t.isBinaryExpression(n) && n.operator === '+' && t.isIdentifier(n.left, { name: 'b' }));
    expect(v).toBe('foobarbaz');
  });

  it('leaves genuinely dynamic values unresolved', () => {
    const src = "const s = getRuntimeValue();";
    const v = foldedValueFor(src, (n) => t.isCallExpression(n));
    expect(v).toBeUndefined();
  });

  it('handles pathological input without infinite loop', () => {
    // Self-referential: `const a = a + 'x';` — must not stall
    const src = `const a = a + 'x';`;
    expect(() => foldedValueFor(src, () => false)).not.toThrow();
  });
});
