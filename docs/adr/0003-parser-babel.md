# ADR 0003: JS/TS parser → `@babel/parser`

**Status:** Accepted, 2026-07-12

## Context

Published npm packages span decades of syntax (ES5 through the latest proposals), plus JSX,
Flow, and TypeScript-in-source. The parser has to be tolerant, not strict — malware regularly
ships syntactically weird code specifically to evade tooling.

## Decision

Use `@babel/parser` with these settings by default:

```ts
parse(source, {
  sourceType: 'unambiguous',
  allowReturnOutsideFunction: true,
  allowImportExportEverywhere: true,
  errorRecovery: true,
  plugins: ['jsx', 'typescript', 'decorators-legacy', 'classProperties',
            'optionalChaining', 'nullishCoalescingOperator', 'topLevelAwait']
})
```

Detector visitors are hand-rolled (small, no framework), operating on the returned AST.

## Rationale

- `errorRecovery: true` yields best-effort AST even on syntax errors — critical for our
  fail-soft invariant (§3, "unparseable-source" WARN finding rather than crash).
- Babel's ecosystem covers JSX/TS/Flow uniformly; no need to route per-file-extension to
  different parsers.
- Peer-reviewed, actively maintained; the alternative (acorn + plugins) has weaker error
  recovery.

## Alternatives rejected

- `acorn` — smaller/faster but weaker recovery and no first-class TS/JSX.
- `swc` / `@swc/core` — fast, but its parser is opinionated toward strict parsing; less forgiving.
- `esprima` — abandoned in practice.

## Consequences

- Parse time dominates per-file cost. Cache tarball-integrity → snapshot (ADR 0005) so we only
  parse each version once ever.
- Tests: `parse-failsoft.test.ts` locks in the "unparseable → WARN finding, never crash" behavior.
