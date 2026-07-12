# ADR 0002: Language — TypeScript on Node ≥ 20

**Status:** Accepted, 2026-07-12

## Context

The tool ships as an npm-installable CLI + GitHub Action against npm packages and lockfiles.

## Decision

TypeScript, Node ≥ 20. Monorepo via pnpm workspaces:

- `packages/core` — graph engine, fetch/extract, cache
- `packages/detectors` — one module per taxonomy row (see ARCHITECTURE.md)
- `packages/cli` — commander entry + renderers (TTY/JSON/SARIF/md)

Compile with `tsc` to CommonJS-compatible ESM (Node's native ESM). Test with `vitest`.

## Rationale

- Audience installs from npm. `npx vetlock` is the zero-commitment adoption path.
- Native JS AST access via `@babel/parser` (ADR 0003) — a Go rewrite would need to embed a JS
  parser or shell out. Native is faster and less impedance.
- Type safety across the finding-schema boundary between engine / detectors / renderers is the
  single most valuable static invariant we have.

## Consequences

- We accept Node startup latency (~150ms cold) — negligible against the fetch+extract+parse work.
- A Go/Rust engine port stays as a ROADMAP flex once we have signal that we need it.
