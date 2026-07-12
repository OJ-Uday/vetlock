# ADR 0004: Fetch → `pacote`; safe-extract is ours

**Status:** Accepted, 2026-07-12

## Context

We need to download package tarballs (versions old and new) and extract them for static analysis.
We must NOT execute any code from these tarballs (see ADR 0005 — the prime directive).

## Decision

- **Fetch:** `pacote` (npm's own package fetcher). Handles registries, scopes, auth, and
  **integrity verification** against the lockfile's `integrity:` hash for free.
- **Extract:** ours. We use `tar` (the npm package) as a low-level stream parser, then apply
  our own entry filter before writing anything to disk.

Our extractor rejects:

1. Absolute paths (`/etc/passwd`) — zip-slip class.
2. Path traversal (`../`, `foo/../../bar`) — zip-slip class.
3. Symbolic links and hard links of any kind — reference-outside-scope class.
4. Files whose size exceeds a per-entry cap (default 50 MiB).
5. Total extracted bytes exceeding a run cap (default 500 MiB) — tarbomb.
6. File count exceeding a run cap (default 10,000).

All extraction happens into a per-run temp directory under `~/.cache/vetlock/tmp/<runId>/`,
which is deleted in `finally` regardless of throw.

## Rationale

- `pacote` composes with npm's own auth/proxy conventions; users don't have to configure a
  second thing to make private registries work.
- We don't use `tar.extract()` (the high-level API) because we need to reject entries *before*
  they touch disk. Streaming through the parser gives us that intercept point.

## Consequences

- Extraction correctness is a first-class test surface. See `zipslip.test.ts`,
  `tarbomb-caps.test.ts`, `symlink-reject.test.ts`, `extract-cleanup.test.ts`.
- Cache layer stores per-version *snapshots* (extracted capabilities), not findings — so a
  detector improvement re-diffs old snapshots without refetching (see ADR 0005 §Cache).
