# Architecture

## Pipeline (one run of `vetlock diff <before> <after>`)

```
┌─ lockfile parse (v2/v3) ──► graph                           packages/core/graph.ts
│
├─ CHANGED-SET compute (added/removed/upgraded/integrity-changed)   packages/core/changeset.ts
│    key: (name, version, integrity)
│
├─ for each changed node (bounded worker pool):
│    ├─ cache lookup by tarball integrity hash                packages/core/cache.ts
│    │    hit → reuse snapshot
│    ├─ fetch tarball via pacote                              packages/core/fetch.ts
│    ├─ safe-extract (zip-slip, symlink, tarbomb caps)         packages/core/extract.ts
│    └─ detectors → snapshot { manifest, capabilities, files… }
│
├─ diff snapshot pairs                                        packages/core/diff.ts
│    upgraded: pairwise diff (old vs new)
│    added:    full-scan (no baseline exists)
│    removed:  INFO note
│
├─ provenance annotation (BFS over new graph)                 packages/core/provenance.ts
│
├─ rollup per direct dependency                               packages/core/rollup.ts
│
└─ renderers                                                  packages/cli/renderers/*.ts
     tty / json / sarif / md
```

## Finding schema (universal currency)

```ts
export interface Finding {
  detector: string;           // 'net.new-endpoint', 'install.script-added', …
  package: string;
  from: string | null;        // null for 'added' direction
  to: string | null;          // null for 'removed' direction
  direction: 'added' | 'changed' | 'removed';
  severity: 'BLOCK' | 'WARN' | 'INFO';
  confidence: 'high' | 'medium' | 'low';
  evidence: Evidence[];       // MANDATORY, non-empty
  provenance: string[][];     // shortest paths root→node
}

export interface Evidence {
  file: string;               // relative to package root
  line: number;
  snippet: string;            // trimmed, ≤ 240 chars
}
```

### Invariants (each = named test)

- **Severity diff framing:** capabilities in BOTH versions → INFO max. Only deltas escalate.
  Test: `severity-diff-framing.test.ts`.
- **Evidence mandatory:** finding without evidence → schema validation failure.
  Test: `finding-schema.test.ts`.
- **Closure completeness:** every changed node analyzed, no depth limit by default.
  Test: `closure-completeness.test.ts`.
- **New-node full-scan:** added transitive package → analyzed absolutely (not diff).
  Test: `new-node-fullscan.test.ts`.
- **Provenance correctness:** every path verified against graph; ≤3 shortest paths + "+N more".
  Test: `provenance-paths.test.ts`.
- **Dedup:** package at multiple positions → analyzed once, all provenances reported.
  Test: `dedup-multiparent.test.ts`.
- **Determinism:** same inputs → byte-identical sorted JSON.
  Test: `determinism-golden.test.ts`.
- **Integrity tripwire:** version-unchanged + integrity-changed → BLOCK unconditionally.
  Test: `integrity-tamper.test.ts`.
- **Never-execute canary:** the soul test. See ADR 0005.
  Test: `never-execute-canary.test.ts`. `@critical` marker.
- **Fail-soft parse:** unparseable source → WARN finding, not crash.
  Test: `parse-failsoft.test.ts`.
- **Zip-slip / tarbomb / symlink:** rejected by extractor.
  Tests: `zipslip.test.ts`, `tarbomb-caps.test.ts`, `symlink-reject.test.ts`.

## Detector contract (the plugin funnel)

```ts
export interface Detector {
  id: string;                      // 'net.new-endpoint'
  category: 'NET'|'EXEC'|'FS'|'ENV'|'CODE'|'OBF'|'INSTALL'|'META'|'DEPS'|'INTEG';
  run(pair: SnapshotPair, ctx: DetectorContext): Finding[];
}

export interface SnapshotPair {
  old: PackageSnapshot | null;     // null for 'added'
  new: PackageSnapshot | null;     // null for 'removed'
}
```

Detectors are pure functions. IO happens once in the fetch/extract layer. This is what makes
them unit-testable in isolation and what makes third-party detectors safe to accept as
plugins (see CONTRIBUTING.md).

## Output modes

| Mode | Flag | Consumer |
|---|---|---|
| Pretty (default) | (default) | Human at a terminal |
| JSON | `--json` | Scripts, wrappers |
| SARIF 2.1.0 | `--sarif` | GitHub Security tab, code-scanning |
| Markdown | `--md` | PR comment body |

Exit codes: `0` clean · `1` ≥ WARN · `2` ≥ BLOCK. `--fail-on=<detector-list>` for per-detector
CI gating.

## Performance budget

- 300-package changed set: < 5 min cold, < 30 s warm (published in BENCHMARK.md).
- Concurrency: `os.cpus().length - 1`, min 2, max 8.
- Per-package parse timeout: 30 s → `worker-timeout.test.ts`.

## Cache

Content-addressed by tarball integrity hash. Path: `~/.cache/vetlock/analysis/<hash>.json`.
Storage is the *snapshot*, not findings — detector improvements re-diff cached snapshots
without refetching.
