# ADR 0005: NEVER-EXECUTE prime directive

**Status:** Accepted, 2026-07-12 (immutable)

## Context

vetlock analyzes potentially-malicious packages. A tool that executes malicious code in order
to detect that it's malicious has inverted its own safety model.

## Decision

The analyzer NEVER runs any code from an analyzed package. Specifically:

1. No `npm install` / `npm ci` / `yarn` / `pnpm install` on any analyzed tree.
2. No invocation of lifecycle scripts (`preinstall`, `install`, `postinstall`, `prepare`, etc.).
   Their bodies are read as text and analyzed.
3. No dynamic `require()` / `import()` of any file from an extracted tarball.
4. No `eval` on extracted contents.
5. No compilation via a system compiler (e.g., no `node-gyp` invocation).

Extracted files are read-only inputs to static analysis: string reads, AST parses, byte-hash
computations. Nothing more.

## Enforcement

This is a **tested** invariant, not a convention.

**`never-execute-canary.test.ts`** — the repo's soul test:

- Fixture: a tarball whose `postinstall` script and whose every `.js` file, if executed, would
  write a sentinel file to `os.tmpdir()/vetlock-canary-<runId>`.
- Test: `analyzePackage(fixtureTarball)` runs the full pipeline.
- Assert: sentinel file does NOT exist afterward.
- Marker: `@critical` — CI skip is treated as failure.

Any future refactor that would allow execution must first delete this test consciously (which
is itself a review flag).

### CI hook

The `never-execute-canary.test.ts` test is marked `@critical` in the CI configuration. Any PR that skips, removes, or comments out this test will fail CI automatically. This is not a soft convention — it is a required check.

See `.github/workflows/assurance-pr.yml` for the enforcement hook.

## Rationale

- Malware detonation-in-a-sandbox is not a viable OSS product surface — the infrastructure
  cost, the false-positive-through-noise-signals problem, and the "run malware to detect
  malware" perception are all disqualifying at our scale.
- Static analysis with a diff frame catches the classes of attacks we care about (§THREAT-MODEL)
  without ever exposing the analyst's machine.
- Users trust security tools that model themselves after their advice. "We never run untrusted
  code" is the same rule we're helping them enforce.

## Consequences

- We cannot catch fully dynamic loading chains where every string is computed at runtime. We
  flag unresolvable dynamic `require`/`import` as its own finding (`CODE` detector) rather than
  pretending to resolve them.
- Lifecycle-script bodies are analyzed by the same AST detectors that analyze regular code —
  a `postinstall` that reads `process.env.NPM_TOKEN` and POSTs it to `evil.example.com`
  produces one finding of INSTALL/BLOCK severity plus co-findings of ENV and NET.

## Cache addendum

Snapshots are keyed by tarball integrity hash (`sha512-…`) → JSON. Storage:
`~/.cache/vetlock/analysis/<hash>.json`. Findings are computed by diffing snapshot pairs; a
detector improvement causes findings to be recomputed from cached snapshots without refetching.
Cache format has a `formatVersion` field; taxonomy-breaking changes bump it and invalidate.
