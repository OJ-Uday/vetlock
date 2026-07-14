# ADR 0009: Ecosystem adapter interface

**Status:** Accepted, 2026-07-13

## Context

vetlock v0.3.0 is npm-only. The STARTUP packet (§3.7) elevates PyPI/pip to a
launch-adjacent ecosystem (not a post-launch roadmap item) because:
- The **completeness doctrine** (ADR 0011) transfers directly to Python — only
  the sink/entry-point *contents* change, not the model.
- Python's attack surface is arguably worse than npm's (`setup.py` executes
  arbitrary code at install), making NEVER-EXECUTE even more essential.
- Two ecosystems at launch signals "platform, not npm tool" — doubling
  addressable market for near-zero marketing cost.

The engine is currently structured with npm assumptions baked into several
layers:
- Lockfile parsing: `packages/core/src/lockfile.ts` (npm), `lockfile-pnpm.ts`,
  `lockfile-yarn.ts`. All three route through a `parseLockfileText` dispatcher.
- Package fetching: `packages/core/src/fetch.ts` uses `pacote`
  (npm-specific).
- Extraction: `packages/core/src/extract.ts` uses `tar` for `.tgz`.
- Capability extraction: `packages/core/src/capabilities.ts` uses
  `@babel/parser` for JS/TS ASTs and hard-codes JS ecosystem module names
  (`child_process`, `fs`, `process.env`, ...).
- Detectors: some are ecosystem-agnostic (`integrity`, `install.script-added`
  on the lifecycle-script class); others are JS-specific (`env.token-harvest`
  scans for `process.env.NPM_TOKEN`).

Adding PyPI naïvely would require touching every one of those layers. We need
an interface that lets each ecosystem contribute its own AST frontend +
sink/entry-point set while sharing the engine, the changeset logic, the
NEVER-EXECUTE canary, the safe-extract, the cache, and the finding schema.

## Decision

Extract an **`EcosystemAdapter`** interface. Each ecosystem contributes one
implementation. The engine dispatches by lockfile format (already done via
`parseLockfileText`) and then delegates ecosystem-specific work to the
adapter.

### The interface (initial shape — will be refined during P4c implementation)

```ts
// packages/core/src/ecosystem.ts

export interface EcosystemAdapter {
  /** Ecosystem identifier: 'npm' | 'pypi' | 'go' | 'crates' | 'gems' | 'maven'. */
  readonly id: string;

  /** Lockfile filenames + magic-bytes patterns this adapter handles. */
  readonly lockfileHints: {
    filenames: string[];   // e.g. ['package-lock.json', 'npm-shrinkwrap.json']
    contentPatterns: RegExp[];  // e.g. /^\s*\{[\s\S]*"lockfileVersion"/
  };

  /** Parse a lockfile text into the shared LockGraph shape. */
  parseLockfile(text: string, filenameHint?: string): LockGraph;

  /** Fetch a package's tarball/wheel/sdist to a local path. */
  fetchArtifact(ref: PackageRef): Promise<string>;

  /** Extract an artifact to a temp dir with the safe-extract invariants. */
  extractArtifact(artifactPath: string, destDir: string): Promise<void>;

  /**
   * Analyse the extracted package for capability signals. Returns the same
   * FileCapabilities[] shape npm currently produces. The ecosystem contributes
   * its OWN AST frontend here — Python via `ast` semantics, Go via
   * `go/ast`, etc. — but the OUTPUT shape is universal so detectors don't
   * care which ecosystem produced it.
   */
  extractCapabilities(extractedDir: string, manifest: PackageManifest): Promise<FileCapabilities[]>;

  /** The sink + entry-point sets contributed to CAPABILITY-MAP.json for this ecosystem. */
  capabilitySlice(): CapabilityMapSlice;

  /**
   * Ecosystem-specific detector variants (e.g. Python's `pth`-file entry-point
   * detector doesn't apply to npm). Detectors emit standard Finding[] so the
   * runAll() layer treats them identically.
   */
  detectors(): Detector[];
}

/** The chunk of CAPABILITY-MAP this ecosystem is responsible for. */
export interface CapabilityMapSlice {
  ecosystem: string;
  sinks: CapabilityMapEntry[];      // e.g. [{class:'code-execution', kind:'sink', id:'os.system'}]
  entryPoints: CapabilityMapEntry[]; // e.g. [{class:'install-hook', kind:'entry-point', id:'setup.py'}]
}
```

### What each adapter owns

| Layer                          | Owned by adapter | Owned by engine |
|--------------------------------|------------------|-----------------|
| Lockfile parser                | ✅               |                 |
| Registry client (fetch)        | ✅               |                 |
| Archive extraction rules       | ✅ (tarball → tar, wheel → zip, sdist → tar) | Safe-extract invariants (zipslip/tarbomb/symlink) enforced by shared helper |
| AST frontend                   | ✅ (Babel for JS, Python `ast` for Python, etc.) |                 |
| Sink/entry-point enumeration   | ✅ (contributes slice to CAPABILITY-MAP)         |                 |
| Ecosystem-specific detectors   | ✅               |                 |
| Universal detectors            |                  | ✅ (integrity-tripwire, install-script-added when both ecosystems have lifecycle-scripts, typosquat via edit-distance) |
| Snapshot + cache               |                  | ✅              |
| Changeset compute              |                  | ✅              |
| runAll / escalation rules      |                  | ✅              |
| Fail-closed / NEVER-EXECUTE    |                  | ✅ (canary tests span ALL adapters — see below) |

### Invariants that span every adapter

- **NEVER-EXECUTE** (ADR 0005) — every adapter's `extractCapabilities` runs
  under the same canary. For Python that means `setup.py` is parsed with
  `python-ast`, never executed.
- **Safe-extract** — every adapter's `extractArtifact` uses the same
  zipslip/symlink/tarbomb-guarded extractor. New archive formats add new
  guards via a shared helper.
- **Fail-closed** (S10) — every adapter's fetch/extract/parse throws structured
  errors; the engine wraps them in `analysis.failed` findings.

## Enforcement

- **`ecosystem-adapter-contract.test`** — instantiate every registered
  adapter, run it through the contract shape (parse a synthetic minimal
  lockfile, extract a synthetic artifact, extract capabilities, return a
  capability slice). Every method must return a shape the engine accepts.
- **`never-execute-canary` runs per adapter** — each adapter provides a
  hostile fixture (`packages/ecosystems/<id>/canary-fixture.tgz` or `.whl`
  etc.); the canary asserts the sentinel file was NOT written for any of
  them.
- **`capability-map-coverage` spans all ecosystems** (ADR 0011) — the coverage
  gate loops every registered adapter and asserts each contributed slice
  has detector+test bindings.

## Rationale

- **Doctrine transfers, not re-invents.** ADR 0011 (completeness) is written
  as an ecosystem-agnostic law. The adapter interface is what makes it
  literally true.
- **New ecosystems reuse the moat.** The red-team story, the FP study, the
  benchmark, the diff-framing, the safe-extract, the NEVER-EXECUTE canary
  all apply to Python for free. A PyPI-only competitor has to rebuild those
  from scratch.
- **Adapter shape is the extension point.** Community contributions for new
  ecosystems (Go, Rust, Maven, Ruby) can land as one new adapter + one
  capability slice, without touching engine code. This is the "platform,
  not tool" positioning stated as an engineering fact.

## Consequences

- The current npm code becomes `NpmAdapter` in P4c prep work — a
  refactoring that must land WITHOUT changing any test's expected output
  (existing 384 tests are the ground truth). This is a P4c-blocking
  refactor, planned as its own PR before the Python adapter lands.
- Every future detector PR has to answer "is this universal or ecosystem-
  specific?" A universal detector goes in `packages/detectors/`; an
  ecosystem-specific one goes in `packages/ecosystems/<id>/detectors/`.
  CI enforces this by inspecting the CAPABILITY-MAP class of each detector.
- The `packages/` layout gains a new `ecosystems/` directory:
  ```
  packages/
    core/
    detectors/         # universal detectors
    cli/
    ecosystems/
      npm/             # NpmAdapter (current npm code, refactored)
      pypi/            # PypiAdapter (P4c)
      (future: go/, crates/, gems/, maven/)
  ```
- The refactor is *pure interface extraction* — behavior must not change.
  Golden-fixture drift tests (P1-C) are the ground truth; any diff means
  the refactor changed behavior and must be re-scoped.

## Non-goals

- No plugin loader / dynamic adapter registration at runtime. Adapters are
  compile-time contributions from packages inside the monorepo. Third-party
  adapters (a `vetlock-adapter-elixir` npm package) are a post-v1 idea and
  need a separate ADR when there's demand.
- No adapter-configurable "universal" detectors. If a detector cares about
  ecosystem-specific syntax, it belongs to that ecosystem — no
  configuration flag lets a universal detector pretend it's cross-language.
