# ADR 0003 (assurance): Bounded, sandboxed, deterministic-where-possible engine runs

**Status:** Accepted, 2026-07-14

Scope: `@vetlock/assurance` only.

## Context

The harness must feed inputs that are *designed to* hang, crash, or exhaust memory. If we
call the engine in-process:

- An infinite loop in a detector on a hostile input hangs the harness process too — the
  distinction between "engine hung" and "harness hung" is lost.
- A native segfault (via `.node` addon or WASM bug) takes down the harness.
- Heap exhaustion inside the engine crashes the harness before oracles can observe.

The whole point of the harness is to *detect* those outcomes as bounded, categorical results.
Also: findings must be reproducible. A property test that fails once but never again is worse
than useless.

## Decision

Every engine invocation goes through a **bounded, sandboxed runner** with a stable contract:

```ts
type AnalyzeFn = (input: AnalysisInput, ctl: RunControl) => Promise<Findings>;

type RunOutcome =
  | { kind: 'ok'; findings: Findings; wallMs: number; peakRssBytes: number }
  | { kind: 'timeout'; wallMs: number }
  | { kind: 'oom'; peakRssBytes: number }
  | { kind: 'crash'; error: SerializedError; wallMs: number }
  | { kind: 'fail-safe'; reason: string; wallMs: number };  // engine returned but signaled it gave up

interface Bounds {
  wallMs: number;      // hard wall-clock cap
  heapMb: number;      // hard heap cap (--max-old-space-size, worker_threads)
  seed: number;        // for any RNG the input generators use
}
```

Runner properties:

1. **Worker-thread isolated.** Every analysis runs in a `worker_threads.Worker` with
   `resourceLimits.maxOldGenerationSizeMb = bounds.heapMb`. A native crash in the worker
   surfaces as `kind: 'crash'`; a heap blow surfaces as `kind: 'oom'`. The parent (harness)
   is never taken down.
2. **Timeboxed.** A wall-clock timer terminates the worker on expiry. Timeout is
   `kind: 'timeout'`, not a crash. This is essential: a real hang must *look like* a hang,
   not an infinite CI job.
3. **Seeded RNG passthrough.** Generators receive `bounds.seed` and derive all randomness
   from it. The seed is echoed in every `RunOutcome` and in the assurance report so a failure
   replays byte-identically.
4. **Zero test hooks in engine.** The runner speaks to the engine only through its public
   analysis surface (ADR-0001).

## Fail-safe convention

The engine itself must have a "give-up" path: when a detector encounters an internal error,
it emits a `BLOCK` finding with reason `analysis-failed`, rather than swallowing the
exception. The harness distinguishes that from a genuine crash: a `fail-safe` outcome is
*safe* (the engine failed toward blocking, which is what we want). A `crash` is *not safe*
(the engine let an exception escape) and is an oracle failure.

This ADR does not implement the engine's fail-safe path — that's an engine change enforced
by the harness's `oracleFailSafe` in P1. It documents the harness's expectation.

## Rationale

- **Detection of hangs requires a bound.** Without one, "hang" and "slow test" are
  indistinguishable and the harness eventually gets muted.
- **Detection of OOM requires a bound.** Node's default heap is process-wide; without a
  per-run cap, an OOM in analysis crashes the harness first.
- **Sandboxing keeps the harness alive.** Worker isolation means one input can crash the
  worker without touching the parent. The harness itself must be more robust than what it
  tests (packet rule #5).
- **Determinism keeps the harness credible.** A flaky harness cries wolf and gets ignored.
  Seeded generation + echoed seed makes every failure replayable.

## Consequences

- Every engine call is slower (worker startup ~50-200ms + serialization overhead).
  Acceptable: the harness is not on the user-facing hot path; it's a CI + scheduled asset.
- Findings + timings must be structured-clonable across worker boundaries. Practically:
  no functions, no `Error` instances directly (serialize to `SerializedError`), no cyclic
  refs. The `Findings` shape is a plain JSON value.
- `Date.now()` / `Math.random()` inside generators are banned — every timestamp comes from
  the caller and every random draw from the seeded PRNG. The oracle set + runner assert this
  by construction (the seed is the only randomness source).

## Alternatives considered

- **In-process analysis + `try/catch`.** Rejected: catches thrown errors but not hangs,
  native crashes, or OOM.
- **Child process per run.** Rejected in favor of `worker_threads`: cheaper startup, still
  gives us `resourceLimits.maxOldGenerationSizeMb` for heap caps. Reconsider if native
  crashes still leak to the parent under some Node version.
- **VM contexts (`vm.runInNewContext`).** Rejected: does not isolate native crashes and
  does not provide independent heap accounting.
