# ADR 0001 (assurance): The harness is a separate package; the engine is imported unchanged

**Status:** Accepted, 2026-07-14

Scope: `@vetlock/assurance` only. Not related to root ADR-0001 (which named the engine).

## Context

vetlock ships with 375 tests and closed 31 red-team exploits during a one-time campaign
(PACKET-VETLOCK-STARTUP §5.1). Both are *inside* the engine. The gaps a *continuous*
adversary needs to find are the ones a self-testing engine cannot find on itself: shortcuts,
special-cased code paths, hidden test hooks, "for the fixtures we know" patterns. Any test
mode inside `@vetlock/core` that makes the engine behave differently under the harness makes
the harness less trustworthy — the whole point is to prove the engine is safe *as shipped*.

## Decision

The assurance harness lives in its own workspace package, `@vetlock/assurance`, alongside
`packages/core`, `packages/detectors`, and `packages/cli`. It **imports the engine's real
public entrypoint** (the same `analyzePackage` / equivalent surface that ships to users) and
attacks that. No conditional branches inside `@vetlock/core` may check for the harness's
presence or behave differently under it.

Concretely:

1. `@vetlock/assurance` depends on `@vetlock/core` via the workspace protocol.
2. The engine exposes exactly the analysis surface it ships to consumers; no `test:` prefixed
   exports, no `internal` re-exports for the harness.
3. Any capability the harness needs to observe (e.g., internal timings, whether a detector
   errored) must be reachable through the *shipped* result shape or a documented
   general-purpose observability channel — not a harness-only hook.
4. The oracle set (see ADR-0003) operates entirely on the engine's public inputs and outputs.

## Rationale

- **Test hooks are attack surface.** The startup packet closed 31 real exploits; several
  turned on the engine's own convenience paths. A harness-only hatch is one more.
- **Assurance is only meaningful for the shipped artifact.** A green harness on a specially-
  configured engine tells us nothing about what users actually run.
- **Two-way independence keeps drift low.** The harness can be built, versioned, and rewritten
  without touching the engine; the engine can refactor without the harness silently rerouting
  around it (because the harness only sees the public surface).

## Consequences

- The harness cannot instrument engine internals. It observes verdicts, findings, timings,
  memory, and process signals — nothing else. Anything the harness needs to see must first
  become a public engine capability. Good pressure.
- Cross-package refactors of the engine's public shape will surface as harness build breaks.
  That is the intended feedback loop — it enforces stability of the shipped surface.
- The harness has to be *more* robust than the engine: it wraps engine calls in bounded,
  sandboxed processes (ADR-0003) because it must never itself crash on the inputs it feeds.

## Enforcement

- Workspace layout: `assurance/package.json` depends on `@vetlock/core` only via workspace
  protocol; no relative paths reaching into `packages/core/src/`.
- Grep guard (P1): a test asserts no `import` in `assurance/src/` uses a path containing
  `../packages/` — every engine reference must go through the package boundary.
- The oracle set is a pure module with no engine imports; it accepts a `RunOutcome` value
  object (ADR-0003) and returns booleans.
