# ADR 0011: The Completeness Doctrine

**Status:** Accepted, 2026-07-13 (governing law — supersedes ad-hoc detector expansion)

## Context

vetlock's detector surface grew organically. When a red-team review found an evasion (e.g.
`process["env"]` computed, `require.call`, `Reflect.get(process.env)`), the historical response
was to patch the specific spelling and move on. This is a losing game — attackers just publish
the next spelling. A detector that matches `child_process.exec` but not `require("child_process").exec`
is, from an attacker's perspective, no detector at all.

The intellectual core of vetlock's engine must therefore change from *matching signatures* to
*covering capability classes*. This ADR states that principle, its enforcement mechanism, and the
consequences we accept for adopting it.

## Decision

**Detectors target capability *classes*, not signatures.** For every dangerous capability there
is a *finite, enumerable* set of **sinks** (the runtime primitives that achieve it) and a *finite,
enumerable* set of **entry points** (the ways attacker code executes at all, and the ways a
dependency enters the graph). vetlock covers the **whole set** — at the narrowest **chokepoint**
it can — and *measures* that coverage. Closing one sink while its siblings stay open is, by
definition, an incomplete fix.

### Two axes of completeness

Both axes are enumerated in a machine-readable **CAPABILITY-MAP** (`packages/detectors/src/
capability-map.json`, source of truth; `docs/CAPABILITY-MAP.md` is generated from it).

1. **Capability sinks — what dangerous thing does the code do?**

   Each capability class enumerates every primitive that achieves it. Examples:

   - `code-execution` = { `eval`, `new Function`, `vm.*` (runInThisContext, runInNewContext,
     Script, SourceTextModule…), `child_process.*` (exec, execFile, spawn, fork, execSync,
     spawnSync…), `worker_threads`, `process.binding`, native `.node` load, `WebAssembly.
     instantiate/compile`, dynamic `require(<computed>)`, dynamic `import(<computed>)`,
     `module.constructor` }.
   - `net-egress` = { `http.request`, `https.request`, `net.Socket`, `dgram.createSocket`,
     `tls.connect`, `dns.lookup` / `dns.resolve` (covert exfil channel), `fetch`, `undici.*`,
     `ws` (WebSocket), … }.
   - `fs-write`, `secret-read`, `persistence`, `obfuscation-decode`, `crypto-mine`, `clipboard`,
     `process-enumeration` — each get their own exhaustive sink set.

   The dataflow layer (constant folding + alias resolution, already built) means semantic
   equivalents collapse to the same sink at analysis time — that is how a *class* is caught,
   not a spelling.

2. **Entry points — how does package code run at all?**

   Enumerated exhaustively:

   - **Execution triggers:** lifecycle scripts (`preinstall`, `install`, `postinstall`,
     `prepare`, `prepublish`, `prepack`…), `main`/`module`/`exports`/`bin` referenced files,
     top-level / import side-effects, test hooks, native `gyp` build, bundled `node_modules`
     (recursed).
   - **Graph entry points:** `dependencies`, `devDependencies`, `optionalDependencies`,
     `peerDependencies`, `bundledDependencies`, `git+`/`github:`/`bitbucket:`/`gitlab:` URLs,
     tarball URLs, `link:`/`file:` refs, yarn/pnpm `npm:<alias>@<real>` alias entries.

   Every entry point is an attack surface. Every one must have a detector attached in the
   CAPABILITY-MAP.

### Chokepoint over enumeration where possible

Prefer detecting at the single place all variants converge — e.g. "any value that flows to a
module-resolution call" via the existing dataflow layer — so novel syntax *within a class* is
caught for free. Then enumerate the residual sinks that can't be reduced to a chokepoint.
Enumeration is the floor; chokepoints are the ceiling. When both are viable, the chokepoint
wins because it generalises past the current attacker's syntax.

## Enforcement

The doctrine is a **tested, CI-gated** invariant, not a convention.

**`capability-map.json`** — the machine-readable source of truth. Each entry:
```json
{
  "class": "code-execution",
  "kind": "sink",
  "id": "child_process.exec",
  "aliases": ["require('child_process').exec", "require('node:child_process').exec"],
  "detectors": ["exec.new-module"],
  "tests": ["packages/core/test/capabilities.test.ts::exec-modules"],
  "corpus_refs": ["shai-hulud-2025", "ua-parser-2021"],
  "chokepoint": "capabilities.execModules"
}
```

**`capability-map-coverage.test.ts`** — fails when any enumerated sink/entry-point:
- has zero detectors bound, OR
- has zero tests bound, OR
- has zero corpus refs where the class is exercised (soft warn during transition; hard fail post-P1).

**`capability-map-generated.test.ts`** — regenerates `docs/CAPABILITY-MAP.md` from
`capability-map.json` and fails if the doc drifted from the source (same doctrine as our
DETECTIONS.md generation gate).

When the assurance harness (`PACKET-VETLOCK-ASSURANCE.md`) or a red-teamer finds a new evasion,
the fix is procedural:

1. Add the sink/entry-point to `capability-map.json`.
2. Add a detector binding (or a test binding, if the existing detector already covers it via a
   chokepoint).
3. Coverage gate goes green again.

The class is *whole* the moment coverage returns to 100%. Adding a signature without touching
the map is now a review-visible mistake.

## Rationale

- **Adversarial durability.** A red-teamer will always find the next spelling; the doctrine
  ensures that "finding it" is a mechanical map update, not a new engineering effort each time.
- **Publishable coverage number.** vetlock's public claim shifts from "we implement N detectors"
  (rewards feature count) to "we cover N capability classes and M sinks/entry-points" (rewards
  completeness). The number is CI-enforced, so we cannot lie about it.
- **Enables OSIF alignment.** The `entry_point` taxonomy in the OSIF open incident format
  (ADR 0013) is *the same enumeration* as this map — one source, three consumers: doctrine,
  benchmark, OSIF.

## Consequences

- Every future detector work must land the `capability-map.json` change in the same PR as the
  detector. Coverage-gate failure = the PR does not merge.
- Historical detectors are backfilled into the map during P1 (this is the meaning of "P1
  operationalises the doctrine"). Until backfill is complete, the coverage gate runs in
  soft-warn mode; after P1 close-gate, it is hard-fail.
- Some detectors have no natural chokepoint (e.g. `install.script-added` — the lifecycle-script
  field name space is finite and enumerable, but there's no "flow" to chokepoint against).
  Those are enumerate-only entries in the map. That is expected and correct — the map admits
  both shapes.
- The doctrine does not eliminate false positives; it eliminates *false negatives within a
  covered class*. FP work continues to happen in the escalation-rules layer.

## Non-goals

- The doctrine does not promise coverage of undiscovered *classes*. It promises coverage of
  every sink/entry-point within a class we've named. New classes (e.g. a novel supply-chain
  vector) are added by naming them and adding their sink set — a much smaller change than
  discovering-then-patching each spelling.
- The doctrine does not replace threat-modelling (`docs/THREAT-MODEL.md`). Threat-modelling
  names classes; the doctrine ensures each named class is *whole*.
