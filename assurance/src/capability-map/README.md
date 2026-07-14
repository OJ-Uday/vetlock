# CAPABILITY-MAP (assurance-side artifact)

**Standalone assurance-side artifact.** This directory ships the machine-readable
CAPABILITY-MAP that the P2 coverage gate reads (packet §3.5, §5 P2 done-gate).

The canonical home for this data is `packages/detectors/src/capability-map.json` in the
engine tree, per `PACKET-VETLOCK-STARTUP.md` §3.5. Until STARTUP ships that file, the
assurance side ships and owns this copy so the P2 coverage gate isn't blocked.

## Files

- `data.json` — the source of truth. Enumerates every capability class, every sink,
  every execution entry-point, and every graph entry-point named in packet §3.5.
- `types.ts` — TypeScript shapes for the map, the sinks, and the coverage report.
- `loader.ts` — `loadCapabilityMap()` and `CAPABILITY_CLASS_IDS`; handles the
  engine-tree-vs-fallback resolution and validation.
- `coverage-gate.ts` — `CoverageGate` class; tracks which enumerated members have been
  proven covered, renders a `CoverageReport`, and exposes `enforce()` that throws when
  any enumerated member is uncovered.
- `index.ts` — barrel exports for consumers.

## Handoff to the engine tree (STARTUP §3.5)

`loadCapabilityMap()` implements a **preferential read**:

1. **First**, look for `<repo-root>/packages/detectors/src/capability-map.json` (the
   engine-tree location STARTUP §3.5 will provide). If present, read from there.
2. **Otherwise**, fall back to this directory's `data.json` and emit a one-time
   warning that the STARTUP artifact isn't there yet.

When STARTUP lands its map, no code change is needed on the assurance side — the
loader silently switches sources on the next process start. To move a sink or entry-point
into the engine's map, copy the entry from `data.json` and delete it from `data.json`
in the same commit. `data.json` becomes a *supplement* for anything the engine map
hasn't yet enumerated, then eventually empty (retained only as a compatibility shim).

## Why enumerate here now instead of waiting for STARTUP

Packet §5 P2's done-gate requires the coverage gate to be at 100% enumerated. If the
engine-tree map lands after the assurance-side gate, the gate can't run — the P2 slice
would sit blocked. Shipping the assurance-side artifact NOW as a **floor, not ceiling**
(packet §7) lets:

- P2 evasion-mutation tests wire against a real map today.
- The coverage gate assert 100% on the enumerated members it sees.
- The engine tree evolve at its own pace, without blocking assurance.

The "floor not ceiling" clause is important: `CoverageGate.enforce()` doesn't require the
map to be exhaustive — it requires every **enumerated** member to be covered. Newly-found
uncovered members are the search target (packet §4), not a gate failure.

## Un-enumerated classes

Only `code-execution` is fully enumerated in packet §3.5. The other eight classes
(`net-egress`, `fs-write`, `env/secret-read`, `persistence`, `obfuscation/decode`,
`crypto-mine`, `clipboard`, `process-enumeration`) ship with empty `sinks: []` and a
`note` field flagging them for panel enumeration. Empty classes contribute zero members
to the gate — they're search targets, not gate failures.

## Testing the shape

`assurance/test/capability-map/schema.test.ts` covers the invariants:

- The JSON parses.
- Every packet §3.5 class is present.
- Every sink id is unique within its class.
- Every entry-point id is unique within its axis.
- Every enumerated `code-execution` sink from the packet is present.

## Testing the gate

`assurance/test/capability-map/coverage-gate.test.ts` covers the behavior:

- Starts at 0% (nothing covered).
- `assertMemberCovered(cls, sink, true)` promotes a member.
- `report()` returns `{ perClass, entryPoints, overall }`.
- `enforce()` throws when any enumerated member is uncovered — this is the packet
  §5 P2 `coverage-gate-fails-on-uncovered-sink.test`.
