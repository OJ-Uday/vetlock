/**
 * CAPABILITY-MAP types (PACKET-VETLOCK-ASSURANCE §3.5, PACKET-VETLOCK-STARTUP §3.5).
 *
 * The map is the machine-readable enumeration of everything the completeness doctrine
 * requires the engine to cover. This file defines the value shapes; `data.json` is the
 * source of truth; `index.ts` and `coverage-gate.ts` are the consumers.
 *
 * Naming: a "member" is either a sink OR an entry-point; the coverage gate treats them
 * uniformly. Every enumerated member must be proven covered by a surviving-mutation test
 * (packet §5 P2 done-gate). Un-enumerated members are the search target — not a failure,
 * but a newly-found uncovered member blocks the build until enumerated+covered.
 */

/** Stable ids for the nine capability classes named in packet §3.5. */
export type CapabilityClassId =
  | 'code-execution'
  | 'net-egress'
  | 'fs-write'
  | 'env/secret-read'
  | 'persistence'
  | 'obfuscation/decode'
  | 'crypto-mine'
  | 'clipboard'
  | 'process-enumeration';

/** A single sink under a capability class — the runtime primitive that achieves the
 *  capability. Sinks are the enumeration floor; the dataflow chokepoint can catch novel
 *  spellings for free (ADR-0011), but each enumerated sink must have a covering test. */
export interface Sink {
  /** Sink id, unique within its class. Slug-safe for use in test names and report ids. */
  readonly id: string;
  /** One-line human-readable description; renders in the report. */
  readonly description: string;
}

/** Per-class record in the JSON artifact. */
export interface CapabilityClass {
  /** The enumerated sinks for this class. Empty means "TBD — panel enumeration"; the
   *  gate treats zero sinks as zero enumerated members (0/0 coverage, not failure). */
  readonly sinks: readonly Sink[];
  /** Optional annotation for classes whose sinks aren't fully enumerated yet. */
  readonly note?: string;
}

/** An entry point — a way attacker code gains execution, or a way a dependency enters
 *  the graph. The gate treats every entry-point as a first-class enumerated member. */
export interface EntryPoint {
  readonly id: string;
  readonly description: string;
}

/** The two entry-point axes from packet §3.5:
 *   • execution — how a package's code runs at all (lifecycle scripts, main/module, etc.)
 *   • graph     — how a package enters the dependency graph (direct/transitive/git/…) */
export interface EntryPoints {
  readonly execution: readonly EntryPoint[];
  readonly graph: readonly EntryPoint[];
}

/** The whole map — one object, one JSON file, one loader. */
export interface CapabilityMap {
  readonly version: string;
  readonly notes: string;
  readonly classes: Readonly<Record<CapabilityClassId, CapabilityClass>>;
  readonly entryPoints: EntryPoints;
}

/** Per-class report from the coverage gate. */
export interface PerClassCoverage {
  readonly classId: CapabilityClassId;
  readonly covered: number;
  readonly total: number;
  /** Integer percent, floored. 100 iff covered === total. */
  readonly percent: number;
  /** Ids of enumerated sinks that haven't been asserted covered. Empty when at 100%. */
  readonly missing: readonly string[];
}

/** The gate's overall report. `entryPoints.execution` and `entryPoints.graph` are
 *  reported alongside classes so the same gate covers both axes of completeness. */
export interface CoverageReport {
  readonly perClass: readonly PerClassCoverage[];
  readonly entryPoints: {
    readonly execution: {
      readonly covered: number;
      readonly total: number;
      readonly percent: number;
      readonly missing: readonly string[];
    };
    readonly graph: {
      readonly covered: number;
      readonly total: number;
      readonly percent: number;
      readonly missing: readonly string[];
    };
  };
  readonly overall: {
    readonly covered: number;
    readonly total: number;
    readonly percent: number;
  };
}
