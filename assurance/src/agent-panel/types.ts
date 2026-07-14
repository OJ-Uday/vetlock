/**
 * Types for the adversarial-agent panel driver (PACKET-VETLOCK-ASSURANCE §5 P4).
 *
 * The panel is a perpetual red-team: a scheduled job that spawns cheap-model agents that
 * propose novel evasion hypotheses against the CAPABILITY-MAP, generates defanged
 * fixtures, runs them through the harness, and files any that evade as coverage gaps.
 *
 * Every shape here is a plain value (no functions, no class instances) so PanelReport can
 * be serialized to `assurance/report/panel-report.json` losslessly and the same bytes can
 * feed a downstream reader (a human, a CI job, another agent).
 */

import type { RunOutcome } from '../oracles/types.js';

/**
 * One entry in the CAPABILITY-MAP: (class, enumerated sink id, kind, description). This is
 * the mock shape used by the panel until Wave 1B-H (`docs/CAPABILITY-MAP.md` +
 * `capability-map.json`) merges — see capability-map.ts.
 */
export interface CapabilityMapEntry {
  readonly class: string;
  readonly sinkId: string;
  readonly kind: 'sink' | 'entry-point';
  readonly description: string;
}

/** The whole map. */
export interface CapabilityMap {
  readonly entries: readonly CapabilityMapEntry[];
}

/** A single hypothesized evasion, produced by an EvasionAgent. */
export interface EvasionHypothesis {
  /** Unique id (stable across identical (agent, class, seed) tuples). */
  readonly id: string;
  /** Capability class this proposes to evade (must match a CAPABILITY-MAP entry). */
  readonly targetClass: string;
  /** Enumerated sink id from the CAPABILITY-MAP entry. */
  readonly targetSink: string;
  /** Human-readable transform description. */
  readonly technique: string;
  /** Defanged source of the mutated fixture. Scanned by scanForDefangViolations. */
  readonly generatedFixture: string;
  /** Agent id or 'stub'. */
  readonly proposedBy: string;
  /** Why the agent thinks this evades. */
  readonly rationale: string;
}

/** One hypothesis run through the harness. */
export interface EvasionRun {
  readonly hypothesis: EvasionHypothesis;
  readonly outcome: RunOutcome;
  /** True iff the finding-survives oracle failed on a verdict-bearing outcome — the mutated
   *  fixture parsed cleanly but the detector missed the target class. Crash/timeout/OOM
   *  outcomes are NOT counted as evasions (they're robustness gaps, a different failure
   *  mode); the outcome is still recorded so a triage reviewer can classify. */
  readonly evaded: boolean;
}

/** A rejected hypothesis (defang guard flagged its fixture). */
export interface RejectedHypothesis {
  readonly hypothesis: EvasionHypothesis;
  /** Why the hypothesis was rejected (defang violations formatted). */
  readonly reason: string;
}

/** The stamped panel report. */
export interface PanelReport {
  /** ISO timestamp of the run (caller supplies via `now` to keep tests deterministic). */
  readonly runAt: string;
  /** Which agent produced these hypotheses (e.g. 'stub'). */
  readonly agent: string;
  /** Seed echoed into every run's bounds. */
  readonly seed: number;
  /** Total hypotheses proposed across all classes. */
  readonly hypothesesProposed: number;
  /** Hypotheses that cleared the defang guard and reached the runner. */
  readonly hypothesesAdmitted: number;
  /** Hypotheses rejected upstream (defang guard flagged them). */
  readonly hypothesesRejected: number;
  /** Runs where evaded === true (strict: verdict-bearing outcome missing the target class). */
  readonly evasionsFound: number;
  /** All admitted runs. */
  readonly runs: readonly EvasionRun[];
  /** All rejected hypotheses. */
  readonly rejected: readonly RejectedHypothesis[];
}

/**
 * The abstract interface every agent implements. Stub is synchronous-in-spirit but the
 * signature is async so the future Claude-agent implementation (which awaits Anthropic's
 * API) fits without a signature change.
 */
export interface EvasionAgent {
  /** Stable agent id — appears in PanelReport.agent and EvasionHypothesis.proposedBy. */
  readonly id: string;
  /**
   * Propose up to `max` evasion hypotheses targeting `entry`. The panel calls this once
   * per CAPABILITY-MAP entry. Callers pass `seed` so agents can seed any internal RNG.
   */
  propose(
    entry: CapabilityMapEntry,
    seed: number,
    max: number,
  ): Promise<readonly EvasionHypothesis[]>;
}

/** Panel driver options. */
export interface PanelOptions {
  /** Which agent to use — stub for CI, or a future 'claude' agent for scheduled runs. */
  readonly agent: EvasionAgent;
  /** The CAPABILITY-MAP the panel targets. */
  readonly capabilityMap: CapabilityMap;
  /** Maximum hypotheses per capability class per run. */
  readonly maxHypothesesPerClass: number;
  /** Deterministic seed. */
  readonly seed: number;
  /** Optional clock injection for byte-deterministic tests. Defaults to `new Date()`. */
  readonly now?: () => Date;
}
