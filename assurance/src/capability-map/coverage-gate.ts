/**
 * CoverageGate — packet §5 P2 done-gate.
 *
 * Tracks which enumerated CAPABILITY-MAP members have been proven covered by tests.
 * Doesn't itself run the tests — it exposes an `assertMemberCovered(class, member, covered)`
 * that a driver (evasion-mutation runner, corpus scanner, agent panel) calls once per
 * enumerated member. `enforce()` throws if any enumerated member is uncovered.
 *
 * Terminology:
 *   • class member = a Sink under a capability class (e.g. "eval" under "code-execution").
 *   • entry-point member = an EntryPoint under `execution` or `graph`.
 *   • enumerated = present in data.json (or the engine-tree map when it lands).
 *   • covered    = assertMemberCovered(..., true) was called at least once for it.
 *
 * The gate treats missing coverage as a build-breaker (packet §4 metrics: "Class coverage
 * gate: 100% of enumerated members covered"). Un-enumerated members are the search
 * target — the gate can't blame you for not covering something the map doesn't name.
 */

import type {
  CapabilityClass,
  CapabilityClassId,
  CapabilityMap,
  CoverageReport,
  PerClassCoverage,
} from './types.js';

/** The two entry-point axes as a small union — used by callers of `assertMemberCovered`
 *  when the member is an entry-point rather than a sink. */
export type EntryPointAxis = 'execution' | 'graph';

/** A member id, tagged with its bucket. Kept as an internal shape; callers use the
 *  positional-arg API of `assertMemberCovered`/`assertEntryPointCovered`. */
type MemberKey =
  | { kind: 'sink'; classId: CapabilityClassId; sinkId: string }
  | { kind: 'entry-point'; axis: EntryPointAxis; entryId: string };

function memberKeyString(k: MemberKey): string {
  return k.kind === 'sink' ? `sink:${k.classId}#${k.sinkId}` : `entry:${k.axis}#${k.entryId}`;
}

export class CoverageGate {
  private readonly map: CapabilityMap;
  private readonly covered = new Set<string>();

  constructor(map: CapabilityMap) {
    this.map = map;
  }

  /** Get the underlying map — read-only accessor for reports/drivers. */
  get capabilityMap(): CapabilityMap {
    return this.map;
  }

  /**
   * Mark an enumerated sink covered (or uncovered when `covered=false`, mainly for tests).
   *
   * Throws if the sink isn't enumerated under the given class — refusing to accept
   * coverage for a member the map doesn't know about is intentional: it guards against
   * a "covered" bookkeeping error masking an actual gap.
   */
  assertMemberCovered(classId: CapabilityClassId, sinkId: string, covered: boolean): void {
    const cls = this.map.classes[classId];
    if (!cls) {
      throw new Error(`[coverage-gate] unknown class "${classId}"`);
    }
    if (!cls.sinks.some((s) => s.id === sinkId)) {
      throw new Error(
        `[coverage-gate] sink "${sinkId}" is not enumerated under class "${classId}" — ` +
          'add it to the CAPABILITY-MAP first (packet §3.5)',
      );
    }
    const key = memberKeyString({ kind: 'sink', classId, sinkId });
    if (covered) this.covered.add(key);
    else this.covered.delete(key);
  }

  /**
   * Mark an enumerated entry-point covered. Same enforcement as `assertMemberCovered`:
   * the entry-point must be enumerated under the given axis.
   */
  assertEntryPointCovered(axis: EntryPointAxis, entryId: string, covered: boolean): void {
    const axisList = this.map.entryPoints[axis];
    if (!axisList.some((e) => e.id === entryId)) {
      throw new Error(
        `[coverage-gate] entry-point "${entryId}" is not enumerated under axis "${axis}" — ` +
          'add it to the CAPABILITY-MAP first (packet §3.5)',
      );
    }
    const key = memberKeyString({ kind: 'entry-point', axis, entryId });
    if (covered) this.covered.add(key);
    else this.covered.delete(key);
  }

  /** Snapshot the current coverage as a structured report. Pure — no side effects. */
  report(): CoverageReport {
    const perClass: PerClassCoverage[] = [];
    let coveredTotal = 0;
    let totalTotal = 0;

    for (const [classId, cls] of Object.entries(this.map.classes) as [
      CapabilityClassId,
      CapabilityClass,
    ][]) {
      const total = cls.sinks.length;
      const missing: string[] = [];
      let covered = 0;
      for (const sink of cls.sinks) {
        const key = memberKeyString({ kind: 'sink', classId, sinkId: sink.id });
        if (this.covered.has(key)) covered++;
        else missing.push(sink.id);
      }
      perClass.push({
        classId,
        covered,
        total,
        percent: total === 0 ? 100 : Math.floor((covered / total) * 100),
        missing,
      });
      coveredTotal += covered;
      totalTotal += total;
    }

    const execution = this.axisCoverage('execution');
    const graph = this.axisCoverage('graph');
    coveredTotal += execution.covered + graph.covered;
    totalTotal += execution.total + graph.total;

    return {
      perClass,
      entryPoints: { execution, graph },
      overall: {
        covered: coveredTotal,
        total: totalTotal,
        percent: totalTotal === 0 ? 100 : Math.floor((coveredTotal / totalTotal) * 100),
      },
    };
  }

  private axisCoverage(axis: EntryPointAxis) {
    const list = this.map.entryPoints[axis];
    const total = list.length;
    const missing: string[] = [];
    let covered = 0;
    for (const e of list) {
      const key = memberKeyString({ kind: 'entry-point', axis, entryId: e.id });
      if (this.covered.has(key)) covered++;
      else missing.push(e.id);
    }
    return {
      covered,
      total,
      percent: total === 0 ? 100 : Math.floor((covered / total) * 100),
      missing,
    };
  }

  /**
   * The gate itself — throws a rich error naming each uncovered enumerated member.
   * Called by `coverage-gate-fails-on-uncovered-sink.test` (packet §5 P2 done-gate name).
   *
   * A class whose sinks[] is empty (TBD panel enumeration) contributes zero enumerated
   * members and cannot fail the gate; it's a search target, not a covered/uncovered
   * question. This is the packet's "unknowns are the search target, not a failure"
   * clause (§4 class-coverage metric).
   */
  enforce(): void {
    const report = this.report();
    const missing: string[] = [];
    for (const c of report.perClass) {
      for (const m of c.missing) missing.push(`class ${c.classId}: sink "${m}"`);
    }
    for (const m of report.entryPoints.execution.missing) {
      missing.push(`entry-point execution: "${m}"`);
    }
    for (const m of report.entryPoints.graph.missing) {
      missing.push(`entry-point graph: "${m}"`);
    }
    if (missing.length === 0) return;
    const preview = missing.slice(0, 10).join('; ');
    const suffix = missing.length > 10 ? ` (+${missing.length - 10} more)` : '';
    throw new Error(
      `[coverage-gate] ${missing.length} enumerated member(s) uncovered: ${preview}${suffix}`,
    );
  }
}
