/**
 * Coverage-gate behavior tests + packet §5 P2 done-gate test
 * (`coverage-gate-fails-on-uncovered-sink.test`).
 *
 * The gate is the enforcer of packet §4's Class-coverage metric:
 *   "Gate: 100% of enumerated members covered".
 *
 * These tests pin the semantics of assertMemberCovered / assertEntryPointCovered / report
 * / enforce, using the real CAPABILITY-MAP so we're testing the same data path the P2
 * coverage gate will use in CI.
 */

import { describe, it, expect } from 'vitest';
import {
  CAPABILITY_CLASS_IDS,
  CoverageGate,
  loadCapabilityMap,
  type CapabilityMap,
} from '../../src/capability-map/index.js';

/** Cover every enumerated sink + entry-point. Used by the "0% → 100%" test and by any
 *  test that wants a fully-covered baseline before flipping one member off.
 *
 *  Iterates OVER THE MAP'S ACTUAL CLASSES, not the packet §3.5 canonical nine — STARTUP's
 *  shipped artifact enumerates additional classes (fs-read, secret-read, integrity,
 *  advisory-known-vuln, dep-graph-anomaly) that we want counted, and may add more in
 *  future without breaking this helper. */
function coverEverything(gate: CoverageGate, map: CapabilityMap): void {
  for (const classId of Object.keys(map.classes) as (keyof CapabilityMap['classes'])[]) {
    for (const sink of map.classes[classId]?.sinks ?? []) {
      gate.assertMemberCovered(classId, sink.id, true);
    }
  }
  for (const e of map.entryPoints.execution) {
    gate.assertEntryPointCovered('execution', e.id, true);
  }
  for (const e of map.entryPoints.graph) {
    gate.assertEntryPointCovered('graph', e.id, true);
  }
}

describe('CoverageGate — starting state', () => {
  it('a fresh gate reports 0% overall coverage', () => {
    const map = loadCapabilityMap();
    const gate = new CoverageGate(map);
    const r = gate.report();
    expect(r.overall.covered).toBe(0);
    expect(r.overall.total).toBeGreaterThan(0);
    expect(r.overall.percent).toBe(0);
  });

  it('per-class report starts with 0 covered, correct total, and every sink in missing[]', () => {
    const map = loadCapabilityMap();
    const gate = new CoverageGate(map);
    const r = gate.report();
    const codeExec = r.perClass.find((c) => c.classId === 'code-execution');
    expect(codeExec).toBeDefined();
    expect(codeExec!.covered).toBe(0);
    expect(codeExec!.total).toBe(map.classes['code-execution'].sinks.length);
    expect(codeExec!.missing.length).toBe(codeExec!.total);
  });
});

describe('CoverageGate — assertMemberCovered semantics', () => {
  it('moving a member to covered=true increments covered count for that class', () => {
    const map = loadCapabilityMap();
    const gate = new CoverageGate(map);
    gate.assertMemberCovered('code-execution', 'eval', true);
    const r = gate.report();
    const codeExec = r.perClass.find((c) => c.classId === 'code-execution')!;
    expect(codeExec.covered).toBe(1);
    expect(codeExec.missing).not.toContain('eval');
  });

  it('moving a member back to covered=false removes it', () => {
    const map = loadCapabilityMap();
    const gate = new CoverageGate(map);
    gate.assertMemberCovered('code-execution', 'eval', true);
    gate.assertMemberCovered('code-execution', 'eval', false);
    const r = gate.report();
    const codeExec = r.perClass.find((c) => c.classId === 'code-execution')!;
    expect(codeExec.covered).toBe(0);
    expect(codeExec.missing).toContain('eval');
  });

  it('idempotent — same member marked covered twice counts once', () => {
    const map = loadCapabilityMap();
    const gate = new CoverageGate(map);
    gate.assertMemberCovered('code-execution', 'eval', true);
    gate.assertMemberCovered('code-execution', 'eval', true);
    const r = gate.report();
    expect(r.perClass.find((c) => c.classId === 'code-execution')!.covered).toBe(1);
  });

  it('rejects a sink id that is not enumerated under the given class', () => {
    const map = loadCapabilityMap();
    const gate = new CoverageGate(map);
    expect(() =>
      gate.assertMemberCovered('code-execution', 'not-a-real-sink-id', true),
    ).toThrow(/not enumerated/);
  });

  it('rejects an unknown class id', () => {
    const map = loadCapabilityMap();
    const gate = new CoverageGate(map);
    // Cast through unknown so TS accepts the deliberately-bogus id.
    const bogus = 'nonexistent-class' as unknown as 'code-execution';
    expect(() => gate.assertMemberCovered(bogus, 'eval', true)).toThrow(/unknown class/);
  });
});

describe('CoverageGate — assertEntryPointCovered semantics', () => {
  it('covering an execution entry-point shows in the execution axis report', () => {
    const map = loadCapabilityMap();
    const gate = new CoverageGate(map);
    // Use the first-enumerated execution entry-point rather than a hardcoded id — STARTUP's
    // shipped artifact uses prefixed ids (install-hook:preinstall etc.), the assurance scaffold
    // used unprefixed (lifecycle-preinstall). Either shape passes this test.
    const firstExec = map.entryPoints.execution[0]?.id;
    if (!firstExec) throw new Error('capability-map has no execution entry-points');
    gate.assertEntryPointCovered('execution', firstExec, true);
    const r = gate.report();
    expect(r.entryPoints.execution.covered).toBe(1);
    expect(r.entryPoints.execution.missing).not.toContain(firstExec);
  });

  it('covering a graph entry-point shows in the graph axis report', () => {
    const map = loadCapabilityMap();
    const gate = new CoverageGate(map);
    const firstGraph = map.entryPoints.graph[0]?.id;
    if (!firstGraph) throw new Error('capability-map has no graph entry-points');
    gate.assertEntryPointCovered('graph', firstGraph, true);
    const r = gate.report();
    expect(r.entryPoints.graph.covered).toBe(1);
    expect(r.entryPoints.graph.missing).not.toContain(firstGraph);
  });

  it('rejects an entry-point id that is not enumerated under the given axis', () => {
    const map = loadCapabilityMap();
    const gate = new CoverageGate(map);
    expect(() => gate.assertEntryPointCovered('execution', 'not-a-real-entry', true)).toThrow(
      /not enumerated/,
    );
  });
});

describe('CoverageGate — report() shape', () => {
  it('report shape includes perClass, entryPoints.execution/graph, and overall', () => {
    const map = loadCapabilityMap();
    const gate = new CoverageGate(map);
    const r = gate.report();
    expect(r).toHaveProperty('perClass');
    expect(r).toHaveProperty('entryPoints.execution');
    expect(r).toHaveProperty('entryPoints.graph');
    expect(r).toHaveProperty('overall.covered');
    expect(r).toHaveProperty('overall.total');
    expect(r).toHaveProperty('overall.percent');
  });

  it('overall totals equal sum of per-class + axis totals', () => {
    const map = loadCapabilityMap();
    const gate = new CoverageGate(map);
    const r = gate.report();
    const sumClasses = r.perClass.reduce((n, c) => n + c.total, 0);
    const sumAxes = r.entryPoints.execution.total + r.entryPoints.graph.total;
    expect(r.overall.total).toBe(sumClasses + sumAxes);
  });

  it('overall percent is 100 when everything is covered', () => {
    const map = loadCapabilityMap();
    const gate = new CoverageGate(map);
    coverEverything(gate, map);
    const r = gate.report();
    expect(r.overall.covered).toBe(r.overall.total);
    expect(r.overall.percent).toBe(100);
  });

  it('a class with zero enumerated sinks reports 100% (search target, not gate failure)', () => {
    const map = loadCapabilityMap();
    const gate = new CoverageGate(map);
    const r = gate.report();
    // Any class with an empty sinks[] should report 100 to reflect "no enumerated members
    // to cover" — this is the packet §4 "unknowns are the search target, not a failure" clause.
    for (const c of r.perClass) {
      if (c.total === 0) expect(c.percent).toBe(100);
    }
  });
});

describe('coverage-gate-fails-on-uncovered-sink (packet §5 P2 done-gate name)', () => {
  it('enforce() throws when a known sink is uncovered, naming the specific sink', () => {
    const map = loadCapabilityMap();
    const gate = new CoverageGate(map);
    coverEverything(gate, map);
    // Flip ONE known sink back to uncovered. Pick the FIRST enumerated code-execution sink
    // dynamically — STARTUP shipped `child_process` as an aggregate id, the scaffold used
    // `child_process.execFile`. Either passes.
    const firstSink = map.classes['code-execution']?.sinks[0]?.id;
    if (!firstSink) throw new Error('code-execution has no enumerated sinks');
    gate.assertMemberCovered('code-execution', firstSink, false);

    let caught: Error | undefined;
    try {
      gate.enforce();
    } catch (e) {
      caught = e as Error;
    }
    expect(caught).toBeInstanceOf(Error);
    // The gate must name the specific missing sink so a human can act on the failure
    // without re-running with more logging.
    expect(caught!.message).toContain(firstSink);
    expect(caught!.message).toContain('code-execution');
  });

  it('enforce() throws when an execution entry-point is uncovered, naming the entry', () => {
    const map = loadCapabilityMap();
    const gate = new CoverageGate(map);
    coverEverything(gate, map);
    const firstExec = map.entryPoints.execution[0]?.id;
    if (!firstExec) throw new Error('capability-map has no execution entry-points');
    gate.assertEntryPointCovered('execution', firstExec, false);

    // Escape any regex metacharacters that STARTUP-prefixed ids may contain (e.g. ':').
    const escaped = firstExec.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    expect(() => gate.enforce()).toThrow(new RegExp(escaped));
  });

  it('enforce() throws when a graph entry-point is uncovered, naming the entry', () => {
    const map = loadCapabilityMap();
    const gate = new CoverageGate(map);
    coverEverything(gate, map);
    const firstGraph = map.entryPoints.graph[0]?.id;
    if (!firstGraph) throw new Error('capability-map has no graph entry-points');
    gate.assertEntryPointCovered('graph', firstGraph, false);
    const escaped = firstGraph.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    expect(() => gate.enforce()).toThrow(new RegExp(escaped));
  });

  it('enforce() reports a count when many members are missing', () => {
    const map = loadCapabilityMap();
    const gate = new CoverageGate(map);
    // Cover nothing — every enumerated member is missing.
    const totalEnumerated = gate.report().overall.total;
    expect(totalEnumerated).toBeGreaterThan(10);

    let msg = '';
    try {
      gate.enforce();
    } catch (e) {
      msg = (e as Error).message;
    }
    // The message should reflect the (large) number of missing members.
    expect(msg).toMatch(/enumerated member\(s\) uncovered/);
  });

  it('enforce() is silent when every enumerated member is covered', () => {
    const map = loadCapabilityMap();
    const gate = new CoverageGate(map);
    coverEverything(gate, map);
    expect(() => gate.enforce()).not.toThrow();
  });
});
