/**
 * Panel driver self-tests (packet §5 P4).
 *
 * The panel is the perpetual red-team's orchestration layer. These tests pin:
 *   - Stub agent determinism (same seed → identical hypotheses byte-for-byte).
 *   - Every hypothesis produced by the stub is defang-clean (packet rule #2).
 *   - The panel driver rejects hypotheses whose fixtures fail the defang guard.
 *   - runPanel returns a structurally valid PanelReport for the stub mode.
 *   - evasionsFound is a number derived from the runs (0 when the target class is
 *     detected, > 0 when the mutated fixture parsed cleanly without producing the class).
 *   - The stub-mode report is JSON-serializable (used by cli.ts).
 */

import { describe, it, expect } from 'vitest';
import { runPanel } from '../../src/agent-panel/panel.js';
import { stubAgent } from '../../src/agent-panel/stub-agent.js';
import { loadCapabilityMap } from '../../src/agent-panel/capability-map.js';
import { scanForDefangViolations } from '../../src/defang/index.js';
import type {
  CapabilityMap,
  EvasionAgent,
  EvasionHypothesis,
  PanelReport,
} from '../../src/agent-panel/index.js';

const FIXED_NOW = (): Date => new Date('2026-07-14T12:00:00.000Z');

// ---------------- stub agent ---------------------------------------------------------------

describe('stubAgent — determinism & shape', () => {
  it('produces 3 hypotheses per capability class (max=3)', async () => {
    const map = loadCapabilityMap();
    for (const entry of map.entries) {
      const hs = await stubAgent.propose(entry, 42, 3);
      expect(hs).toHaveLength(3);
    }
  });

  it('produces fewer when max < 3', async () => {
    const [entry] = loadCapabilityMap().entries;
    const one = await stubAgent.propose(entry, 42, 1);
    expect(one).toHaveLength(1);
    const zero = await stubAgent.propose(entry, 42, 0);
    expect(zero).toHaveLength(0);
  });

  it('produces byte-identical hypotheses for the same (entry, seed)', async () => {
    const [entry] = loadCapabilityMap().entries;
    const a = await stubAgent.propose(entry, 42, 3);
    const b = await stubAgent.propose(entry, 42, 3);
    expect(JSON.stringify(a)).toBe(JSON.stringify(b));
  });

  it('every hypothesis names its target class + sink', async () => {
    const map = loadCapabilityMap();
    for (const entry of map.entries) {
      const hs = await stubAgent.propose(entry, 42, 3);
      for (const h of hs) {
        expect(h.targetClass).toBe(entry.class);
        expect(h.targetSink).toBe(entry.sinkId);
        expect(h.proposedBy).toBe('stub');
        expect(h.id).toContain(entry.sinkId);
      }
    }
  });

  it('every generated fixture passes the defang guard (packet rule #2)', async () => {
    const map = loadCapabilityMap();
    for (const entry of map.entries) {
      const hs = await stubAgent.propose(entry, 42, 3);
      for (const h of hs) {
        const scan = scanForDefangViolations(h.generatedFixture);
        if (!scan.clean) {
          throw new Error(
            `stub-agent produced a defang-DIRTY fixture for ${h.id}: ${JSON.stringify(scan.violations)}`,
          );
        }
        expect(scan.clean).toBe(true);
      }
    }
  });
});

// ---------------- panel driver -------------------------------------------------------------

describe('runPanel — stub mode', () => {
  it('returns a structurally valid PanelReport', async () => {
    const map = loadCapabilityMap();
    const report = await runPanel({
      agent: stubAgent,
      capabilityMap: map,
      maxHypothesesPerClass: 3,
      seed: 42,
      now: FIXED_NOW,
    });
    expect(report.agent).toBe('stub');
    expect(report.seed).toBe(42);
    expect(report.runAt).toBe('2026-07-14T12:00:00.000Z');
    expect(report.hypothesesProposed).toBe(map.entries.length * 3);
    // Every stub hypothesis is defang-clean → nothing rejected.
    expect(report.hypothesesRejected).toBe(0);
    expect(report.hypothesesAdmitted).toBe(map.entries.length * 3);
    expect(report.runs).toHaveLength(map.entries.length * 3);
    expect(report.rejected).toHaveLength(0);
  }, 60_000);

  it('every admitted run has a verdict-bearing or bounded-failure outcome', async () => {
    const report = await runPanel({
      agent: stubAgent,
      capabilityMap: loadCapabilityMap(),
      maxHypothesesPerClass: 3,
      seed: 42,
      now: FIXED_NOW,
    });
    for (const run of report.runs) {
      // The runner never resolves outside these five kinds. Belt & suspenders.
      expect(['ok', 'fail-safe', 'timeout', 'oom', 'crash']).toContain(run.outcome.kind);
    }
  }, 60_000);

  it('evasionsFound is the count of runs where evaded === true', async () => {
    const report = await runPanel({
      agent: stubAgent,
      capabilityMap: loadCapabilityMap(),
      maxHypothesesPerClass: 3,
      seed: 42,
      now: FIXED_NOW,
    });
    const evadedCount = report.runs.filter((r) => r.evaded).length;
    expect(report.evasionsFound).toBe(evadedCount);
  }, 60_000);

  it('is JSON-serializable (used by cli.ts)', async () => {
    const report = await runPanel({
      agent: stubAgent,
      capabilityMap: loadCapabilityMap(),
      maxHypothesesPerClass: 3,
      seed: 42,
      now: FIXED_NOW,
    });
    const json = JSON.stringify(report);
    const parsed = JSON.parse(json) as PanelReport;
    expect(parsed.agent).toBe('stub');
    expect(parsed.hypothesesProposed).toBe(report.hypothesesProposed);
  }, 60_000);

  it('rejects hypotheses whose generatedFixture fails the defang guard', async () => {
    // A rogue agent that returns a fixture containing a real-looking network host. The
    // panel MUST scan and reject before running.
    const rogueAgent: EvasionAgent = {
      id: 'rogue',
      async propose(entry, seed): Promise<readonly EvasionHypothesis[]> {
        return [
          {
            id: `rogue-${entry.sinkId}-s${seed}`,
            targetClass: entry.class,
            targetSink: entry.sinkId,
            technique: 'rogue: emits a real host',
            // https://attacker.com is a real-looking network host → guard flags.
            generatedFixture: `lockfileVersion: '6.0'\npackages:\n  /rogue: 'https://attacker.com/leak'\n`,
            proposedBy: 'rogue',
            rationale: 'this fixture is intentionally dirty for the test',
          },
        ];
      },
    };
    // Single-entry capability map for scope — one hypothesis in, one rejection out.
    const map: CapabilityMap = {
      entries: [
        {
          class: 'net-egress',
          sinkId: 'http.request',
          kind: 'sink',
          description: 'test slice',
        },
      ],
    };
    const report = await runPanel({
      agent: rogueAgent,
      capabilityMap: map,
      maxHypothesesPerClass: 1,
      seed: 1,
      now: FIXED_NOW,
    });
    expect(report.hypothesesProposed).toBe(1);
    expect(report.hypothesesAdmitted).toBe(0);
    expect(report.hypothesesRejected).toBe(1);
    expect(report.runs).toHaveLength(0);
    expect(report.rejected).toHaveLength(1);
    expect(report.rejected[0].reason).toContain('defang guard flagged');
  });

  it('produces byte-identical reports for the same (agent, seed) — determinism', async () => {
    // Only compare fields that must be deterministic. wallMs on outcomes is not
    // deterministic (depends on system load), so we normalize before comparing.
    const map = loadCapabilityMap();
    const a = await runPanel({
      agent: stubAgent,
      capabilityMap: map,
      maxHypothesesPerClass: 3,
      seed: 42,
      now: FIXED_NOW,
    });
    const b = await runPanel({
      agent: stubAgent,
      capabilityMap: map,
      maxHypothesesPerClass: 3,
      seed: 42,
      now: FIXED_NOW,
    });
    // Compare hypothesis identity + evaded flags + outcome kinds. Timings drop out.
    const projectA = a.runs.map((r) => ({
      id: r.hypothesis.id,
      evaded: r.evaded,
      kind: r.outcome.kind,
    }));
    const projectB = b.runs.map((r) => ({
      id: r.hypothesis.id,
      evaded: r.evaded,
      kind: r.outcome.kind,
    }));
    expect(projectA).toEqual(projectB);
    expect(a.evasionsFound).toBe(b.evasionsFound);
    expect(a.hypothesesProposed).toBe(b.hypothesesProposed);
  }, 120_000);

  it('rejects a negative maxHypothesesPerClass', async () => {
    await expect(
      runPanel({
        agent: stubAgent,
        capabilityMap: loadCapabilityMap(),
        maxHypothesesPerClass: -1,
        seed: 42,
        now: FIXED_NOW,
      }),
    ).rejects.toThrow(/maxHypothesesPerClass/);
  });
});
