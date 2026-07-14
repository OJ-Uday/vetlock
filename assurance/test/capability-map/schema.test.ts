/**
 * Schema tests for the CAPABILITY-MAP artifact.
 *
 * The loader reads STARTUP's `packages/detectors/src/capability-map.json` preferentially
 * (that's the source of truth per ADR-0011) and falls back to the assurance-side
 * `data.json` when STARTUP's file isn't present.
 *
 * These tests are STRUCTURAL — they assert the artifact has the right *shape* to feed the
 * coverage gate. They do NOT hardcode individual sink/entry-point IDs because STARTUP
 * grows the enumeration continuously (packet §7 "floor, not ceiling") and pinning specific
 * strings would break every time STARTUP adds one. The right way to notice enumeration
 * drift is `CoverageGate`'s per-run report, not this file.
 */

import { describe, it, expect } from 'vitest';
import {
  CAPABILITY_CLASS_IDS,
  loadCapabilityMap,
  type CapabilityMap,
} from '../../src/capability-map/index.js';

describe('capability-map — parses + validates', () => {
  it('loadCapabilityMap() returns a well-formed CapabilityMap', () => {
    const map: CapabilityMap = loadCapabilityMap();
    expect(map.version).toBeTypeOf('string');
    expect(map.version.length).toBeGreaterThan(0);
    expect(map.notes).toBeTypeOf('string');
    expect(map.classes).toBeTypeOf('object');
    expect(map.entryPoints).toBeTypeOf('object');
    expect(Array.isArray(map.entryPoints.execution)).toBe(true);
    expect(Array.isArray(map.entryPoints.graph)).toBe(true);
  });
});

describe('capability-map — every packet §3.5 class is represented', () => {
  // The nine classes are the taxonomic FLOOR. Every one must have an entry (empty sinks
  // OK — packet §4: "unknowns are the search target"), or STARTUP has renamed a class we
  // depend on and we need to know about it here first.
  const map = loadCapabilityMap();
  for (const cls of CAPABILITY_CLASS_IDS) {
    it(`class "${cls}" is present`, () => {
      expect(map.classes[cls]).toBeDefined();
      expect(Array.isArray(map.classes[cls]!.sinks)).toBe(true);
    });
  }
});

describe('capability-map — structural invariants', () => {
  const map = loadCapabilityMap();

  it('every sink has a non-empty id and description', () => {
    for (const cls of CAPABILITY_CLASS_IDS) {
      for (const sink of map.classes[cls]?.sinks ?? []) {
        expect(sink.id).toBeTypeOf('string');
        expect(sink.id.length).toBeGreaterThan(0);
        expect(sink.description).toBeTypeOf('string');
        expect(sink.description.length).toBeGreaterThan(0);
      }
    }
  });

  it('sink ids are unique within their class', () => {
    for (const cls of CAPABILITY_CLASS_IDS) {
      const ids = (map.classes[cls]?.sinks ?? []).map((s) => s.id);
      expect(new Set(ids).size).toBe(ids.length);
    }
  });

  it('execution entry-point ids are unique + non-empty', () => {
    const ids = map.entryPoints.execution.map((e) => e.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const e of map.entryPoints.execution) {
      expect(e.id.length).toBeGreaterThan(0);
      expect(e.description.length).toBeGreaterThan(0);
    }
  });

  it('graph entry-point ids are unique + non-empty', () => {
    const ids = map.entryPoints.graph.map((e) => e.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const e of map.entryPoints.graph) {
      expect(e.id.length).toBeGreaterThan(0);
      expect(e.description.length).toBeGreaterThan(0);
    }
  });

  it('code-execution class has at least one enumerated sink', () => {
    // The one hard floor: this class MUST have enumeration progress. Packet §3.5 explicitly
    // names 16 sinks for it; STARTUP has committed to enumerating them. If this fails, the
    // artifact was truncated or the shape adapter dropped everything.
    const sinks = map.classes['code-execution']?.sinks ?? [];
    expect(sinks.length).toBeGreaterThan(0);
  });
});

describe('capability-map — enumeration coverage report', () => {
  it('reports total enumerated members for the ASSURANCE.md scorecard', () => {
    // This test doesn't assert a threshold — it just observes and passes. The number goes
    // into ASSURANCE.md via the metrics collector. Growth over time is the health metric.
    const map = loadCapabilityMap();
    let totalSinks = 0;
    for (const cls of CAPABILITY_CLASS_IDS) {
      totalSinks += map.classes[cls]?.sinks.length ?? 0;
    }
    const totalEntryPoints = map.entryPoints.execution.length + map.entryPoints.graph.length;
    // Log to test output; the CI collector picks up the ASSURANCE.md side of it separately.
    // eslint-disable-next-line no-console
    console.log(
      `[capability-map] enumerated: ${totalSinks} sinks + ${totalEntryPoints} entry-points ` +
        `(${totalSinks + totalEntryPoints} total)`,
    );
    // Vacuous pass — the real signal is the ASSURANCE.md report.
    expect(totalSinks + totalEntryPoints).toBeGreaterThan(0);
  });
});
