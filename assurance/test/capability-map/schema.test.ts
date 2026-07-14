/**
 * Schema tests for the CAPABILITY-MAP data.json.
 *
 * These assertions pin the shape of the artifact against packet §3.5. They read the JSON
 * through `loadCapabilityMap()` (the same loader consumers use), so a shape change on
 * either side breaks these tests before it can silently break the coverage gate.
 */

import { describe, it, expect } from 'vitest';
import {
  CAPABILITY_CLASS_IDS,
  loadCapabilityMap,
  type CapabilityMap,
} from '../../src/capability-map/index.js';

// Packet §3.5 explicitly names every `code-execution` sink. Any missing member here is a
// packet-drift failure — the enumeration is the whole point of the artifact.
const REQUIRED_CODE_EXECUTION_SINKS = [
  'eval',
  'new Function',
  'vm.*',
  'child_process.exec',
  'child_process.execFile',
  'child_process.spawn',
  'child_process.fork',
  'child_process.execSync',
  'worker_threads',
  'process.binding',
  'native-node-load',
  'WebAssembly.instantiate',
  'WebAssembly.compile',
  'require(computed)',
  'import(computed)',
  'module.constructor',
] as const;

// Packet §3.5 also names the execution and graph entry-point families. These must all
// be present as enumerated ids.
const REQUIRED_EXECUTION_ENTRY_POINTS = [
  'lifecycle-preinstall',
  'lifecycle-install',
  'lifecycle-postinstall',
  'lifecycle-prepare',
  'lifecycle-prepublish',
  'pkg-main',
  'pkg-module',
  'pkg-exports',
  'pkg-bin',
  'top-level-side-effects',
  'import-side-effects',
  'test-hooks',
  'native-gyp-build',
  'bundled-node-modules',
] as const;

const REQUIRED_GRAPH_ENTRY_POINTS = [
  'direct',
  'transitive',
  'optional',
  'peer',
  'bundled',
  'git-dep',
  'url-dep',
  'tarball-dep',
  'alias',
  'link-protocol',
  'file-protocol',
] as const;

describe('capability-map data.json — parses + validates', () => {
  it('loadCapabilityMap() returns a well-formed CapabilityMap', () => {
    const map: CapabilityMap = loadCapabilityMap();
    expect(map.version).toBeTypeOf('string');
    expect(map.version.length).toBeGreaterThan(0);
    expect(map.notes).toBeTypeOf('string');
    expect(map.classes).toBeTypeOf('object');
    expect(map.entryPoints).toBeTypeOf('object');
  });
});

describe('capability-map data.json — all packet §3.5 classes present', () => {
  const map = loadCapabilityMap();
  for (const classId of CAPABILITY_CLASS_IDS) {
    it(`has class "${classId}"`, () => {
      expect(map.classes[classId]).toBeDefined();
      expect(Array.isArray(map.classes[classId].sinks)).toBe(true);
    });
  }
});

describe('capability-map data.json — sink ids unique within their class', () => {
  const map = loadCapabilityMap();
  for (const classId of CAPABILITY_CLASS_IDS) {
    it(`class "${classId}" has no duplicate sink ids`, () => {
      const ids = map.classes[classId].sinks.map((s) => s.id);
      const unique = new Set(ids);
      expect(unique.size).toBe(ids.length);
    });
  }
});

describe('capability-map data.json — code-execution enumeration matches packet §3.5', () => {
  const map = loadCapabilityMap();
  const sinkIds = new Set(map.classes['code-execution'].sinks.map((s) => s.id));
  for (const required of REQUIRED_CODE_EXECUTION_SINKS) {
    it(`enumerates code-execution sink "${required}"`, () => {
      expect(sinkIds.has(required)).toBe(true);
    });
  }
});

describe('capability-map data.json — entry-points enumerate packet §3.5 families', () => {
  const map = loadCapabilityMap();
  const executionIds = new Set(map.entryPoints.execution.map((e) => e.id));
  const graphIds = new Set(map.entryPoints.graph.map((e) => e.id));

  for (const required of REQUIRED_EXECUTION_ENTRY_POINTS) {
    it(`enumerates execution entry-point "${required}"`, () => {
      expect(executionIds.has(required)).toBe(true);
    });
  }

  for (const required of REQUIRED_GRAPH_ENTRY_POINTS) {
    it(`enumerates graph entry-point "${required}"`, () => {
      expect(graphIds.has(required)).toBe(true);
    });
  }
});

describe('capability-map data.json — entry-point ids unique within axis', () => {
  const map = loadCapabilityMap();
  it('no duplicate ids in entryPoints.execution', () => {
    const ids = map.entryPoints.execution.map((e) => e.id);
    expect(new Set(ids).size).toBe(ids.length);
  });
  it('no duplicate ids in entryPoints.graph', () => {
    const ids = map.entryPoints.graph.map((e) => e.id);
    expect(new Set(ids).size).toBe(ids.length);
  });
});

describe('capability-map data.json — descriptions present + non-empty', () => {
  const map = loadCapabilityMap();
  it('every enumerated sink has a non-empty description', () => {
    for (const classId of CAPABILITY_CLASS_IDS) {
      for (const sink of map.classes[classId].sinks) {
        expect(sink.description.length).toBeGreaterThan(0);
      }
    }
  });
  it('every enumerated entry-point has a non-empty description', () => {
    for (const e of map.entryPoints.execution) expect(e.description.length).toBeGreaterThan(0);
    for (const e of map.entryPoints.graph) expect(e.description.length).toBeGreaterThan(0);
  });
});
