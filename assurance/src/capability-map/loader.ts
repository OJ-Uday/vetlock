/**
 * loadCapabilityMap — resolves the machine-readable CAPABILITY-MAP source.
 *
 * Precedence (packet §3.5 handoff):
 *   1. If the engine tree ships `packages/detectors/src/capability-map.json` (the eventual
 *      canonical location), read it and use it as the source of truth.
 *   2. Otherwise, fall back to the assurance-side copy at
 *      `assurance/src/capability-map/data.json`, and log a one-time warning that the
 *      STARTUP artifact hasn't landed yet.
 *
 * This lets the P2 coverage gate ship NOW without waiting on the engine tree — and
 * makes the switchover a zero-code change on the assurance side once the engine
 * lands its map.
 *
 * The loader validates minimally (schema + shape); it does NOT enforce coverage — that's
 * `CoverageGate`'s job.
 */

import { readFileSync, existsSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import type {
  CapabilityClass,
  CapabilityClassId,
  CapabilityMap,
  EntryPoints,
  Sink,
} from './types.js';

// -----------------------------------------------------------------------------------------
// Path resolution
// -----------------------------------------------------------------------------------------

/** The nine class ids the packet enumerates (§3.5). Kept as a runtime value because
 *  TypeScript's `CapabilityClassId` is compile-only. */
const KNOWN_CLASS_IDS: readonly CapabilityClassId[] = [
  'code-execution',
  'net-egress',
  'fs-write',
  'env/secret-read',
  'persistence',
  'obfuscation/decode',
  'crypto-mine',
  'clipboard',
  'process-enumeration',
];

/** Locate the engine-tree map. It's expected to land at
 *  `<repo-root>/packages/detectors/src/capability-map.json`. `import.meta.url` in a
 *  compiled dist file points at `<repo-root>/assurance/dist/capability-map/index.js`; in
 *  tests (tsx / vitest) it points at `<repo-root>/assurance/src/capability-map/index.ts`.
 *  Both climb the same three directories. */
function resolveEngineMapPath(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  // ../../..  = <repo-root>
  return resolve(here, '..', '..', '..', 'packages', 'detectors', 'src', 'capability-map.json');
}

/** The assurance-side fallback lives next to this loader file (or its compiled sibling).
 *  We resolve it as `data.json` in the same directory so it works for both `src` and
 *  `dist` — the JSON is emitted alongside the .js by esModuleInterop-style copy in tests
 *  and by TypeScript's default rootDir behavior in a real build. In compiled output the
 *  JSON isn't copied by tsc; we handle that by falling back to the src path. */
function resolveLocalMapPath(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  const candidate = resolve(here, 'data.json');
  if (existsSync(candidate)) return candidate;
  // Compiled `dist/capability-map/index.js` — climb back to src/capability-map/data.json.
  return resolve(here, '..', '..', 'src', 'capability-map', 'data.json');
}

// -----------------------------------------------------------------------------------------
// Startup-handoff warning — logged once per process, muted in tests
// -----------------------------------------------------------------------------------------

let warnedAboutStartupHandoff = false;

/** Reset the warned-once latch. Test-only escape hatch. */
export function _resetStartupHandoffWarning(): void {
  warnedAboutStartupHandoff = false;
}

function maybeWarnStartupHandoff(enginePath: string): void {
  if (warnedAboutStartupHandoff) return;
  warnedAboutStartupHandoff = true;
  // Muted under vitest — the tests explicitly assert loadCapabilityMap works today.
  if (process.env.VITEST) return;
  // eslint-disable-next-line no-console
  console.warn(
    `[@vetlock/assurance:capability-map] STARTUP handoff pending — engine map not found at ${enginePath}. ` +
      'Falling back to assurance-side copy. When STARTUP §3.5 lands packages/detectors/src/capability-map.json, ' +
      'this warning will go away and the engine map becomes the source of truth.',
  );
}

// -----------------------------------------------------------------------------------------
// Validation
// -----------------------------------------------------------------------------------------

/** Narrow assertion helpers that throw structured errors — good for humans reading a
 *  failing test log AND for the coverage gate's diagnostics. */
function assert(cond: unknown, msg: string): asserts cond {
  if (!cond) throw new Error(`[capability-map] ${msg}`);
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function validateSink(cls: string, s: unknown, seen: Set<string>): Sink {
  assert(isRecord(s), `class "${cls}" contains a non-object sink`);
  assert(typeof s.id === 'string' && s.id.length > 0, `class "${cls}" has a sink with a missing/empty id`);
  assert(
    typeof s.description === 'string' && s.description.length > 0,
    `class "${cls}" sink "${String(s.id)}" has a missing/empty description`,
  );
  assert(!seen.has(s.id), `class "${cls}" has duplicate sink id "${s.id}"`);
  seen.add(s.id);
  return { id: s.id, description: s.description };
}

function validateClass(id: string, raw: unknown): CapabilityClass {
  assert(isRecord(raw), `class "${id}" is not an object`);
  assert(Array.isArray(raw.sinks), `class "${id}" is missing sinks[] array`);
  const seen = new Set<string>();
  const sinks: Sink[] = raw.sinks.map((s) => validateSink(id, s, seen));
  const out: { sinks: Sink[]; note?: string } = { sinks };
  if (typeof raw.note === 'string') out.note = raw.note;
  return out;
}

function validateEntryPoint(axis: string, raw: unknown, seen: Set<string>) {
  assert(isRecord(raw), `entryPoints.${axis} contains a non-object entry`);
  assert(
    typeof raw.id === 'string' && raw.id.length > 0,
    `entryPoints.${axis} entry has a missing/empty id`,
  );
  assert(
    typeof raw.description === 'string' && raw.description.length > 0,
    `entryPoints.${axis} entry "${String(raw.id)}" has a missing/empty description`,
  );
  assert(!seen.has(raw.id), `entryPoints.${axis} has duplicate id "${raw.id}"`);
  seen.add(raw.id);
  return { id: raw.id, description: raw.description };
}

function validateEntryPoints(raw: unknown): EntryPoints {
  assert(isRecord(raw), 'entryPoints must be an object');
  assert(Array.isArray(raw.execution), 'entryPoints.execution must be an array');
  assert(Array.isArray(raw.graph), 'entryPoints.graph must be an array');
  const executionSeen = new Set<string>();
  const graphSeen = new Set<string>();
  return {
    execution: raw.execution.map((e) => validateEntryPoint('execution', e, executionSeen)),
    graph: raw.graph.map((e) => validateEntryPoint('graph', e, graphSeen)),
  };
}

function validateMap(raw: unknown): CapabilityMap {
  assert(isRecord(raw), 'top-level must be an object');
  assert(typeof raw.version === 'string' && raw.version.length > 0, 'version must be a non-empty string');

  // Shape detection: STARTUP §3.5 shipped `entries: [...]` at packages/detectors/src/capability-map.json
  // as of engine v0.4.0 (commit 5776abe). The assurance-side scaffold used `classes: {…}`
  // as its interim shape. Both roundtrip to the same CapabilityMap; we adapt STARTUP's
  // shape into ours when we see it.
  if (Array.isArray((raw as { entries?: unknown }).entries)) {
    return adaptStartupShape(raw as unknown as StartupShape);
  }

  // Legacy assurance-side scaffold shape.
  assert(typeof raw.notes === 'string', 'notes must be a string');
  assert(isRecord(raw.classes), 'classes must be an object');
  const classes: Partial<Record<CapabilityClassId, CapabilityClass>> = {};
  for (const id of KNOWN_CLASS_IDS) {
    assert(id in raw.classes, `missing class "${id}" (packet §3.5 requires all 9)`);
    classes[id] = validateClass(id, (raw.classes as Record<string, unknown>)[id]);
  }
  return {
    version: raw.version,
    notes: raw.notes,
    classes: classes as Record<CapabilityClassId, CapabilityClass>,
    entryPoints: validateEntryPoints(raw.entryPoints),
  };
}

// -----------------------------------------------------------------------------------------
// STARTUP §3.5 shape adapter
//
// STARTUP shipped (packages/detectors/src/capability-map.json, ADR-0011):
//   { version, entries: [
//       { class, kind, id, aliases?, detectors?, tests?, corpus_refs? },
//       ...
//     ] }
//
// STARTUP's actual ontology (as of engine v0.4.2):
//   kind: 'sink' — the class field is one of the capability classes (code-execution,
//     net-egress, fs-write, fs-read, secret-read, obfuscation-decode, integrity,
//     advisory-known-vuln, dep-graph-anomaly).
//   kind: 'entry-point' — the class field is the entry-point FAMILY name
//     (install-hook, publisher-trust, typosquat, graph-entry-point).
//
// We adapt into assurance's shape:
//   sinks → grouped by class name (mapping STARTUP's names into packet §3.5 taxonomy
//     where they differ; unknown-to-us STARTUP classes are kept under their own key so
//     the coverage gate still sees them).
//   entry-points → 'graph-entry-point' family → entryPoints.graph[]; all other entry-point
//     families → entryPoints.execution[] (install-hook, publisher-trust, typosquat all
//     fire at install / publish time — the execution axis in packet terms).
// -----------------------------------------------------------------------------------------

/** STARTUP class name → packet §3.5 class name. When no mapping exists, keep STARTUP's
 *  name verbatim (assurance is a consumer, not a taxonomy gatekeeper). */
const STARTUP_CLASS_ALIAS: Record<string, string> = {
  'obfuscation-decode': 'obfuscation/decode', // slash-form is packet §3.5
  // 'secret-read' and 'fs-read' are STARTUP splits of the packet's 'env/secret-read'.
  // We honor STARTUP's split — future assurance coverage can name either bucket.
};

interface StartupEntry {
  readonly class: string;
  readonly kind: 'sink' | 'entry-point' | string;
  readonly id: string;
  readonly aliases?: readonly string[];
  readonly detectors?: readonly string[];
  readonly tests?: readonly string[];
  readonly corpus_refs?: readonly string[];
  readonly description?: string;
}

interface StartupShape {
  readonly version: string;
  readonly entries: readonly StartupEntry[];
  readonly $comment?: string;
  readonly generatedFrom?: string;
}

function describeStartupEntry(e: StartupEntry): string {
  if (typeof e.description === 'string' && e.description.length > 0) return e.description;
  const bits: string[] = [];
  if (e.detectors && e.detectors.length > 0) {
    bits.push(`detectors: ${e.detectors.join(', ')}`);
  }
  if (e.aliases && e.aliases.length > 0) {
    bits.push(`aliases: ${e.aliases.slice(0, 3).join(', ')}${e.aliases.length > 3 ? '…' : ''}`);
  }
  return bits.length > 0 ? bits.join(' · ') : `(no description; kind=${e.kind})`;
}

function adaptStartupShape(raw: StartupShape): CapabilityMap {
  const classes: Record<string, { sinks: Sink[] }> = {};
  const execution: { id: string; description: string }[] = [];
  const graph: { id: string; description: string }[] = [];

  for (const e of raw.entries) {
    assert(typeof e.class === 'string' && e.class.length > 0, 'STARTUP entry missing class');
    assert(typeof e.id === 'string' && e.id.length > 0, `STARTUP entry (class=${e.class}) missing id`);
    const description = describeStartupEntry(e);

    if (e.kind === 'sink') {
      const clsKey = STARTUP_CLASS_ALIAS[e.class] ?? e.class;
      if (!classes[clsKey]) classes[clsKey] = { sinks: [] };
      classes[clsKey].sinks.push({ id: e.id, description });
      continue;
    }

    if (e.kind === 'entry-point') {
      // STARTUP puts entry-point families in the CLASS field. graph-entry-point → graph axis;
      // everything else (install-hook, publisher-trust, typosquat) fires at execution time.
      // Prefix the id with the family so ids stay unique across families.
      const prefixedId = `${e.class}:${e.id}`;
      if (e.class === 'graph-entry-point') {
        graph.push({ id: prefixedId, description });
      } else {
        execution.push({ id: prefixedId, description });
      }
      continue;
    }

    // Unknown kind — record as a sink under a synthetic class so it's visible in coverage
    // reports but doesn't pollute canonical classes.
    const cls = `x-startup:${e.kind}`;
    if (!classes[cls]) classes[cls] = { sinks: [] };
    classes[cls].sinks.push({ id: e.id, description });
  }

  // Ensure every packet §3.5 class is at least present (empty sinks OK — packet §4:
  // "unknowns are the search target"). STARTUP may not enumerate every class yet.
  for (const id of KNOWN_CLASS_IDS) {
    if (!classes[id]) classes[id] = { sinks: [] };
  }

  return {
    version: raw.version,
    notes: 'Adapted from STARTUP §3.5 shape at packages/detectors/src/capability-map.json.',
    classes: classes as unknown as Record<CapabilityClassId, CapabilityClass>,
    entryPoints: { execution, graph },
  };
}

// -----------------------------------------------------------------------------------------
// Public API
// -----------------------------------------------------------------------------------------

/** The nine class ids from packet §3.5 as a runtime constant. Exported for consumers that
 *  need to iterate (e.g. reports, gates, drivers). */
export const CAPABILITY_CLASS_IDS: readonly CapabilityClassId[] = KNOWN_CLASS_IDS;

/**
 * Load the CAPABILITY-MAP. Reads the engine-tree map preferentially, falls back to the
 * assurance-side copy, validates the shape, and returns the parsed value.
 *
 * @throws if neither the engine map nor the local fallback is readable or valid JSON.
 */
export function loadCapabilityMap(): CapabilityMap {
  const enginePath = resolveEngineMapPath();
  const localPath = resolveLocalMapPath();

  let sourcePath: string;
  let text: string;
  if (existsSync(enginePath)) {
    sourcePath = enginePath;
    text = readFileSync(enginePath, 'utf8');
  } else {
    maybeWarnStartupHandoff(enginePath);
    sourcePath = localPath;
    text = readFileSync(localPath, 'utf8');
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (e) {
    throw new Error(`[capability-map] ${sourcePath} is not valid JSON: ${(e as Error).message}`);
  }

  return validateMap(parsed);
}
