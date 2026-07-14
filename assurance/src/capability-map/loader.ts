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
