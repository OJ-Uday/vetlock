/**
 * CAPABILITY-MAP loader (ADR 0011 completeness doctrine).
 *
 * Source of truth: packages/detectors/src/capability-map.json
 * Generated doc: docs/CAPABILITY-MAP.md (produced by scripts/generate-capability-map-doc.js)
 *
 * The map enumerates every capability CLASS the engine claims to cover, listing
 * each sink (runtime primitive that achieves the class) and each entry-point
 * (way attacker code runs or a dependency enters the graph). Coverage of a
 * class is a *measured, published, CI-enforced* number: any entry without a
 * detector + test binding fails `capability-map-coverage.test`.
 */

import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

/** Where the enumerated primitive fits in the doctrine. */
export type CapabilityClass =
  | 'code-execution'
  | 'net-egress'
  | 'fs-write'
  | 'fs-read'
  | 'secret-read'
  | 'install-hook'
  | 'graph-entry-point'
  | 'integrity'
  | 'typosquat'
  | 'publisher-trust'
  | 'obfuscation-decode'
  | 'advisory-known-vuln'
  | 'dep-graph-anomaly';

export type CapabilityKind = 'sink' | 'entry-point';

export interface CapabilityMapEntry {
  class: CapabilityClass;
  kind: CapabilityKind;
  id: string;
  aliases?: string[];
  detectors: string[];
  tests: string[];
  corpus_refs: string[];
  chokepoint?: string;
  notes?: string;
  /**
   * True when a real-world corpus example does NOT yet exercise this entry.
   * The coverage gate treats these as WARN, not fail — deliberate honesty
   * gap for entries whose real attack has never been observed OR whose
   * corpus fixture is on the roadmap.
   */
  soft_warn_no_corpus?: boolean;
}

export interface CapabilityMap {
  version: string;
  entries: CapabilityMapEntry[];
}

let cachedMap: CapabilityMap | null = null;

/**
 * Load and return the CAPABILITY-MAP. Cached after first read.
 */
export function getCapabilityMap(): CapabilityMap {
  if (cachedMap) return cachedMap;
  const here = path.dirname(fileURLToPath(import.meta.url));
  // In dev (before tsc build): packages/detectors/src/capability-map.ts →
  // capability-map.json is next to it in src/.
  // In production (after tsc build): packages/detectors/dist/capability-map.js →
  // no capability-map.json is emitted by tsc (it doesn't copy .json), so
  // fall back to walking up to find the source.
  const candidates = [
    path.join(here, 'capability-map.json'),                    // dev/tsc-in-place
    path.join(here, '..', 'src', 'capability-map.json'),       // dist → src
  ];
  let text: string | null = null;
  for (const p of candidates) {
    try { text = readFileSync(p, 'utf8'); break; } catch { /* try next */ }
  }
  if (text === null) {
    console.error(`[vetlock] WARNING: capability-map.json not found in any candidate path. Tried: ${candidates.join(', ')}`);
    cachedMap = { version: 'missing', entries: [] };
    return cachedMap;
  }
  const parsed = JSON.parse(text) as CapabilityMap;
  if (!parsed.entries || !Array.isArray(parsed.entries)) {
    throw new Error('capability-map.json is malformed — missing entries[]');
  }
  cachedMap = parsed;
  return parsed;
}

/**
 * Return the set of all detector IDs referenced by the map. Used by the
 * coverage-gate test to cross-check every referenced detector actually
 * exists in the exported registry.
 */
export function referencedDetectors(): Set<string> {
  const out = new Set<string>();
  for (const e of getCapabilityMap().entries) {
    for (const d of e.detectors) out.add(d);
  }
  return out;
}

/**
 * Return the set of all test file paths referenced by the map. Used by the
 * coverage-gate test to cross-check every referenced test file exists.
 */
export function referencedTests(): Set<string> {
  const out = new Set<string>();
  for (const e of getCapabilityMap().entries) {
    for (const t of e.tests) out.add(t);
  }
  return out;
}
