/**
 * advisory-known-vuln-shift — a completeness-vector transform for the
 * `advisory-known-vuln` class (STARTUP §3.5 sinks: `ghsa-affected-version` and
 * `ghsa-adjacent-version`; detector chokepoint: `deps.new-direct-dep`).
 *
 * The `advisory-known-vuln` class covers dependencies whose resolved version
 * matches a curated GHSA advisory (`ghsa-affected-version`) or falls in a
 * ±3-patch / ±1-minor neighborhood of one (`ghsa-adjacent-version`). Detection
 * is a GRAPH-level check performed during `runDiff` — the detector compares the
 * new snapshot's dependency tree against the advisory dataset and emits a
 * finding when a package.json entry's resolved version lands in a flagged range.
 *
 * The transform shipped here — `advisoryVersionShift` — is a completeness probe
 * along the "same class, sibling version" axis:
 *
 *   • Input:  package.json with a `dependencies` entry pinned to a specific
 *             version.
 *   • Output: the same package.json with that entry shifted to an
 *             ADJACENT version string (e.g. "1.2.3" → "1.2.4"), still landing
 *             in the ±3-patch neighborhood the `ghsa-adjacent-version` sink
 *             covers.
 *
 * If the scanner catches `1.2.3` (say, on a known GHSA-affected range) but
 * misses `1.2.4` (which the adjacent-version detector should flag), the class
 * is version-boundary incomplete. Practical adversary use: a malicious publisher
 * that knows the exact affected range shifts by one patch to skirt the scanner
 * while still landing in a range the detector's ±3-patch policy should
 * flag as adjacent-known-vuln.
 *
 * The transform:
 *   • is a NO-OP on non-JSON input,
 *   • is a NO-OP if `dependencies` is empty or missing,
 *   • picks the FIRST dependency whose value parses as a bare version (no
 *     range operators — `^`, `~`, `>=`, etc. — since those cover a range not
 *     a point release, and shifting them doesn't make sense),
 *   • increments the patch component by 1 (mod-safe via a bounded max),
 *   • preserves everything else byte-identically.
 *
 * ENGINE ROUTING NOTE
 * -------------------
 * `advisory-known-vuln` findings are emitted by `runDiff` (deps.new-direct-dep
 * detector) against a curated advisory dataset. The assurance runner's
 * `engine:extractCapabilities` scenario is per-file text-in and cannot fire
 * advisory detection — that requires two snapshots + advisory data. Because
 * the current assurance surface can't reach this class through the standard
 * evasion loop, the transform is routed to `NO_ENGINE_DETECTOR_YET` in
 * evasion-catch-rate.test.ts — same protocol as Wave 6-Y's dep-graph-anomaly
 * and integrity transforms, which also target graph-level classes. When a
 * future wave wires an assurance `engine:runDiff` scenario with an advisory
 * dataset, this transform migrates out of `NO_ENGINE_DETECTOR_YET` and into
 * the standard finding-survives loop.
 */

import type { CompletenessTransform } from './types.js';

/** Parse a semver-shape spec into [major, minor, patch]. Returns null if the
 *  spec has range operators (`^1.2.3`, `>=1.2`, etc.) or isn't a bare version. */
function parseBareVersion(spec: string): [number, number, number] | null {
  const trimmed = spec.trim();
  // Reject range operators — the ±3-patch adjacency shift is only meaningful
  // for a bare pinned version.
  if (/^[\s^~<>=]/.test(trimmed)) return null;
  const m = trimmed.match(/^(\d+)\.(\d+)\.(\d+)(?:-[\w.]+)?$/);
  if (!m) return null;
  return [Number(m[1]), Number(m[2]), Number(m[3])];
}

export const advisoryVersionShift: CompletenessTransform = {
  id: 'advisory-version-shift',
  family: 'sink-family-widening',
  targetClass: 'advisory-known-vuln',
  description:
    'Shift a bare-pinned dependency version by +1 patch (e.g. "1.2.3" → "1.2.4"). Same class — the shifted version lands in the ±3-patch adjacency neighborhood that ghsa-adjacent-version covers, exercising the class boundary between affected-version and adjacent-version sinks.',
  transform(source, _seed): string {
    let parsed: unknown;
    try {
      parsed = JSON.parse(source);
    } catch {
      return source;
    }
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      return source;
    }
    const pkg = parsed as Record<string, unknown>;
    const deps = pkg.dependencies;
    if (typeof deps !== 'object' || deps === null || Array.isArray(deps)) {
      return source;
    }
    const depMap = deps as Record<string, unknown>;
    let targetKey: string | null = null;
    let bareVersion: [number, number, number] | null = null;
    for (const [k, v] of Object.entries(depMap)) {
      if (typeof v !== 'string') continue;
      const parsedV = parseBareVersion(v);
      if (parsedV === null) continue;
      targetKey = k;
      bareVersion = parsedV;
      break;
    }
    if (targetKey === null || bareVersion === null) return source;
    const [major, minor, patch] = bareVersion;
    // Increment patch. Cap at a large max to avoid overflow — versions like
    // 999999999999999 aren't representable safely as JS numbers, but we're
    // never going to see one in a real fixture. Guard anyway.
    const nextPatch = patch < 2 ** 30 ? patch + 1 : patch;
    depMap[targetKey] = `${major}.${minor}.${nextPatch}`;
    return JSON.stringify(pkg, null, 2);
  },
};
