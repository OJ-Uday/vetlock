/**
 * Stub evasion agent.
 *
 * Returns a small deterministic set of hard-coded hypotheses that mimic the shape a real
 * cheap-model agent would emit — a rationale, a technique label, and a defanged fixture.
 * Every fixture MUST pass `scanForDefangViolations` (packet rule #2). The panel driver
 * still scans each hypothesis before running it — the stub's own compliance is a defense
 * in depth, not a substitute for the guard.
 *
 * The stub is the CI mode: no network, no API keys, byte-deterministic. It also doubles
 * as the reference implementation for what a real EvasionAgent has to produce.
 *
 * DETERMINISM: `propose(entry, seed, max)` returns the same first `min(N, max)` hypotheses
 * every time it's called with the same (entry.sinkId, seed) — same input, same bytes.
 */

import type { CapabilityMapEntry, EvasionAgent, EvasionHypothesis } from './types.js';

// A tiny lockfile-shaped template. The engine's parseLockfileText will accept it as
// pnpm-lock.yaml (matching the P0 robustness generator's target); the "malicious"
// characteristics are named in inert-marker fields the detector should look at, not in
// actual payload bytes. This lets the stub name every capability class the mock
// CAPABILITY-MAP enumerates without ever emitting a live payload.
//
// Reserved-domain endpoints: *.invalid, example.com, 127.0.0.1 — all allow-listed by the
// defang guard.

interface StubTemplate {
  readonly technique: string;
  readonly rationale: string;
  /** Produce the fixture text. `entry` gives the sink to name inside the fixture. */
  buildFixture(entry: CapabilityMapEntry): string;
}

/**
 * Three techniques per class. Each is a plausible novelty a cheap model might propose:
 *   - identifier-obfuscation via string concatenation
 *   - source relocation into a nested manifest field (README, description, script name)
 *   - unicode homoglyph replacement in the identifier
 * The stub is not trying to be exhaustive; it's trying to exercise the panel end-to-end
 * with representative shapes.
 */
const TECHNIQUES: readonly StubTemplate[] = [
  {
    technique: 'identifier-split-and-concat',
    rationale:
      'Split the sink identifier across two string literals concatenated at runtime. Static string-match detectors miss the split token.',
    buildFixture(entry): string {
      // pnpm-lock.yaml-shaped. The "malicious" characteristic is the description
      // string; no code runs.
      return [
        `lockfileVersion: '6.0'`,
        `settings:`,
        `  autoInstallPeers: true`,
        `packages:`,
        `  /evade-${entry.class}@0.1.0:`,
        `    resolution:`,
        `      integrity: sha512-AAAA`,
        `      tarball: https://packages.invalid/evade-${entry.class}/-/evade-${entry.class}-0.1.0.tgz`,
        `    description: 'proposes to evade ${entry.sinkId} by splitting the identifier'`,
        ``,
      ].join('\n');
    },
  },
  {
    technique: 'nested-manifest-relocation',
    rationale:
      "Move the sink invocation from index.js into a nested package.json 'scripts' entry the walker misses. Detector visits main entry but skips deep scripts.",
    buildFixture(entry): string {
      return [
        `lockfileVersion: '6.0'`,
        `settings:`,
        `  autoInstallPeers: true`,
        `packages:`,
        `  /nested-${entry.class}@0.2.0:`,
        `    resolution:`,
        `      integrity: sha512-BBBB`,
        `      tarball: https://packages.test/nested-${entry.class}/-/nested-${entry.class}-0.2.0.tgz`,
        `    peerDependencies:`,
        `      inert-marker: '*'`,
        `    description: 'moves ${entry.sinkId} into a nested script hook — echo hello only'`,
        ``,
      ].join('\n');
    },
  },
  {
    technique: 'unicode-homoglyph',
    rationale:
      "Replace ASCII characters in the sink identifier with visually identical unicode homoglyphs. Detector's exact-match table doesn't include the mixed-script variant.",
    buildFixture(entry): string {
      // The homoglyph is only in the description — inert. No functional call is emitted.
      return [
        `lockfileVersion: '6.0'`,
        `settings:`,
        `  autoInstallPeers: true`,
        `packages:`,
        `  /homoglyph-${entry.class}@0.3.0:`,
        `    resolution:`,
        `      integrity: sha512-CCCC`,
        `      tarball: https://packages.example/homoglyph-${entry.class}/-/homoglyph-${entry.class}-0.3.0.tgz`,
        `    description: 'homoglyph on ${entry.sinkId} — cyrillic o replaces latin o in the identifier'`,
        ``,
      ].join('\n');
    },
  },
];

/**
 * Deterministic id for a stub hypothesis. Stable across runs of the same (sinkId, index).
 */
function stubHypothesisId(entry: CapabilityMapEntry, index: number, seed: number): string {
  return `stub-${entry.sinkId}-${index}-s${seed}`;
}

/** The stub agent — implements EvasionAgent. */
export const stubAgent: EvasionAgent = {
  id: 'stub',
  async propose(
    entry: CapabilityMapEntry,
    seed: number,
    max: number,
  ): Promise<readonly EvasionHypothesis[]> {
    const n = Math.max(0, Math.min(max, TECHNIQUES.length));
    const hypotheses: EvasionHypothesis[] = [];
    for (let i = 0; i < n; i++) {
      const tpl = TECHNIQUES[i];
      hypotheses.push({
        id: stubHypothesisId(entry, i, seed),
        targetClass: entry.class,
        targetSink: entry.sinkId,
        technique: tpl.technique,
        generatedFixture: tpl.buildFixture(entry),
        proposedBy: 'stub',
        rationale: tpl.rationale,
      });
    }
    return hypotheses;
  },
};
