/**
 * MITRE ATT&CK tagging — every built-in detector's Finding must carry a
 * `mitre[]` list whose entries match the Enterprise-matrix technique-id
 * shape (Txxxx or Txxxx.yyy). Detectors that legitimately have no ATT&CK
 * mapping may set `mitre = []` explicitly, but the audit §2.1 mandate is
 * that they be TAGGED — not silently absent — so this test enumerates
 * every built-in detector id and asserts a decision was recorded.
 *
 * The central mapping lives at packages/core/src/mitre-tags.ts.
 */

import { describe, it, expect } from 'vitest';
import { MITRE_TAGS, mitreTagsFor } from '../src/mitre-tags.js';
import { validateFinding, type Finding } from '../src/finding.js';

/** ATT&CK Enterprise ID shape. */
const TECHNIQUE_RE = /^T\d{4}(\.\d{3})?$/;

// Every detector id that either a built-in detector object OR the engine can
// emit as a Finding. Engine-side ids are enumerated because they never come
// from a Detector.run() call — they're stamped directly by engine.ts /
// config-trust.ts.
const ENGINE_EMITTED_IDS = [
  'integrity.hash-mismatch',
  'analysis.failed',
  'deps.workspace-shadowing',
  'deps.aliased-name',
  'deps.non-registry-source',
  'deps.local-source',
  'config.in-diff-untrusted',
];

// Every detector-object id, sourced from packages/detectors/src/*.ts (each
// detector emits at least one of these; some emit multiple). Enumerated
// explicitly here rather than imported so this test lives in @vetlock/core
// and avoids a cycle back to @vetlock/detectors.
const DETECTOR_EMITTED_IDS = [
  'install.script-added',
  'install.script-changed',
  'install.bundled-lifecycle',
  'meta.maintainer-change',
  'net.new-module',
  'net.new-endpoint',
  'net.encoded-endpoint',
  'exec.new-module',
  'fs.new-hotpath-write',
  'fs.new-hotpath-read',
  'env.token-harvest',
  'code.dynamic-loading-added',
  'obf.entropy-jump',
  'obf.new-obfuscated-file',
  'bin.new-native-artifact',
  'wasm.suspicious-import',
  'wasm.unparseable',
  'deps.new-direct-dep',
  'deps.typosquat-candidate',
  'deps.first-version-cluster',
  'deps.bundled-dependency-added',
];

describe('MITRE ATT&CK tagging (audit §2.1)', () => {
  it('all built-in detector ids have a MITRE mapping in MITRE_TAGS', () => {
    for (const id of DETECTOR_EMITTED_IDS) {
      expect(MITRE_TAGS[id], `detector '${id}' has no MITRE mapping`).toBeDefined();
    }
  });

  it('all engine-emitted synthetic ids also have a MITRE mapping', () => {
    for (const id of ENGINE_EMITTED_IDS) {
      expect(MITRE_TAGS[id], `engine-emitted '${id}' has no MITRE mapping`).toBeDefined();
    }
  });

  it('every mapped technique matches /^T\\d{4}(\\.\\d{3})?$/', () => {
    for (const [detectorId, techniques] of Object.entries(MITRE_TAGS)) {
      for (const t of techniques) {
        expect(t).toMatch(TECHNIQUE_RE);
      }
      // Sanity guard: no more than 3 per detector (audit §2.1 conservative rule).
      expect(techniques.length).toBeLessThanOrEqual(3);
      // No duplicates.
      expect(new Set(techniques).size).toBe(techniques.length);
      // Reference back to detector to make the failure message useful.
      void detectorId;
    }
  });

  it('mitreTagsFor returns empty array for unmapped ids', () => {
    expect(mitreTagsFor('nonexistent.detector')).toEqual([]);
  });

  it('mitreTagsFor returns the same array as MITRE_TAGS lookup', () => {
    for (const id of DETECTOR_EMITTED_IDS) {
      expect(mitreTagsFor(id)).toEqual(MITRE_TAGS[id]);
    }
  });

  it('validateFinding accepts a Finding with a well-formed mitre field', () => {
    const f: Finding = {
      detector: 'net.new-module',
      category: 'NET',
      package: 'evil',
      from: null,
      to: '1.0.0',
      direction: 'added',
      severity: 'WARN',
      confidence: 'high',
      message: 'test',
      evidence: [{ file: 'index.js', line: 1, snippet: 'require("http")' }],
      provenance: [],
      mitre: ['T1071.001', 'T1041'],
    };
    expect(validateFinding(f)).toBeNull();
  });

  it('validateFinding accepts a Finding without mitre (backwards compat)', () => {
    const f: Finding = {
      detector: 'net.new-module',
      category: 'NET',
      package: 'evil',
      from: null,
      to: '1.0.0',
      direction: 'added',
      severity: 'WARN',
      confidence: 'high',
      message: 'test',
      evidence: [{ file: 'index.js', line: 1, snippet: 'require("http")' }],
      provenance: [],
    };
    expect(validateFinding(f)).toBeNull();
  });

  it('validateFinding rejects a Finding whose mitre contains an invalid id', () => {
    const f: Finding = {
      detector: 'net.new-module',
      category: 'NET',
      package: 'evil',
      from: null,
      to: '1.0.0',
      direction: 'added',
      severity: 'WARN',
      confidence: 'high',
      message: 'test',
      evidence: [{ file: 'index.js', line: 1, snippet: 'require("http")' }],
      provenance: [],
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      mitre: ['not-a-technique-id'] as any,
    };
    const err = validateFinding(f);
    expect(err).toBeTruthy();
    expect(err).toMatch(/invalid MITRE technique id/);
  });

  it('validateFinding rejects a Finding whose mitre is not an array', () => {
    const f = {
      detector: 'net.new-module',
      category: 'NET',
      package: 'evil',
      from: null,
      to: '1.0.0',
      direction: 'added',
      severity: 'WARN',
      confidence: 'high',
      message: 'test',
      evidence: [{ file: 'index.js', line: 1, snippet: 'require("http")' }],
      provenance: [],
      mitre: 'T1071.001',
    } as unknown as Finding;
    const err = validateFinding(f);
    expect(err).toBeTruthy();
    expect(err).toMatch(/mitre must be a string array/);
  });
});

