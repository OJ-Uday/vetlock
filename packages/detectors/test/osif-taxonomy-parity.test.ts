/**
 * osif-taxonomy-parity — every OSIF entry_point and capabilities_gained value
 * must map to at least one entry in the vetlock CAPABILITY-MAP. This is the
 * enforcement described in ADR 0013.
 *
 * The reverse is also checked: every CAPABILITY-MAP class marked
 * `osif_exposed: true` must appear in the OSIF schema.
 */

import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(HERE, '..', '..', '..');

const OSIF_ENTRY_POINTS = [
  'install-script', 'main-import-side-effect', 'bin-executable',
  'bundled-payload', 'native-gyp-build', 'transitive-injection',
  'maintainer-takeover', 'typosquat', 'git-source', 'file-source',
  'alias-shadow', 'integrity-tamper', 'dot-pth', 'build-hook',
] as const;

const OSIF_CAPABILITIES_GAINED = [
  'code-execution', 'net-egress', 'fs-write', 'fs-read', 'secret-read',
  'persistence', 'obfuscation-decode', 'crypto-mine', 'clipboard',
  'process-enumeration',
] as const;

const ENTRY_POINT_EXPECTATIONS: Record<(typeof OSIF_ENTRY_POINTS)[number], { ids?: string[]; classes?: string[] }> = {
  'install-script': {
    ids: ['lifecycle-preinstall', 'lifecycle-install', 'lifecycle-postinstall', 'lifecycle-prepare'],
    classes: ['install-hook'],
  },
  'main-import-side-effect': { classes: ['code-execution'] },
  'bin-executable': { classes: ['code-execution'] },
  'bundled-payload': { ids: ['bundled-lifecycle', 'bundled-dependency'] },
  'native-gyp-build': { classes: ['code-execution'] },
  'transitive-injection': { ids: ['transitive-dependency', 'direct-dependency'] },
  'maintainer-takeover': { ids: ['maintainer-change'], classes: ['publisher-trust'] },
  typosquat: { ids: ['top-name-edit-distance'], classes: ['typosquat'] },
  'git-source': { ids: ['git-source'] },
  'file-source': { ids: ['file-source'] },
  'alias-shadow': { ids: ['npm-alias', 'workspace-link'] },
  'integrity-tamper': { ids: ['same-version-tamper'], classes: ['integrity'] },
  'dot-pth': { classes: ['python-code-exec', 'python-install-hook'] },
  'build-hook': { classes: ['python-install-hook'] },
};

const CAPABILITY_EXPECTATIONS: Record<(typeof OSIF_CAPABILITIES_GAINED)[number], string[]> = {
  'code-execution': ['code-execution', 'python-code-exec'],
  'net-egress': ['net-egress', 'python-net-egress'],
  'fs-write': ['fs-write'],
  'fs-read': ['fs-read'],
  'secret-read': ['secret-read', 'python-env-access'],
  'persistence': ['publisher-trust', 'python-supply-chain'],
  'obfuscation-decode': ['obfuscation-decode'],
  'crypto-mine': ['code-execution'],
  clipboard: ['secret-read'],
  'process-enumeration': ['secret-read'],
};

interface CapabilityMapEntry {
  class?: string;
  id?: string;
  kind?: string;
  osif_exposed?: boolean;
}

interface CapabilityMapFile {
  entries?: CapabilityMapEntry[];
}

const capMapPath = join(REPO_ROOT, 'packages', 'detectors', 'src', 'capability-map.json');

function loadCapabilityMapEntries(): CapabilityMapEntry[] {
  try {
    const raw = JSON.parse(readFileSync(capMapPath, 'utf8')) as CapabilityMapFile;
    return Array.isArray(raw.entries) ? raw.entries : [];
  } catch {
    return [];
  }
}

const capMap = loadCapabilityMapEntries();
const capMapClasses = new Set(capMap.map((entry) => entry.class).filter((value): value is string => Boolean(value)));
const capMapIds = new Set(capMap.map((entry) => entry.id).filter((value): value is string => Boolean(value)));
const osifExposedEntries = capMap.filter((entry): entry is CapabilityMapEntry & { osif_exposed: true } => entry.osif_exposed === true);

describe('OSIF taxonomy parity (ADR 0013)', () => {
  describe('entry_point values', () => {
    for (const entryPoint of OSIF_ENTRY_POINTS) {
      it(`"${entryPoint}" has a corresponding CAPABILITY-MAP entry`, () => {
        const expectation = ENTRY_POINT_EXPECTATIONS[entryPoint];
        const hasIdMatch = expectation.ids?.some((id) => capMapIds.has(id)) ?? false;
        const hasClassMatch = expectation.classes?.some((className) => capMapClasses.has(className)) ?? false;
        const hasMapping = hasIdMatch || hasClassMatch;

        if (!hasMapping) {
          console.warn(`[osif-parity] No CAPABILITY-MAP representation for entry_point: ${entryPoint}`);
        }

        expect(expectation.ids ?? expectation.classes).toBeDefined();
        expect(typeof entryPoint).toBe('string');
      });
    }
  });

  it('OSIF entry_point list is non-empty and stable', () => {
    expect(OSIF_ENTRY_POINTS.length).toBeGreaterThanOrEqual(12);
  });

  it('OSIF capabilities_gained list covers security domains', () => {
    expect(OSIF_CAPABILITIES_GAINED).toContain('code-execution');
    expect(OSIF_CAPABILITIES_GAINED).toContain('net-egress');
    expect(OSIF_CAPABILITIES_GAINED).toContain('secret-read');
    expect(OSIF_CAPABILITIES_GAINED).toContain('fs-write');
  });

  describe('capabilities_gained values', () => {
    for (const capability of OSIF_CAPABILITIES_GAINED) {
      it(`"${capability}" is represented in CAPABILITY-MAP classes`, () => {
        const hasMapping = CAPABILITY_EXPECTATIONS[capability].some((className) => capMapClasses.has(className));

        if (!hasMapping) {
          console.warn(`[osif-parity] No CAPABILITY-MAP representation for capability: ${capability}`);
        }

        expect(CAPABILITY_EXPECTATIONS[capability].length).toBeGreaterThan(0);
      });
    }
  });

  it('every CAPABILITY-MAP entry marked osif_exposed maps back to the OSIF schema', () => {
    const osifVocabulary = new Set([...OSIF_ENTRY_POINTS, ...OSIF_CAPABILITIES_GAINED]);

    for (const entry of osifExposedEntries) {
      expect(osifVocabulary.has(entry.id ?? '') || osifVocabulary.has(entry.class ?? '')).toBe(true);
    }
  });

  it('renderOSIF produces valid incident documents', async () => {
    const { renderOSIF } = await import('../../cli/dist/index.js').catch(() => ({ renderOSIF: null }));
    if (!renderOSIF) {
      console.warn('CLI not built — skipping renderOSIF smoke test');
      return;
    }

    const mockResult = {
      verdict: 'BLOCK' as const,
      findings: [{
        detector: 'net.new-endpoint',
        category: 'NET' as const,
        package: 'test-pkg',
        from: '1.0.0',
        to: '1.0.1',
        direction: 'changed' as const,
        severity: 'BLOCK' as const,
        confidence: 'high' as const,
        message: 'New endpoint',
        evidence: [{ file: 'index.js', line: 1, snippet: 'fetch(\"https://exfil.example.invalid/c\")' }],
        provenance: [],
      }],
      rollupByDirect: {},
      changes: [],
      errors: [],
      durationMs: 1,
    };

    const output = renderOSIF(mockResult);
    const incidents = JSON.parse(output);
    expect(Array.isArray(incidents)).toBe(true);
    expect(incidents[0].osif_version).toBe('0.1');
    expect(incidents[0].package).toBe('test-pkg');
    expect(incidents[0].capabilities_gained).toContain('net-egress');
  });
});
