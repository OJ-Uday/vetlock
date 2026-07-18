/**
 * OSIF v0.1 renderer — emits one incident document per affected package.
 *
 * OSIF (Open Supply-chain Incident Format) is a CC0 format for describing
 * the mechanics of supply-chain attacks. Schema: https://osif.dev/schema/v0/incident.json
 * Spec: https://github.com/OJ-Uday/osif-spec
 */

import type { Finding, RunResult } from '@vetlock/core';
import { VETLOCK_VERSION } from '@vetlock/core';

const CATEGORY_TO_OSIF_CAPABILITY: Record<Finding['category'], string> = {
  NET: 'net-egress',
  EXEC: 'code-execution',
  FS: 'fs-write',
  ENV: 'secret-read',
  CODE: 'code-execution',
  OBF: 'obfuscation-decode',
  INSTALL: 'code-execution',
  META: 'persistence',
  INTEG: 'code-execution',
  DEPS: 'code-execution',
};

function detectorToEntryPoint(detectorId: string): string {
  if (detectorId.startsWith('install.')) return 'install-script';
  if (detectorId.startsWith('meta.maintainer')) return 'maintainer-takeover';
  if (detectorId.startsWith('deps.typosquat')) return 'typosquat';
  if (detectorId === 'integrity.hash-mismatch') return 'integrity-tamper';
  if (detectorId.startsWith('deps.local-source')) return 'file-source';
  if (detectorId.startsWith('deps.non-registry-source')) return 'git-source';
  if (detectorId.startsWith('deps.aliased-name')) return 'alias-shadow';
  if (detectorId.startsWith('deps.bundled-dependency')) return 'bundled-payload';
  if (detectorId.startsWith('deps.new-direct-dep')) return 'transitive-injection';
  return 'main-import-side-effect';
}

function detectorsToEvasionTechniques(findings: Finding[]): string[] {
  const techniques = new Set<string>();
  for (const finding of findings) {
    if (finding.detector.startsWith('net.encoded') || finding.detector === 'obf.entropy-jump') {
      techniques.add('obfuscation');
    }
    if (finding.detector === 'code.dynamic-eval' || finding.detector === 'code.reflect-get') {
      techniques.add('dynamic-dispatch');
    }
  }
  return [...techniques];
}

function collectAffectedVersions(findings: Finding[]): string[] {
  const versions = new Set<string>();
  for (const finding of findings) {
    if (finding.to) versions.add(finding.to);
    else if (finding.from) versions.add(finding.from);
  }
  return versions.size > 0 ? [...versions] : ['unknown'];
}

function collectIndicators(findings: Finding[]): Array<{ kind: string; value: string }> {
  const seen = new Set<string>();
  const indicators: Array<{ kind: string; value: string }> = [];
  const reservedTld = /\.(invalid|example|test|localhost)\b/i;

  for (const finding of findings) {
    if (!finding.detector.startsWith('net.') && finding.detector !== 'net.new-endpoint') continue;
    for (const evidence of finding.evidence) {
      const matches = evidence.snippet.matchAll(/https?:\/\/[^\s"'`)<>\]]+/g);
      for (const match of matches) {
        const url = match[0];
        if (!reservedTld.test(url) || seen.has(url)) continue;
        seen.add(url);
        indicators.push({ kind: 'url', value: url });
      }
    }
  }

  return indicators;
}

function isPackageIncidentFinding(finding: Finding): boolean {
  return finding.package.length > 0 && !finding.package.startsWith('<');
}

export interface OsifIncident {
  id: string;
  ecosystem: 'npm' | 'pypi';
  package: string;
  affected_versions: string[];
  entry_point: string;
  capabilities_gained: string[];
  evasion_techniques?: string[];
  delivery?: object;
  indicators?: Array<{ kind: string; value: string }>;
  detectability: {
    signals: string[];
    vetlock_version: string;
    verdict: RunResult['verdict'];
    finding_count: number;
  };
  osif_version: '0.1';
}

export function renderOSIF(result: RunResult): string {
  const byPackageAndDirection = new Map<string, { packageName: string; direction: Finding['direction']; findings: Finding[] }>();

  for (const finding of result.findings) {
    if (!isPackageIncidentFinding(finding)) continue;
    const key = `${finding.package}\u0000${finding.direction}`;
    const group = byPackageAndDirection.get(key);
    if (group) {
      group.findings.push(finding);
      continue;
    }
    byPackageAndDirection.set(key, {
      packageName: finding.package,
      direction: finding.direction,
      findings: [finding],
    });
  }

  const incidents: OsifIncident[] = [];
  const ecosystem = ((result as { ecosystem?: string }).ecosystem === 'pypi' ? 'pypi' : 'npm');
  const year = new Date().getFullYear();

  for (const { packageName, direction, findings } of byPackageAndDirection.values()) {
    const capabilities = [...new Set(findings.map((f) => CATEGORY_TO_OSIF_CAPABILITY[f.category]))];
    const entryPoints = [...new Set(findings.map((f) => detectorToEntryPoint(f.detector)))];
    const indicators = collectIndicators(findings);
    const evasionTechniques = detectorsToEvasionTechniques(findings);

    const incident: OsifIncident = {
      id: `OSIF-${year}-${packageName.toUpperCase().replace(/[^A-Z0-9]/g, '-')}-${direction.toUpperCase()}`,
      ecosystem,
      package: packageName,
      affected_versions: collectAffectedVersions(findings),
      entry_point: entryPoints[0] ?? 'main-import-side-effect',
      capabilities_gained: capabilities.length > 0 ? capabilities : ['code-execution'],
      detectability: {
        signals: [...new Set(findings.map((f) => f.detector))],
        vetlock_version: VETLOCK_VERSION,
        verdict: result.verdict,
        finding_count: findings.length,
      },
      osif_version: '0.1',
    };

    if (evasionTechniques.length > 0) incident.evasion_techniques = evasionTechniques;
    if (indicators.length > 0) incident.indicators = indicators;

    incidents.push(incident);
  }

  return JSON.stringify(incidents, null, 2);
}
