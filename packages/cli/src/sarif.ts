/**
 * SARIF 2.1.0 renderer — for GitHub code-scanning uploads.
 * We only emit fields GitHub actually reads; the rest is intentionally omitted.
 *
 * NOTE: A canonical SARIF renderer also lives at
 * `@vetlock/core` → packages/core/src/report/sarif.ts as a library-level export
 * (audit §2.5 architectural borrow). Both share the same level mapping and
 * emit the same rule/result shape; this CLI file also stamps `properties.mitre`
 * per result and rule, so a SIEM consuming the vetlock SARIF can group by
 * ATT&CK technique.
 */

import type { RunResult, Severity } from '@vetlock/core';

const SARIF_LEVEL: Record<Severity, 'error' | 'warning' | 'note'> = {
  BLOCK: 'error',
  WARN: 'warning',
  INFO: 'note',
};

export function renderSARIF(result: RunResult): string {
  const uniqueRules = new Map<string, { id: string; shortDescription: string; category: string; mitre: readonly string[] }>();
  for (const f of result.findings) {
    if (!uniqueRules.has(f.detector)) {
      uniqueRules.set(f.detector, {
        id: f.detector,
        shortDescription: `${f.category}: ${f.detector}`,
        category: f.category,
        mitre: f.mitre ?? [],
      });
    }
  }

  const rules = [...uniqueRules.values()].map((r) => ({
    id: r.id,
    name: r.id,
    shortDescription: { text: r.shortDescription },
    helpUri: 'https://github.com/OJ-Uday/vetlock/blob/main/docs/DETECTIONS.md',
    properties: {
      category: r.category,
      // ATT&CK technique IDs so SIEM / GitHub code-scanning consumers can
      // group findings by kill-chain step; empty array when unmapped.
      mitre: r.mitre,
    },
  }));

  const results = result.findings.map((f) => {
    const first = f.evidence[0]!;
    return {
      ruleId: f.detector,
      level: SARIF_LEVEL[f.severity],
      message: {
        text:
          `[${f.package} ${f.from ?? ''}→${f.to ?? ''}] ${f.message}` +
          (f.provenance.length > 0 ? `\n  via: ${f.provenance[0]!.join(' → ')}` : ''),
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: `${f.package}/${first.file}` },
            region: { startLine: first.line, snippet: { text: first.snippet } },
          },
        },
      ],
      properties: {
        package: f.package,
        from: f.from,
        to: f.to,
        confidence: f.confidence,
        mitre: f.mitre ?? [],
      },
    };
  });

  const sarif = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'vetlock',
            informationUri: 'https://github.com/OJ-Uday/vetlock',
            version: '0.2.0',
            rules,
          },
        },
        results,
        properties: {
          // Top-level riskScore so a GitHub code-scanning summary or SIEM
          // dashboard can render a single number per SARIF run.
          riskScore: result.riskScore,
        },
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}
