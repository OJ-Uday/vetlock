/**
 * SARIF 2.1.0 renderer — for GitHub code-scanning uploads.
 * We only emit fields GitHub actually reads; the rest is intentionally omitted.
 */

import type { RunResult, Severity } from '@vetlock/core';

const SARIF_LEVEL: Record<Severity, 'error' | 'warning' | 'note'> = {
  BLOCK: 'error',
  WARN: 'warning',
  INFO: 'note',
};

export function renderSARIF(result: RunResult): string {
  const uniqueRules = new Map<string, { id: string; shortDescription: string; category: string }>();
  for (const f of result.findings) {
    if (!uniqueRules.has(f.detector)) {
      uniqueRules.set(f.detector, {
        id: f.detector,
        shortDescription: `${f.category}: ${f.detector}`,
        category: f.category,
      });
    }
  }

  const rules = [...uniqueRules.values()].map((r) => ({
    id: r.id,
    name: r.id,
    shortDescription: { text: r.shortDescription },
    helpUri: 'https://github.com/OJ-Uday/vetlock/blob/main/docs/DETECTIONS.md',
    properties: { category: r.category },
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
            version: '0.0.0',
            rules,
          },
        },
        results,
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}
