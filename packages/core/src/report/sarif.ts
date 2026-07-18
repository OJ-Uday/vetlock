/**
 * SARIF 2.1.0 renderer — a first-class report format (audit §2.5 architectural
 * borrow). Emits a JSON string that validates against the SARIF v2.1.0 schema
 * enough for GitHub code-scanning ingest, Sonarqube import, and generic SIEM
 * pipelines that parse `runs[].results[]`.
 *
 * Spec:
 *   https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
 *
 * Level mapping (audit §2.5):
 *   vetlock BLOCK → SARIF error
 *   vetlock WARN  → SARIF warning
 *   vetlock INFO  → SARIF note
 *
 * Extra properties (SIEM-friendly extensions — SARIF permits arbitrary
 * `properties` bags on rules, results, and runs):
 *   - runs[].properties.riskScore         — RunResult.riskScore (0-10)
 *   - runs[].properties.verdict           — CLEAN / INFO / WARN / BLOCK
 *   - runs[].tool.driver.rules[].properties.category — vetlock category
 *   - runs[].tool.driver.rules[].properties.mitre    — ATT&CK technique IDs
 *   - runs[].results[].properties.package/from/to/confidence/mitre
 *
 * Deliberate omissions (kept small on purpose — see cli/src/sarif.ts for the
 * CLI-facing renderer that adds helpUri and other GitHub-code-scanning
 * niceties):
 *   - No `artifactChanges` or `graphs` — vetlock's diff model doesn't map
 *     cleanly to SARIF's edit-oriented graph model.
 *   - No `taxonomies` — MITRE technique IDs travel as bare property strings.
 */

import type { Severity } from '../finding.js';
import type { RunResult } from '../engine.js';

const SARIF_LEVEL: Record<Severity, 'error' | 'warning' | 'note'> = {
  BLOCK: 'error',
  WARN: 'warning',
  INFO: 'note',
};

export interface SarifRenderOptions {
  /** Tool driver name; defaults to 'vetlock'. */
  driverName?: string;
  /** Tool driver informationUri; defaults to the vetlock repo. */
  driverInformationUri?: string;
  /** Tool driver semver; defaults to the vetlock package version. */
  driverVersion?: string;
  /**
   * Whether the output should be pretty-printed with 2-space indentation.
   * Defaults to true (SARIF is usually consumed by humans in CI logs).
   */
  pretty?: boolean;
}

/**
 * Render a RunResult as a SARIF 2.1.0 JSON string. See module docstring for
 * the field-mapping rules; see SARIF v2.1.0 spec for the schema.
 */
export function toSarif(result: RunResult, opts: SarifRenderOptions = {}): string {
  const driverName = opts.driverName ?? 'vetlock';
  const driverInformationUri = opts.driverInformationUri ?? 'https://github.com/OJ-Uday/vetlock';
  const driverVersion = opts.driverVersion ?? 'unknown';

  const uniqueRules = new Map<string, { id: string; category: string; mitre: readonly string[] }>();
  for (const f of result.findings) {
    if (!uniqueRules.has(f.detector)) {
      uniqueRules.set(f.detector, {
        id: f.detector,
        category: f.category,
        mitre: f.mitre ?? [],
      });
    }
  }

  const rules = [...uniqueRules.values()].map((r) => ({
    id: r.id,
    name: r.id,
    shortDescription: { text: `${r.category}: ${r.id}` },
    properties: {
      category: r.category,
      mitre: r.mitre,
    },
  }));

  const results = result.findings.map((f) => {
    // Every emitted Finding has evidence[0] by schema (validateFinding). If
    // some future path emits without evidence, we synthesize a package-level
    // location so the SARIF still validates rather than crashing here.
    const first = f.evidence[0];
    const uri = first ? `${f.package}/${first.file}` : f.package;
    const region = first ? { startLine: first.line, snippet: { text: first.snippet } } : { startLine: 1 };
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
            artifactLocation: { uri },
            region,
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
            name: driverName,
            informationUri: driverInformationUri,
            version: driverVersion,
            rules,
          },
        },
        results,
        properties: {
          verdict: result.verdict,
          riskScore: result.riskScore,
        },
      },
    ],
  };

  return opts.pretty === false ? JSON.stringify(sarif) : JSON.stringify(sarif, null, 2);
}
