/**
 * GuarddogScanner — differential adapter for DataDog's `guarddog` CLI.
 *
 * guarddog (Apache-2.0, github.com/DataDog/guarddog) is the closest OSS peer to vetlock.
 * It runs YARA source-code rules and Python metadata heuristics over a single package
 * version. It produces a JSON report whose top level includes a `risks[]` array — each
 * risk is a capability × threat correlation that guarddog scored high enough to surface.
 *
 * Contract with the differential pipeline (mirrors NpmAuditScanner / OsvScanner):
 *   - isAvailable() runs `guarddog --version`; true iff exit=0. False on ENOENT — the
 *     binary is a soft dependency (Python + `uv tool install guarddog` or `pip install`).
 *   - scan(lockfilePath) invokes `guarddog npm scan --output-format=json <target>` and
 *     parses the JSON. The target is derived from the lockfile: the differential pipeline
 *     runs the adapter with a lockfile path, but guarddog itself needs a package
 *     name+version (or a local tarball). For the offline / seeded ledger path we do NOT
 *     resolve packages at scan time — the fixture-level `seededDeltas` cover the ten
 *     historical corpus fixtures. This adapter is invoked live only in E2E mode
 *     (`GUARDDOG_E2E=1`) where the target is passed via a second argument path.
 *
 * Exit-code semantics: `guarddog` exits **non-zero when findings are detected**, matching
 * `npm audit` / `osv-scanner`. stdout is inspected regardless of exit code.
 *
 * JSON output shape (from guarddog/analyzer/analyzer.py `analyze()` return value, and
 * guarddog/reporters/json.py):
 *     {
 *       "issues": <int>,               // total number of rule matches
 *       "errors": {...},               // per-rule errors, if any
 *       "results": {...},              // per-rule match details
 *       "path": "<local path>",        // scanned target
 *       "risk_score": {...},           // 0-10 aggregated score + factors
 *       "risks": [                     // correlated risk objects — what we consume
 *         {
 *           "name":               "<risk name>",
 *           "category":           "<risk category>",
 *           "severity":           "low" | "medium" | "high",
 *           "mitre_tactics":      "<comma-separated tactics>",
 *           "threat_identifies":  "<threat.*>",
 *           "threat_rule":        "<yara rule name>",
 *           "threat_description": "<match description>",
 *           "threat_location":    "<file:line>",
 *           "threat_code":        "<snippet>",
 *           "threat_match":       "<exact match bytes>",
 *           "capability_identifies": "<capability.*> | null",
 *           "capability_rule":       "<yara rule name> | null",
 *           "file_path":             "<file>"
 *         }
 *       ]
 *     }
 *
 * The `risks[]` array is what we surface as ScannerFinding[] — one Finding per risk.
 * Per-rule `results[]` entries WITHOUT a matching risk (unpaired capabilities, unpaired
 * threats below correlation threshold) are DELIBERATELY not surfaced: guarddog's own
 * design says those are alert-fatigue and should not gate CI.
 */

import { spawn } from 'node:child_process';
import type { DifferentialScanner, ScannerFinding } from './types.js';

const SCANNER_ID = 'guarddog';

// --- guarddog JSON shape (partial). Only fields we consume are typed. ---

interface GuarddogRisk {
  readonly name?: string;
  readonly category?: string;
  readonly severity?: string; // 'low' | 'medium' | 'high'
  readonly mitre_tactics?: string;
  readonly threat_identifies?: string;
  readonly threat_rule?: string;
  readonly threat_description?: string;
  readonly threat_location?: string;
  readonly capability_identifies?: string | null;
  readonly capability_rule?: string | null;
  readonly file_path?: string;
}

interface GuarddogReport {
  readonly issues?: number;
  readonly errors?: Record<string, string>;
  readonly path?: string;
  readonly risk_score?: {
    readonly score?: number;
    readonly label?: string;
  };
  readonly risks?: readonly GuarddogRisk[];
  /** Failure body — either a top-level message or a nested error object. Mirrors the
   *  npm-audit adapter's shape for consistency across scanners. */
  readonly error?: { readonly code?: string; readonly summary?: string; readonly detail?: string };
  readonly message?: string;
}

/**
 * Normalize a guarddog severity (`low`/`medium`/`high`) to the ScannerFinding severity.
 *
 * guarddog does not use CRITICAL — its top band is `high` (which correlates to a risk
 * score >= 7.6 in the risk engine). We map `high` to `HIGH` and reserve `CRITICAL` for
 * scanners that produce it natively.
 */
function toSeverity(s: string | undefined): ScannerFinding['severity'] {
  switch ((s ?? '').toLowerCase()) {
    case 'high':
      return 'HIGH';
    case 'medium':
      return 'MODERATE';
    case 'low':
      return 'LOW';
    default:
      // Anything unrecognized collapses to INFO. guarddog's own JSON only ever emits the
      // three values above; falling into INFO would signal a schema drift worth logging.
      return 'INFO';
  }
}

/**
 * Derive a "package" label for the ScannerFinding.
 *
 * guarddog operates on a single target and doesn't tag each finding with a package name
 * (the whole scan IS about one package). We surface the file-path relative fragment when
 * present, else the guarddog-reported top-level `path` field, else `<guarddog-target>`.
 * The differential ledger uses this for de-duping — meaningful string is enough.
 */
function derivePackage(risk: GuarddogRisk, reportPath: string | undefined): string {
  if (risk.file_path && risk.file_path.length > 0) return risk.file_path;
  if (reportPath && reportPath.length > 0) return reportPath;
  return '<guarddog-target>';
}

function parseFindings(report: GuarddogReport): ScannerFinding[] {
  if (report.error || report.message) {
    // Two failure shapes mirroring npm-audit's behavior:
    //   { "error": { "code": "...", "summary": "..." } }
    //   { "message": "...", "error": { ... } }
    const code = report.error?.code ?? 'guarddog-error';
    const summary =
      report.message ??
      report.error?.summary ??
      report.error?.detail ??
      '<no detail>';
    throw new Error(`guarddog reported error: ${code} — ${summary}`);
  }
  const out: ScannerFinding[] = [];
  const risks = report.risks ?? [];
  for (const risk of risks) {
    const title =
      risk.name ??
      risk.threat_description ??
      risk.threat_rule ??
      'guarddog risk';
    const severity = toSeverity(risk.severity);
    // rawMessage preserves the correlation shape (threat rule + capability rule +
    // MITRE tactic + file:line) so the ledger has enough evidence for triage.
    const rawMessage = JSON.stringify({
      threat_rule: risk.threat_rule ?? null,
      threat_identifies: risk.threat_identifies ?? null,
      capability_rule: risk.capability_rule ?? null,
      capability_identifies: risk.capability_identifies ?? null,
      mitre_tactics: risk.mitre_tactics ?? null,
      location: risk.threat_location ?? null,
      file_path: risk.file_path ?? null,
    });
    out.push({
      scanner: SCANNER_ID,
      package: derivePackage(risk, report.path),
      severity,
      cve: undefined, // guarddog does not tag risks with CVE IDs (it's behavioral)
      title,
      rawMessage,
    });
  }
  return out;
}

/** Run a subprocess with stdout/stderr capture. No shell interpolation. */
function run(
  cmd: string,
  args: readonly string[],
): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, [...args], { stdio: ['ignore', 'pipe', 'pipe'] });
    const stdoutChunks: Buffer[] = [];
    const stderrChunks: Buffer[] = [];
    child.stdout.on('data', (b: Buffer) => stdoutChunks.push(b));
    child.stderr.on('data', (b: Buffer) => stderrChunks.push(b));
    child.on('error', (err) => reject(err));
    child.on('close', (code) => {
      resolve({
        code,
        stdout: Buffer.concat(stdoutChunks).toString('utf-8'),
        stderr: Buffer.concat(stderrChunks).toString('utf-8'),
      });
    });
  });
}

/**
 * Derive a guarddog scan target from a lockfile path.
 *
 * The other differential adapters (npm-audit, osv-scanner) take a LOCKFILE and read
 * pinned versions from it. guarddog takes either a package NAME (which requires network
 * fetch and is not appropriate for a synchronous CI adapter) or a local TARBALL/DIRECTORY.
 *
 * The adapter's scan() interface is `scan(lockfilePath)` for symmetry. We resolve the
 * scan target as follows:
 *   - If `GUARDDOG_TARGET` env var is set, use that path (tarball or directory).
 *   - Otherwise, resolve `<dirname(lockfilePath)>` and scan the whole tree — guarddog
 *     handles a directory target by walking it and applying the YARA rules to every
 *     matching file, which is what a differential run over a project should exercise.
 *
 * This keeps the offline / airgapped path clean: no registry fetches, no package-name
 * resolution — either you point at a real artifact or the seeded-deltas ledger carries
 * the historical outcomes.
 */
function resolveTarget(lockfilePath: string): string {
  const envTarget = process.env.GUARDDOG_TARGET;
  if (envTarget && envTarget.length > 0) return envTarget;
  // Directory the lockfile is in. guarddog accepts a directory as a scan target.
  // We avoid path.dirname import churn — a simple last-slash split is fine here.
  const idx = lockfilePath.lastIndexOf('/');
  return idx > 0 ? lockfilePath.slice(0, idx) : '.';
}

export class GuarddogScanner implements DifferentialScanner {
  readonly id = SCANNER_ID;
  readonly name = 'guarddog';

  async isAvailable(): Promise<boolean> {
    try {
      const { code } = await run('guarddog', ['--version']);
      return code === 0;
    } catch {
      // ENOENT — binary not on PATH. Soft-fail per the DifferentialScanner contract.
      return false;
    }
  }

  async scan(lockfilePath: string): Promise<ScannerFinding[]> {
    const target = resolveTarget(lockfilePath);
    // `guarddog npm scan --output-format=json <target>` — the `npm` sub-command drives
    // the npm-ecosystem ruleset. For cross-ecosystem probes (e.g. a PyPI target) the
    // subcommand would be `pypi`; that lives behind an env var
    // (`GUARDDOG_ECOSYSTEM`) for the E2E hosts that care to switch it.
    const ecosystem = process.env.GUARDDOG_ECOSYSTEM ?? 'npm';
    const { code, stdout, stderr } = await run('guarddog', [
      ecosystem,
      'scan',
      '--output-format=json',
      target,
    ]);
    if (!stdout || stdout.trim().length === 0) {
      throw new Error(
        `guarddog produced no stdout (exit=${code ?? '<null>'}, target=${target}): ${stderr.slice(0, 500)}`,
      );
    }
    let parsed: GuarddogReport;
    try {
      parsed = JSON.parse(stdout) as GuarddogReport;
    } catch (err) {
      throw new Error(
        `guarddog stdout was not JSON (exit=${code ?? '<null>'}): ${(err as Error).message}`,
      );
    }
    return parseFindings(parsed);
  }
}
