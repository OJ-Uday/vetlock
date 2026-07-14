/**
 * OsvScanner — differential adapter for Google's open-source osv-scanner.
 *
 * osv-scanner is a free binary from the OSV project (osv.dev). It reads lockfiles for
 * every common ecosystem (npm, pypi, go, maven, …) and correlates each pinned package/
 * version against the OSV database (advisory data aggregated across GHSA / RustSec /
 * PyPI / npm / Go / OSS-Fuzz). It's a *soft dependency* here — if the binary isn't on
 * PATH we skip cleanly and the differential ledger reports one fewer scanner covered.
 *
 * Contract:
 *   - isAvailable() runs `osv-scanner --version`; true iff exit=0. False on ENOENT.
 *   - scan(lockfilePath) invokes `osv-scanner --format=json --lockfile=<path>` and
 *     parses the JSON.
 *
 * Exit-code semantics: osv-scanner exits **non-zero when vulnerabilities are found** —
 * same convention as `npm audit`. We inspect stdout regardless of exit code.
 *
 * The OSV JSON schema is public (see the osv-scanner project's `output` docs page). We
 * consume only what the ScannerFinding shape requires; extra fields are ignored.
 */

import { spawn } from 'node:child_process';
import type { DifferentialScanner, ScannerFinding } from './types.js';

const SCANNER_ID = 'osv-scanner';

// --- OSV JSON shape (v1). Partial — we only take fields we render. ---

interface OsvPackage {
  readonly name?: string;
  readonly version?: string;
  readonly ecosystem?: string;
}

interface OsvVulnerability {
  readonly id?: string; // e.g. "GHSA-vh95-rmgr-6w4m" or "CVE-2020-7598"
  readonly aliases?: readonly string[];
  readonly summary?: string;
  readonly database_specific?: { readonly severity?: string };
  readonly severity?: readonly { readonly type?: string; readonly score?: string }[];
}

interface OsvPackageResult {
  readonly package?: OsvPackage;
  readonly vulnerabilities?: readonly OsvVulnerability[];
}

interface OsvSourceResult {
  readonly source?: { readonly path?: string; readonly type?: string };
  readonly packages?: readonly OsvPackageResult[];
}

interface OsvReport {
  readonly results?: readonly OsvSourceResult[];
}

function toSeverity(v: OsvVulnerability): ScannerFinding['severity'] {
  const raw = v.database_specific?.severity ?? '';
  switch (raw.toUpperCase()) {
    case 'CRITICAL':
      return 'CRITICAL';
    case 'HIGH':
      return 'HIGH';
    case 'MODERATE':
    case 'MEDIUM':
      return 'MODERATE';
    case 'LOW':
      return 'LOW';
    default:
      return 'INFO';
  }
}

/** Pick a CVE from id or aliases if one exists. */
function extractCve(v: OsvVulnerability): string | undefined {
  const CVE = /^CVE-\d{4}-\d{4,7}$/;
  if (v.id && CVE.test(v.id)) return v.id;
  for (const a of v.aliases ?? []) {
    if (CVE.test(a)) return a;
  }
  return undefined;
}

function parseFindings(report: OsvReport): ScannerFinding[] {
  const out: ScannerFinding[] = [];
  for (const src of report.results ?? []) {
    for (const pkg of src.packages ?? []) {
      const name = pkg.package?.name ?? '<unknown>';
      for (const v of pkg.vulnerabilities ?? []) {
        out.push({
          scanner: SCANNER_ID,
          package: name,
          severity: toSeverity(v),
          cve: extractCve(v),
          title: v.summary ?? v.id ?? 'osv advisory',
          rawMessage: JSON.stringify({ package: name, id: v.id, aliases: v.aliases }),
        });
      }
    }
  }
  return out;
}

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

export class OsvScanner implements DifferentialScanner {
  readonly id = SCANNER_ID;
  readonly name = 'osv-scanner';

  async isAvailable(): Promise<boolean> {
    try {
      const { code } = await run('osv-scanner', ['--version']);
      return code === 0;
    } catch {
      // ENOENT — binary not on PATH. Soft-fail is the whole contract for this scanner.
      return false;
    }
  }

  async scan(lockfilePath: string): Promise<ScannerFinding[]> {
    const { code, stdout, stderr } = await run('osv-scanner', [
      '--format=json',
      `--lockfile=${lockfilePath}`,
    ]);
    if (!stdout || stdout.trim().length === 0) {
      throw new Error(
        `osv-scanner produced no stdout (exit=${code ?? '<null>'}): ${stderr.slice(0, 500)}`,
      );
    }
    let parsed: OsvReport;
    try {
      parsed = JSON.parse(stdout) as OsvReport;
    } catch (err) {
      throw new Error(
        `osv-scanner stdout was not JSON (exit=${code ?? '<null>'}): ${(err as Error).message}`,
      );
    }
    return parseFindings(parsed);
  }
}
