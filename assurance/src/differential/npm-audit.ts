/**
 * NpmAuditScanner — differential adapter for the built-in `npm audit`.
 *
 * npm audit is the ecosystem's default advisory-DB check. It reads a package-lock.json
 * and queries the GitHub Advisory Database / npm registry advisories endpoint for known
 * CVEs affecting the pinned versions. Nearly every npm project runs it.
 *
 * Contract with the differential pipeline:
 *   - isAvailable() runs `npm --version`; true iff exit=0. npm ships with Node.
 *   - scan(lockfilePath) copies the lockfile into a fresh temp dir (npm needs the
 *     package-lock.json in a directory it can write to), runs `npm audit --json
 *     --package-lock-only`, parses the JSON, and returns normalized ScannerFindings.
 *
 * Exit-code semantics: `npm audit` exits **non-zero when vulnerabilities are found**.
 * That's not an adapter error — it's the whole point. We inspect stdout regardless of
 * exit code; only a missing / malformed JSON body is treated as a real failure. Network
 * failures inside npm audit render as `{"error": {…}}` in stdout — those we surface as a
 * thrown adapter error so the caller can decide whether to skip (e.g., CI-offline).
 */

import { spawn } from 'node:child_process';
import { mkdtemp, copyFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, basename } from 'node:path';
import type { DifferentialScanner, ScannerFinding } from './types.js';

const SCANNER_ID = 'npm-audit';

// --- npm audit JSON shape (v2). Kept intentionally partial — only fields we consume. ---

interface NpmAuditVia {
  readonly source?: number;
  readonly name?: string;
  readonly title?: string;
  readonly url?: string;
  readonly severity?: string; // 'info' | 'low' | 'moderate' | 'high' | 'critical'
  readonly cwe?: readonly string[];
  readonly cve?: readonly string[]; // sometimes present on advisory records
}

interface NpmAuditVulnerability {
  readonly name?: string;
  readonly severity?: string;
  readonly via?: ReadonlyArray<NpmAuditVia | string>;
}

interface NpmAuditReport {
  readonly auditReportVersion?: number;
  readonly vulnerabilities?: Readonly<Record<string, NpmAuditVulnerability>>;
  /** Present on network / registry failures. npm's shape varies across versions — we
   *  accept either an object OR a top-level `message` string. */
  readonly error?: { readonly code?: string; readonly summary?: string; readonly detail?: string };
  readonly message?: string;
}

/** Normalize an npm-audit severity string (lower-case) to the ScannerFinding severity. */
function toSeverity(s: string | undefined): ScannerFinding['severity'] {
  switch ((s ?? '').toLowerCase()) {
    case 'critical':
      return 'CRITICAL';
    case 'high':
      return 'HIGH';
    case 'moderate':
      return 'MODERATE';
    case 'low':
      return 'LOW';
    default:
      // 'info' + anything unrecognized collapse to INFO. Better than dropping the finding.
      return 'INFO';
  }
}

/** Pull the first CVE-YYYY-NNNNN we can find on a `via` entry. */
function extractCve(via: NpmAuditVia): string | undefined {
  if (via.cve && via.cve.length > 0) {
    for (const c of via.cve) {
      if (/^CVE-\d{4}-\d{4,7}$/.test(c)) return c;
    }
  }
  // Some npm advisories embed CVE ids in the title; extract if present.
  if (via.title) {
    const m = /CVE-\d{4}-\d{4,7}/.exec(via.title);
    if (m) return m[0];
  }
  return undefined;
}

function parseFindings(report: NpmAuditReport): ScannerFinding[] {
  if (report.error || report.message) {
    // Two npm shapes for a failure body:
    //   { "error": { "code": "...", "summary": "..." } }
    //   { "message": "request to ... failed, reason: ...", "error": { "summary": "", "detail": "" } }
    // Prefer the top-level `message` when present because it carries the real cause;
    // fall back to `error.code`/`error.summary`.
    const code = report.error?.code ?? 'audit-error';
    const summary =
      report.message ??
      report.error?.summary ??
      report.error?.detail ??
      '<no detail>';
    throw new Error(`npm audit reported error: ${code} — ${summary}`);
  }
  const out: ScannerFinding[] = [];
  const vulns = report.vulnerabilities ?? {};
  for (const [pkg, vuln] of Object.entries(vulns)) {
    const via = vuln.via ?? [];
    for (const entry of via) {
      // `via` can be a string (name of another package in the chain — not an advisory
      // itself; skip). Advisory records are objects.
      if (typeof entry === 'string') continue;
      const title = entry.title ?? `${pkg} vulnerability`;
      const severity = toSeverity(entry.severity ?? vuln.severity);
      out.push({
        scanner: SCANNER_ID,
        package: pkg,
        severity,
        cve: extractCve(entry),
        title,
        rawMessage: JSON.stringify({ package: pkg, via: entry }),
      });
    }
  }
  return out;
}

/** Run a subprocess, collect stdout/stderr/exit, no shell interpolation. */
function run(
  cmd: string,
  args: readonly string[],
  cwd?: string,
): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, [...args], { cwd, stdio: ['ignore', 'pipe', 'pipe'] });
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

export class NpmAuditScanner implements DifferentialScanner {
  readonly id = SCANNER_ID;
  readonly name = 'npm audit';

  async isAvailable(): Promise<boolean> {
    try {
      const { code } = await run('npm', ['--version']);
      return code === 0;
    } catch {
      return false;
    }
  }

  async scan(lockfilePath: string): Promise<ScannerFinding[]> {
    // npm audit needs a directory containing package-lock.json (and tolerates a missing
    // package.json when --package-lock-only is passed with a v2/v3 lockfile that already
    // records the root package). We copy the lockfile into a fresh tmp dir so we don't
    // pollute the caller's tree.
    const tmp = await mkdtemp(join(tmpdir(), 'vetlock-npm-audit-'));
    try {
      const dest = join(tmp, 'package-lock.json');
      await copyFile(lockfilePath, dest);
      const { code, stdout, stderr } = await run(
        'npm',
        ['audit', '--json', '--package-lock-only'],
        tmp,
      );
      if (!stdout || stdout.trim().length === 0) {
        // npm couldn't produce a report at all — this is a real adapter failure.
        throw new Error(
          `npm audit produced no stdout (exit=${code ?? '<null>'}, lockfile=${basename(lockfilePath)}): ${stderr.slice(0, 500)}`,
        );
      }
      let parsed: NpmAuditReport;
      try {
        parsed = JSON.parse(stdout) as NpmAuditReport;
      } catch (err) {
        throw new Error(
          `npm audit stdout was not JSON (exit=${code ?? '<null>'}): ${(err as Error).message}`,
        );
      }
      return parseFindings(parsed);
    } finally {
      await rm(tmp, { recursive: true, force: true }).catch(() => {
        // Swallow cleanup failures — the OS will collect the tmpdir eventually.
      });
    }
  }
}
