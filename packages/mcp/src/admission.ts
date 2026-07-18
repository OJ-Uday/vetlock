/**
 * Scan-only admission primitives used by the MCP transport.
 *
 * Never-execute invariant: this module fetches tarball bytes and statically
 * analyzes them. It never calls npm/pnpm/yarn, imports package code, or spawns
 * a process based on a caller-controlled package or lockfile.
 */
import { createHash } from 'node:crypto';
import { promises as fs } from 'node:fs';
import * as path from 'node:path';
import {
  analyzeTarball,
  computeRiskScore,
  fetchTarball,
  parsePackageSpec,
  runDiff,
  type Finding,
  type RunResult,
} from '@vetlock/core';
import { runAll } from '@vetlock/detectors';

export type AdmissionDecision = 'allow' | 'review' | 'block';
export const MAX_LOCKFILE_BYTES = 5 * 1024 * 1024;

export interface Policy {
  /** Finding severities that require a human decision. Defaults to WARN, INFO. */
  reviewSeverities?: Array<'WARN' | 'INFO'>;
  /** Finding severities that must not be admitted. Defaults to BLOCK. */
  blockSeverities?: Array<'BLOCK' | 'WARN' | 'INFO'>;
  /** Block malformed/unavailable analysis instead of allowing it. Defaults true. */
  failClosed?: boolean;
}

export interface PackageAnalysis {
  package: { name: string; requestedVersion: string; resolvedVersion: string };
  artifactSha256: string;
  projectHash: string;
  findings: Finding[];
  riskScore: number;
  neverExecuted: true;
}

export interface AdmissionReceipt {
  version: 1;
  kind: 'vetlock-admission-receipt';
  integrity: 'sha256-deterministic-unsigned';
  package: string;
  packageVersion: string;
  artifactSha256: string;
  projectHash: string;
  policyHash: string;
  findingsHash: string;
  decision: AdmissionDecision;
  issuedAt: string;
  receiptHash: string;
  /** Receipts protect integrity only; authenticity requires user-managed signing keys. */
  authenticity: 'not-signed';
}

export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const obj = value as Record<string, unknown>;
  return `{${Object.keys(obj).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(obj[key])}`).join(',')}}`;
}

export function sha256(value: string | Buffer): string {
  return createHash('sha256').update(value).digest('hex');
}

export function normalizedPolicy(policy: Policy = {}): Required<Policy> {
  return {
    reviewSeverities: [...new Set(policy.reviewSeverities ?? ['WARN', 'INFO'])].sort() as Array<'WARN' | 'INFO'>,
    blockSeverities: [...new Set(policy.blockSeverities ?? ['BLOCK'])].sort() as Array<'BLOCK' | 'WARN' | 'INFO'>,
    failClosed: policy.failClosed ?? true,
  };
}

export function evaluatePolicy(findings: readonly Finding[], policy: Policy = {}): {
  decision: AdmissionDecision;
  policy: Required<Policy>;
  reasons: string[];
} {
  const resolved = normalizedPolicy(policy);
  const seen = new Set(findings.map((finding) => finding.severity));
  const blocked = resolved.blockSeverities.filter((severity) => seen.has(severity));
  if (blocked.length) return { decision: 'block', policy: resolved, reasons: [`blocking severity present: ${blocked.join(', ')}`] };
  const review = resolved.reviewSeverities.filter((severity) => seen.has(severity));
  if (review.length) return { decision: 'review', policy: resolved, reasons: [`review severity present: ${review.join(', ')}`] };
  return { decision: 'allow', policy: resolved, reasons: ['no finding matches the configured block or review policy'] };
}

function assertRegularPath(filePath: string): string {
  if (!path.isAbsolute(filePath)) throw new Error('lockfile paths must be absolute');
  return path.resolve(filePath);
}

export async function readLockfile(filePath: string): Promise<{ path: string; text: string; sha256: string }> {
  const resolved = assertRegularPath(filePath);
  const stat = await fs.stat(resolved);
  if (!stat.isFile()) throw new Error(`not a regular file: ${resolved}`);
  if (stat.size > MAX_LOCKFILE_BYTES) throw new Error(`lockfile exceeds ${MAX_LOCKFILE_BYTES} byte limit`);
  const text = await fs.readFile(resolved, 'utf8');
  return { path: resolved, text, sha256: sha256(text) };
}

export async function analyzeLockfileChange(beforePath: string, afterPath: string): Promise<RunResult & {
  lockfiles: { before: { path: string; sha256: string }; after: { path: string; sha256: string } };
  neverExecuted: true;
}> {
  const [before, after] = await Promise.all([readLockfile(beforePath), readLockfile(afterPath)]);
  const result = await runDiff(before.text, after.text, {
    oldLockfilePath: before.path,
    newLockfilePath: after.path,
    runDetectors: (pair) => runAll(pair),
  });
  return {
    ...result,
    lockfiles: { before: { path: before.path, sha256: before.sha256 }, after: { path: after.path, sha256: after.sha256 } },
    neverExecuted: true,
  };
}

async function installedVersion(projectDirectory: string, packageName: string): Promise<string | null> {
  const manifestPath = path.join(projectDirectory, 'node_modules', packageName, 'package.json');
  try {
    const parsed: unknown = JSON.parse(await fs.readFile(manifestPath, 'utf8'));
    const version = typeof parsed === 'object' && parsed !== null ? (parsed as { version?: unknown }).version : undefined;
    return typeof version === 'string' ? version : null;
  } catch { return null; }
}

/**
 * Reuses the Wave 8 gate's safe fetch/analyze/detect sequence, but deliberately
 * stops before its package-manager shellout. The returned artifact hash binds a
 * future receipt to the exact bytes that were analyzed.
 */
export async function analyzePackageInstall(spec: string, projectDirectory: string, registry?: string): Promise<PackageAnalysis> {
  const parsed = parsePackageSpec(spec);
  if (!parsed) throw new Error(`invalid package spec: ${spec}`);
  const projectPath = path.resolve(projectDirectory);
  if (!(await fs.stat(projectPath)).isDirectory()) throw new Error('projectDirectory must be an existing directory');
  const tarballPath = await fetchTarball({ name: parsed.name, version: parsed.version, registry });
  try {
    const bytes = await fs.readFile(tarballPath);
    const newSnapshot = await analyzeTarball(tarballPath);
    const previous = await installedVersion(projectPath, parsed.name);
    let oldSnapshot = null;
    if (previous && previous !== newSnapshot.version) {
      const oldTarball = await fetchTarball({ name: parsed.name, version: previous, registry });
      try { oldSnapshot = await analyzeTarball(oldTarball); } finally { await fs.unlink(oldTarball).catch(() => undefined); }
    }
    const findings = runAll({ old: oldSnapshot, new: newSnapshot });
    const projectHash = sha256(canonicalJson({ projectDirectory: projectPath, package: parsed.name, installedVersion: previous }));
    return {
      package: { name: parsed.name, requestedVersion: parsed.version, resolvedVersion: newSnapshot.version },
      artifactSha256: sha256(bytes),
      projectHash,
      findings,
      riskScore: computeRiskScore(findings),
      neverExecuted: true,
    };
  } finally {
    await fs.unlink(tarballPath).catch(() => undefined);
  }
}

export function createReceipt(input: Omit<AdmissionReceipt, 'version' | 'kind' | 'integrity' | 'receiptHash' | 'authenticity'>): AdmissionReceipt {
  const unsigned = {
    version: 1 as const,
    kind: 'vetlock-admission-receipt' as const,
    integrity: 'sha256-deterministic-unsigned' as const,
    ...input,
    authenticity: 'not-signed' as const,
  };
  return { ...unsigned, receiptHash: sha256(canonicalJson(unsigned)) };
}

export function verifyReceipt(receipt: AdmissionReceipt): { valid: boolean; reason: string } {
  if (receipt.version !== 1 || receipt.kind !== 'vetlock-admission-receipt') return { valid: false, reason: 'unsupported receipt format' };
  if (receipt.integrity !== 'sha256-deterministic-unsigned' || receipt.authenticity !== 'not-signed') return { valid: false, reason: 'unsupported receipt integrity mode' };
  const { receiptHash, ...unsigned } = receipt;
  return sha256(canonicalJson(unsigned)) === receiptHash
    ? { valid: true, reason: 'receipt hash is intact; receipt is unsigned and does not prove issuer identity' }
    : { valid: false, reason: 'receipt hash does not match its contents' };
}

export function explainFinding(findings: readonly Finding[], detector: string, packageName?: string): Finding[] {
  return findings.filter((finding) => finding.detector === detector && (!packageName || finding.package === packageName));
}
