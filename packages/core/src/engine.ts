/**
 * Recursive engine — the product.
 *
 * Given two lockfiles (before and after), computes the changeset, fetches +
 * analyzes each changed node concurrently through a bounded worker pool, runs
 * detectors on each pair, and produces a RunResult with findings, provenance,
 * and per-direct-dep rollup.
 *
 * IO here is intentional (fetch, extract). Detectors themselves are pure and
 * live in packages/detectors — they get called via a `runDetectors` closure so
 * the engine doesn't depend on that package at compile time (circular avoided).
 */

import { promises as fs } from 'node:fs';
import type {
  Finding,
  PackageSnapshot,
  SnapshotPair,
  Severity,
} from './finding.js';
import {
  parseLockfile,
  shortestPaths,
  type LockGraph,
} from './lockfile.js';
import { computeChangeset, type Change } from './changeset.js';
import { fetchTarball, type PackageRef } from './fetch.js';
import { analyzeTarball } from './analyze.js';
import { makeCache, type SnapshotCache } from './cache.js';

export interface EngineOptions {
  /** Called for each changed node with the (old, new) snapshot pair. Impl in @vetlock/detectors. */
  runDetectors: (pair: SnapshotPair, packageName: string) => Finding[];
  /** Concurrency for fetch+analyze (default: os.cpus().length - 1, min 2, max 8). */
  concurrency?: number;
  /** Per-package total timeout in ms (default 90_000). */
  timeoutMs?: number;
  /** Cache instance; default uses ~/.cache/vetlock/analysis. */
  cache?: SnapshotCache;
  /**
   * Override the fetch step — the engine will call this instead of the default
   * pacote-backed fetchTarball. Useful for offline tests and corpus replay
   * (points at file:// or local paths).
   */
  fetchOverride?: (ref: PackageRef & { resolved?: string | null }) => Promise<string>;
  /** Progress callback (optional). */
  onProgress?: (event: ProgressEvent) => void;
}

export type ProgressEvent =
  | { kind: 'start'; total: number }
  | { kind: 'analyze'; packageName: string; version: string }
  | { kind: 'cache-hit'; packageName: string; version: string }
  | { kind: 'error'; packageName: string; error: string }
  | { kind: 'done'; total: number; withFindings: number };

export interface RunResult {
  /** Aggregate max severity across all findings. */
  verdict: Severity | 'CLEAN';
  findings: Finding[];
  /** name → { max severity, count } for direct deps (root's dependency list). */
  rollupByDirect: Record<string, { maxSeverity: Severity | 'CLEAN'; count: number }>;
  /** ChangeSet echoed back for reporting. */
  changes: Change[];
  /** Errors we swallowed (per-package) so the run could continue. */
  errors: Array<{ package: string; version: string; error: string }>;
  /** Timing info. */
  durationMs: number;
}

export async function runDiff(
  oldLockfileText: string,
  newLockfileText: string,
  opts: EngineOptions,
): Promise<RunResult> {
  const t0 = Date.now();
  const oldG = parseLockfile(JSON.parse(oldLockfileText));
  const newG = parseLockfile(JSON.parse(newLockfileText));

  const changes = computeChangeset(oldG, newG);
  opts.onProgress?.({ kind: 'start', total: changes.length });

  const cache = opts.cache ?? makeCache();
  const conc = clamp(opts.concurrency ?? ((cpuCount() ?? 3) - 1), 2, 8);

  // Snapshot fetch/analyze per (name, version, integrity) — dedup across changes that
  // point at the same tarball.
  interface PackageRefFull { name: string; version: string; integrity: string; resolved: string | null; }
  const refs = new Map<string, PackageRefFull>();
  for (const c of changes) {
    if (c.kind !== 'removed' && c.newVersion) {
      const id = `${c.name}@${c.newVersion}`;
      const node = c.nodeKeyNew ? newG.nodes.get(c.nodeKeyNew) : null;
      refs.set(id, {
        name: c.name,
        version: c.newVersion,
        integrity: c.newIntegrity ?? '',
        resolved: node?.resolved ?? null,
      });
    }
    if (c.kind !== 'added' && c.oldVersion) {
      const id = `${c.name}@${c.oldVersion}`;
      const node = c.nodeKeyOld ? oldG.nodes.get(c.nodeKeyOld) : null;
      refs.set(id, {
        name: c.name,
        version: c.oldVersion,
        integrity: c.oldIntegrity ?? '',
        resolved: node?.resolved ?? null,
      });
    }
  }

  const snapshots = new Map<string, PackageSnapshot>();
  const errors: Array<{ package: string; version: string; error: string }> = [];

  const refList = [...refs.entries()];
  let idx = 0;
  await Promise.all(
    Array.from({ length: conc }, () => (async () => {
      while (true) {
        const cursor = idx++;
        if (cursor >= refList.length) return;
        const [id, ref] = refList[cursor]!;
        try {
          const snap = await analyzeOne(ref, cache, opts);
          snapshots.set(id, snap);
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          errors.push({ package: ref.name, version: ref.version, error: msg });
          opts.onProgress?.({ kind: 'error', packageName: ref.name, error: msg });
        }
      }
    })()),
  );

  const findings: Finding[] = [];

  for (const change of changes) {
    const oldSnap = change.oldVersion
      ? snapshots.get(`${change.name}@${change.oldVersion}`) ?? null
      : null;
    const newSnap = change.newVersion
      ? snapshots.get(`${change.name}@${change.newVersion}`) ?? null
      : null;

    const pair: SnapshotPair = { old: oldSnap, new: newSnap };
    // Integrity-changed always produces a synthetic finding, regardless of content diff.
    if (change.kind === 'integrity-changed') {
      findings.push({
        detector: 'integrity.hash-mismatch',
        category: 'INTEG',
        package: change.name,
        from: change.oldVersion,
        to: change.newVersion,
        direction: 'changed',
        severity: 'BLOCK',
        confidence: 'high',
        message:
          `Same version, different integrity: ${change.oldIntegrity} → ${change.newIntegrity}. Registry-side or in-flight tamper.`,
        evidence: [
          {
            file: 'package.json',
            line: 1,
            snippet: `integrity ${change.oldIntegrity} → ${change.newIntegrity}`,
          },
        ],
        provenance: [],
      });
      continue;
    }

    const detected = opts.runDetectors(pair, change.name);
    // Attach provenance for nodes in the new graph.
    const provenanceKey = change.nodeKeyNew;
    let paths: string[][] = [];
    if (provenanceKey) {
      paths = shortestPaths(newG, provenanceKey, 3);
    }
    for (const f of detected) {
      f.provenance = paths;
    }
    findings.push(...detected);
  }

  // Determinism: sort findings by (severity high→low, package, detector, first-evidence).
  findings.sort(byFindingKey);

  // Compute verdict.
  let verdict: Severity | 'CLEAN' = 'CLEAN';
  for (const f of findings) {
    if (f.severity === 'BLOCK') {
      verdict = 'BLOCK';
      break;
    }
    if (f.severity === 'WARN' && verdict !== 'WARN') {
      verdict = 'WARN';
    } else if (f.severity === 'INFO' && verdict === 'CLEAN') {
      verdict = 'INFO';
    }
  }

  const rollupByDirect = computeRollup(newG, findings);

  opts.onProgress?.({
    kind: 'done',
    total: changes.length,
    withFindings: new Set(findings.map((f) => f.package)).size,
  });

  return {
    verdict,
    findings,
    rollupByDirect,
    changes,
    errors,
    durationMs: Date.now() - t0,
  };
}

async function analyzeOne(
  ref: { name: string; version: string; integrity: string; resolved: string | null },
  cache: SnapshotCache,
  opts: EngineOptions,
): Promise<PackageSnapshot> {
  // Cache lookup by integrity (if present).
  if (ref.integrity) {
    const cached = await cache.get(ref.integrity);
    if (cached && cached.name === ref.name && cached.version === ref.version) {
      opts.onProgress?.({ kind: 'cache-hit', packageName: ref.name, version: ref.version });
      return cached;
    }
  }

  opts.onProgress?.({ kind: 'analyze', packageName: ref.name, version: ref.version });

  const tarballPath = opts.fetchOverride
    ? await opts.fetchOverride(ref)
    : await fetchTarball(ref);
  try {
    const timeout = opts.timeoutMs ?? 90_000;
    const snap = await withTimeout(
      analyzeTarball(tarballPath, { integrity: ref.integrity }),
      timeout,
      `${ref.name}@${ref.version}`,
    );
    if (ref.integrity) {
      // best-effort cache write; don't block on it
      cache.put(ref.integrity, snap).catch(() => {});
    }
    return snap;
  } finally {
    // Only unlink temp files we fetched ourselves. Overrides own their files.
    if (!opts.fetchOverride) {
      await fs.unlink(tarballPath).catch(() => {});
    }
  }
}

async function withTimeout<T>(p: Promise<T>, ms: number, label: string): Promise<T> {
  return await new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`analyze ${label} timed out after ${ms}ms`)), ms);
    p.then((v) => { clearTimeout(timer); resolve(v); }, (e) => { clearTimeout(timer); reject(e); });
  });
}

function byFindingKey(a: Finding, b: Finding): number {
  const rank: Record<Severity, number> = { BLOCK: 0, WARN: 1, INFO: 2 };
  if (rank[a.severity] !== rank[b.severity]) return rank[a.severity] - rank[b.severity];
  if (a.package !== b.package) return a.package.localeCompare(b.package);
  if (a.detector !== b.detector) return a.detector.localeCompare(b.detector);
  const aEv = a.evidence[0];
  const bEv = b.evidence[0];
  if (aEv && bEv) {
    if (aEv.file !== bEv.file) return aEv.file.localeCompare(bEv.file);
    return aEv.line - bEv.line;
  }
  return 0;
}

function computeRollup(
  graph: LockGraph,
  findings: Finding[],
): Record<string, { maxSeverity: Severity | 'CLEAN'; count: number }> {
  // "Direct deps" = children of the root node.
  const root = graph.nodes.get('');
  const directNames = new Set<string>();
  if (root) {
    for (const childKey of root.dependencies) {
      const child = graph.nodes.get(childKey);
      if (child) directNames.add(child.name);
    }
  }
  const findingsByPkg = new Map<string, Finding[]>();
  for (const f of findings) {
    (findingsByPkg.get(f.package) ?? findingsByPkg.set(f.package, []).get(f.package)!).push(f);
  }

  const rollup: Record<string, { maxSeverity: Severity | 'CLEAN'; count: number }> = {};
  for (const name of directNames) {
    // For each direct dep, gather all findings under its subtree (name + everything reachable through it in newG).
    const subtree = collectSubtree(graph, name);
    let max: Severity | 'CLEAN' = 'CLEAN';
    let count = 0;
    for (const s of subtree) {
      const fs = findingsByPkg.get(s) ?? [];
      count += fs.length;
      for (const f of fs) {
        if (f.severity === 'BLOCK') { max = 'BLOCK'; }
        else if (f.severity === 'WARN' && max !== 'BLOCK') max = 'WARN';
        else if (f.severity === 'INFO' && max === 'CLEAN') max = 'INFO';
      }
    }
    rollup[name] = { maxSeverity: max, count };
  }
  return rollup;
}

function collectSubtree(graph: LockGraph, rootPackageName: string): Set<string> {
  const seen = new Set<string>();
  const startKeys = graph.byName.get(rootPackageName) ?? [];
  const stack: string[] = [...startKeys];
  while (stack.length > 0) {
    const key = stack.pop()!;
    const node = graph.nodes.get(key);
    if (!node) continue;
    if (seen.has(node.name)) continue;
    seen.add(node.name);
    for (const child of node.dependencies) stack.push(child);
  }
  return seen;
}

function cpuCount(): number | null {
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const os = require('node:os');
    return os.cpus().length;
  } catch { return null; }
}
function clamp(n: number, lo: number, hi: number): number { return Math.max(lo, Math.min(hi, n)); }
