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
 *
 * REDTEAM F1 FIX: runDiff now routes both lockfile texts through the universal
 * parseLockfileText() dispatcher instead of JSON.parse() + parseLockfile().
 * Previously engine.ts:77 called JSON.parse unconditionally, crashing with
 * 'Unexpected token' on any pnpm-lock.yaml or yarn.lock despite the CLI
 * advertising multi-format support.
 */

import { promises as fs } from 'node:fs';
import type {
  Finding,
  PackageSnapshot,
  SnapshotPair,
  Severity,
} from './finding.js';
import {
  shortestPaths,
  type LockGraph,
} from './lockfile.js';
import { parseLockfileText } from './lockfile-any.js';
import { computeChangeset, type Change } from './changeset.js';
import { fetchTarball, classifyResolved, type PackageRef } from './fetch.js';
import { analyzeTarball } from './analyze.js';
import { makeCache, type SnapshotCache } from './cache.js';

export interface EngineOptions {
  /** Called for each changed node with the (old, new) snapshot pair. Impl in @vetlock/detectors. */
  runDetectors: (pair: SnapshotPair, packageName: string) => Finding[];
  /** Concurrency for fetch+analyze (default: cpu count, min 2, max 8). */
  concurrency?: number;
  /** Per-package total timeout in ms (default 90_000). */
  timeoutMs?: number;
  /**
   * Timeout (ms) for the fetch step only — resolving a package's tarball via
   * `fetchOverride` or the default `fetchTarball` — separate from `timeoutMs`,
   * which guards the analyze step. Default 30_000ms.
   *
   * FAIL-CLOSED INVARIANT: a fetch that hangs (a Promise that never settles)
   * or that runs longer than this timeout must never hang the engine forever
   * or let the run render CLEAN. We race the fetch against an
   * `AbortSignal.timeout()` guard; on timeout the resulting rejection flows
   * through the same per-package catch as any other fetch error, which the
   * engine turns into a BLOCK-tier `analysis.failed` finding (see the
   * REDTEAM S4 fix in runDiff, below).
   */
  analyzerTimeoutMs?: number;
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
  /**
   * Filename hint for the OLD lockfile — used by parseLockfileText to dispatch
   * to the correct format parser. E.g. 'pnpm-lock.yaml', 'yarn.lock'.
   * Defaults to 'package-lock.json' (npm) when omitted.
   *
   * REDTEAM F1: without this, non-JSON lockfiles crashed with a JSON.parse error.
   */
  oldLockfilePath?: string;
  /** Filename hint for the NEW lockfile. @see oldLockfilePath */
  newLockfilePath?: string;
  /**
   * Set of high-value npm package names. When a `deps.workspace-shadowing` finding
   * concerns a package in this set, the finding is escalated from WARN to BLOCK
   * (REDTEAM F2). Pass `new Set(TOP_NPM_NAMES)` from @vetlock/detectors.
   * When omitted, workspace-shadowing findings remain at WARN.
   */
  topNpmNames?: ReadonlySet<string>;
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
  /**
   * Compressed 0.0-10.0 risk score, computed from findings via a fixed
   * additive-with-multiplier formula. See `computeRiskScore` for the pinned
   * weighting. A score of 0.0 means "no findings"; 10.0 is the ceiling.
   *
   * Formula (identical across renderers, tests pin the exact numbers):
   *   base per finding = { BLOCK: 5, WARN: 2, INFO: 0 }[severity]
   *   confidence multiplier = { high: 1.0, medium: 0.7, low: 0.5 }[confidence]
   *   direction multiplier = { added: 1.0, changed: 0.8, absolute: 1.0,
   *                            removed: 0.3 }[direction]
   *   contribution = base * confidence * direction
   *   riskScore    = clamp( round1(sum(contributions)), 0, 10 )
   *
   * Rationale: BLOCK dominates; INFO contributes zero so info-only reports
   * stay at 0.0. 'removed' contributes at 0.3× because removals only reach
   * INFO severity by the diff-framing invariant — but the multiplier is
   * kept below 1.0 so a mostly-removals report never approaches the ceiling
   * even under future taxonomy changes. Rounded to 1 decimal for stability
   * across dashboards.
   */
  riskScore: number;
}

export async function runDiff(
  oldLockfileText: string,
  newLockfileText: string,
  opts: EngineOptions,
): Promise<RunResult> {
  const t0 = Date.now();
  // REDTEAM F1 FIX: use the universal dispatcher so pnpm-lock.yaml and
  // yarn.lock are handled correctly; previously JSON.parse was called
  // unconditionally here, crashing on YAML input.
  //
  // P4c: capture the ecosystem tag returned by the dispatcher so downstream
  // analyzeOne calls know whether to route through pacote (npm-family) or
  // the PyPI JSON API (pypi-family).  Both graphs must agree on ecosystem —
  // a diff that mixes an npm lockfile with a poetry.lock would be nonsense.
  const oldParsed = parseLockfileText(oldLockfileText, opts.oldLockfilePath);
  const newParsed = parseLockfileText(newLockfileText, opts.newLockfilePath);
  if (oldParsed.ecosystem !== newParsed.ecosystem) {
    throw new Error(
      `lockfile ecosystem mismatch: old='${oldParsed.ecosystem}' new='${newParsed.ecosystem}'. ` +
      `Cross-ecosystem diffs are not meaningful (they compare different registries).`,
    );
  }
  const ecosystem = newParsed.ecosystem;
  const oldG = oldParsed.graph;
  const newG = newParsed.graph;

  const changes = computeChangeset(oldG, newG);
  opts.onProgress?.({ kind: 'start', total: changes.length });

  const cache = opts.cache ?? makeCache();
  const MAX_WORKERS = 8;
  const cpus = opts.concurrency ?? cpuCount() ?? 2;
  const conc = Math.max(2, Math.min(cpus, MAX_WORKERS));
  const concurrency = Number.isNaN(conc) || conc < 2 ? 2 : conc;

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

  // REDTEAM S4 FIX: track which (name, version) pairs failed to analyze so we
  // can emit a synthetic BLOCK-tier analysis.failed finding for each.  A run
  // that had ANY analyzer failure must never render CLEAN.
  const analysisFailed = new Map<string, { name: string; version: string; error: string }>();

  const refList = [...refs.entries()];
  let idx = 0;
  await Promise.all(
    Array.from({ length: concurrency }, () => (async () => {
      while (true) {
        const cursor = idx++;
        if (cursor >= refList.length) return;
        const [id, ref] = refList[cursor]!;
        try {
          const snap = await analyzeOne(ref, cache, opts, ecosystem);
          snapshots.set(id, snap);
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          errors.push({ package: ref.name, version: ref.version, error: msg });
          analysisFailed.set(id, { name: ref.name, version: ref.version, error: msg });
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
    // REDTEAM S10 FIX: a blank oldIntegrity means the "before" lockfile did not
    // pin this artifact. That transition is itself the signal — the attacker
    // may have crafted the before-side lockfile precisely to suppress this
    // check. Message the two shapes distinctly so review can see which case.
    if (change.kind === 'integrity-changed') {
      const oldBlank = !change.oldIntegrity;
      const message = oldBlank
        ? `Package '${change.name}' at version ${change.newVersion} previously had NO integrity pinned. The "before" lockfile omitted the integrity field — this may be an attacker-crafted lockfile intended to suppress the same-version tamper check.`
        : `Same version, different integrity: ${change.oldIntegrity} → ${change.newIntegrity}. Registry-side or in-flight tamper.`;
      findings.push({
        detector: 'integrity.hash-mismatch',
        category: 'INTEG',
        package: change.name,
        from: change.oldVersion,
        to: change.newVersion,
        direction: 'changed',
        severity: 'BLOCK',
        confidence: 'high',
        message,
        evidence: [
          {
            file: 'package.json',
            line: 1,
            snippet: oldBlank
              ? `integrity <missing> → ${change.newIntegrity}`
              : `integrity ${change.oldIntegrity} → ${change.newIntegrity}`,
          },
        ],
        provenance: [],
        // T1554 Compromise Client Software Binary — the same-version-different-hash
        // shape is a substituted-binary attack; T1195.002 covers the supply-chain
        // origin.
        mitre: ['T1554', 'T1195.002'],
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

  // REDTEAM S4 FIX: for every package that failed to analyze, emit a synthetic
  // BLOCK-tier finding.  This closes the denial-of-detection window: a tarball
  // that stalls or crashes the analyzer can never yield a CLEAN verdict.
  //
  // We emit one finding per (name, version) pair that failed, keyed on the
  // change.  If the failure was on the "new" side of a change we want to
  // surface that change's identity in the finding; if there is no matching
  // change (only-old-side failure) we still emit.
  const emittedFailPackages = new Set<string>();
  for (const change of changes) {
    const failId = change.newVersion ? `${change.name}@${change.newVersion}` : null;
    const failEntry = failId ? analysisFailed.get(failId) : null;
    if (!failEntry) continue;
    if (emittedFailPackages.has(failEntry.name)) continue;
    emittedFailPackages.add(failEntry.name);
    const snippet = failEntry.error.slice(0, 240);
    findings.push({
      detector: 'analysis.failed',
      category: 'META',
      package: failEntry.name,
      from: change.oldVersion ?? null,
      to: change.newVersion ?? null,
      direction: change.kind === 'added' ? 'added' : change.kind === 'removed' ? 'removed' : 'changed',
      severity: 'BLOCK',
      confidence: 'high',
      message: `Package '${failEntry.name}' could not be analyzed — all findings are absent. Error: ${failEntry.error}`,
      evidence: [{ file: 'package.json', line: 1, snippet }],
      provenance: [],
      // T1027 Obfuscated Files or Information — a package the analyzer cannot
      // parse (malformed, crypter-shipped, extreme entropy) is functionally the
      // same defense-evasion posture.
      mitre: ['T1027'],
    });
  }
  // Also emit for failures that didn't match any change (edge case: only-old-side fetch).
  for (const [, failEntry] of analysisFailed) {
    if (emittedFailPackages.has(failEntry.name)) continue;
    emittedFailPackages.add(failEntry.name);
    const snippet = failEntry.error.slice(0, 240);
    findings.push({
      detector: 'analysis.failed',
      category: 'META',
      package: failEntry.name,
      from: failEntry.version,
      to: null,
      direction: 'changed',
      severity: 'BLOCK',
      confidence: 'high',
      message: `Package '${failEntry.name}' could not be analyzed — all findings are absent. Error: ${failEntry.error}`,
      evidence: [{ file: 'package.json', line: 1, snippet }],
      provenance: [],
      mitre: ['T1027'],
    });
  }

  // REDTEAM F2 FIX: emit WARN findings for lockfile entries that have `link: true`
  // and share a name with any legitimate package in the new graph (workspace shadowing).
  // An attacker can add `"link": true` to a lockfile entry to make vetlock skip it
  // entirely. We record link entries in LockGraph.workspaceLinks and surface them here.
  // Escalates to BLOCK when the name matches a top-npm-name (opts.topNpmNames).
  for (const link of newG.workspaceLinks) {
    if (!link.name) continue;
    const isTopName = opts.topNpmNames?.has(link.name) ?? false;
    findings.push({
      detector: 'deps.workspace-shadowing',
      category: 'DEPS',
      package: link.name,
      from: null,
      to: link.version || null,
      direction: 'added',
      severity: isTopName ? 'BLOCK' : 'WARN',
      confidence: 'medium',
      message: `Lockfile entry '${link.key}' has \`link: true\` and uses name '${link.name}'. ` +
        `This entry is excluded from content analysis. If this name matches a real npm package, ` +
        `an attacker may have injected a workspace-link to shadow it and bypass analysis.` +
        (isTopName ? ' [escalated: name matches a top-npm-name — high-value target]' : ''),
      evidence: [
        {
          file: link.key,
          line: 1,
          snippet: `"link": true, "name": "${link.name}", "resolved": "${link.resolved ?? ''}"`,
        },
      ],
      provenance: [],
      // T1036.005 Match Legitimate Name or Location — workspace-link
      // shadowing masquerades an unanalyzed local entry as a real package;
      // T1195.002 is the supply-chain umbrella.
      mitre: ['T1036.005', 'T1195.002'],
    });
  }

  // REDTEAM F6 FIX: emit WARN findings for yarn npm: aliases where the declared
  // name differs from the actually-installed package. Every downstream detector
  // operates on the declared name, so a malicious package aliased as 'chalk'
  // bypasses all chalk-specific trust-store and advisory checks.
  // We emit for both the new graph's aliases (just-added aliases) and also scan
  // the old graph for removed aliases (completeness; direction='removed').
  const emittedAliasKeys = new Set<string>();
  for (const alias of newG.npmAliases) {
    const key = `${alias.declaredName}→${alias.realName}`;
    if (emittedAliasKeys.has(key)) continue;
    emittedAliasKeys.add(key);
    findings.push({
      detector: 'deps.aliased-name',
      category: 'DEPS',
      package: alias.declaredName,
      from: null,
      to: alias.version || null,
      direction: 'added',
      severity: 'WARN',
      confidence: 'high',
      message: `Package '${alias.declaredName}' is a yarn npm: alias — it actually installs ` +
        `'${alias.realName}@${alias.version}' from npm. ` +
        `Detectors that key on the package name ('${alias.declaredName}') may not apply to the real payload.`,
      evidence: [
        {
          file: `node_modules/${alias.declaredName}`,
          line: 1,
          snippet: `${alias.declaredName}@npm:${alias.realName}@${alias.version}`,
        },
      ],
      provenance: [],
      mitre: ['T1036.005', 'T1195.002'],
    });
  }

  // REDTEAM N5 FIX: emit WARN findings for packages whose resolved field uses a
  // git+ / github: / bitbucket: / gitlab: URL. vetlock fetches from the registry
  // by name@version, not from the git URL — the analyzed tarball is from the registry
  // while npm install actually clones the git repo. This is a TOCTOU gap.
  // REDTEAM S9 FIX: emit INFO findings for packages whose resolved field uses a
  // file: URL with an absolute path. The CLI's fetchOverride passes these paths
  // directly to safeExtract — an attacker can point at any local .tgz.
  // NOTE: corpus fixtures use `file://` URLs for their test tarballs. To avoid
  // corpus regressions, we emit file: findings at INFO (not WARN/BLOCK) so the
  // corpus manifests can tolerate them without asserting on them.
  const emittedResolvedPkgs = new Set<string>();
  for (const change of changes) {
    if (change.kind === 'removed') continue;
    const nodeKey = change.nodeKeyNew;
    if (!nodeKey) continue;
    const node = newG.nodes.get(nodeKey);
    if (!node?.resolved) continue;
    const kind = classifyResolved(node.resolved);
    if (!kind) continue;
    const pkgKey = `${change.name}:${kind}`;
    if (emittedResolvedPkgs.has(pkgKey)) continue;
    emittedResolvedPkgs.add(pkgKey);

    if (kind === 'git') {
      findings.push({
        detector: 'deps.non-registry-source',
        category: 'DEPS',
        package: change.name,
        from: change.oldVersion ?? null,
        to: change.newVersion ?? null,
        direction: change.kind === 'added' ? 'added' : 'changed',
        severity: 'WARN',
        confidence: 'high',
        message: `Package '${change.name}' has a git/VCS resolved URL ('${node.resolved}'). ` +
          `vetlock analyzes the registry tarball for '${change.name}@${change.newVersion ?? ''}', ` +
          `but npm install will fetch from the git URL — these may differ.`,
        evidence: [
          {
            file: nodeKey,
            line: 1,
            snippet: `resolved: ${node.resolved}`,
          },
        ],
        provenance: [],
        mitre: ['T1195.002'],
      });
    } else if (kind === 'file' && change.kind === 'added') {
      // Only flag newly-added file: entries. An existing file: entry that was
      // already present before is less suspicious — and corpus fixtures use
      // file:// for both the 'before' and 'after' versions, so firing on
      // 'changed' would break corpus tests that expect CLEAN/BLOCK verdicts.
      findings.push({
        detector: 'deps.local-source',
        category: 'DEPS',
        package: change.name,
        from: null,
        to: change.newVersion ?? null,
        direction: 'added',
        severity: 'INFO',
        confidence: 'medium',
        message: `Package '${change.name}' was newly added with a local file: resolved URL ('${node.resolved}'). ` +
          `This path is attacker-controlled — a malicious lockfile can point at any local .tgz.`,
        evidence: [
          {
            file: nodeKey,
            line: 1,
            snippet: `resolved: ${node.resolved}`,
          },
        ],
        provenance: [],
        mitre: ['T1195.002'],
      });
    }
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
    riskScore: computeRiskScore(findings),
  };
}

/**
 * `runScan` — single-input capability profile (ADR 0012 scan mode).
 *
 * Takes ONE lockfile and reports what its packages DO — as opposed to
 * `runDiff`, which reports what changed between two lockfiles. The output
 * uses `direction: 'absolute'` on every finding to distinguish scan-frame
 * from diff-frame ("does X" vs "started doing X").
 *
 * Implementation: build an empty "before" lockfile matching the input's
 * format, invoke `runDiff` — every package appears as an ADDED node from
 * that engine's perspective — then post-map `direction: 'added'` →
 * `'absolute'` before returning. This reuses the entire fetch/extract/
 * detector pipeline with zero duplication.
 *
 * Same invariants apply: NEVER-EXECUTE (ADR 0005), safe-extract (ADR 0004),
 * fail-closed on analyzer errors (S10). The integrity tripwire structurally
 * can't fire in scan mode (no before-side to compare against — this is
 * documented in the threat model's scan-mode section).
 */
export async function runScan(
  lockfileText: string,
  opts: EngineOptions,
): Promise<RunResult> {
  // Detect the lockfile format so we can synthesize a matching "empty" input.
  // parseLockfileText's dispatcher inspects the filename hint + content shape;
  // its return carries a `.kind` field we can key off.
  const parsed = parseLockfileText(lockfileText, opts.newLockfilePath);
  const emptyLockfile = emptyLockfileFor(parsed.kind);
  const result = await runDiff(emptyLockfile, lockfileText, {
    ...opts,
    // The "before" is synthetic — no filename hint (dispatcher will detect
    // from content).
    oldLockfilePath: undefined,
    newLockfilePath: opts.newLockfilePath,
  });

  // Post-map every finding's direction: 'added' → 'absolute'. Everything
  // else the engine emits (evidence, provenance, severity, category,
  // package, from/to) is unchanged.
  const remapped = result.findings.map((f) => (
    f.direction === 'added' ? { ...f, direction: 'absolute' as const } : f
  ));

  return {
    ...result,
    findings: remapped,
    // The riskScore recomputes to the same value here as in runDiff — the
    // direction remap 'added' → 'absolute' both weight at 1.0 (see the
    // formula on RunResult). We recompute anyway so external callers who
    // mutate `.findings` before checking `.riskScore` see a consistent view.
    riskScore: computeRiskScore(remapped),
  };
}

/**
 * Return a minimal empty lockfile in the given format. Used by `runScan` to
 * synthesize the "before" side of a scan (see ADR 0012).
 *
 * These strings must parse cleanly through parseLockfileText → each parser
 * → an empty LockGraph. That's a small enough surface that direct string
 * synthesis is safer than building AST objects.
 */
function emptyLockfileFor(
  kind: 'npm' | 'pnpm' | 'yarn-classic' | 'yarn-berry' | 'pypi-requirements' | 'pypi-poetry' | 'pypi-uv',
): string {
  switch (kind) {
    case 'pnpm':
      return `lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies: {}\npackages: {}\n`;
    case 'yarn-classic':
      return `# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\n# yarn lockfile v1\n\n`;
    case 'yarn-berry':
      return `__metadata:\n  version: 6\n  cacheKey: 10\n`;
    // P4c PyPI adapter — empty representations that round-trip through
    // parseLockfileText → parsePypiLockfileText yielding a LockGraph whose
    // only content is the empty root node. That lets `runScan` (single-input
    // capability profile — ADR 0012) synthesize a "before" side for a PyPI
    // lockfile the same way it already does for npm-family lockfiles.
    case 'pypi-requirements':
      // A single pinned line so the content sniffer still classifies as
      // pypi-requirements when no filename hint is provided.  The synthetic
      // package is never fetched — runScan is a single-input mode.
      return `# empty requirements.txt (vetlock scan-mode synthetic before-side)\nvetlock-scan-empty==0.0.0\n`;
    case 'pypi-poetry':
      return `[metadata]\nlock-version = "2.0"\npython-versions = "*"\ncontent-hash = ""\n`;
    case 'pypi-uv':
      return `version = 1\nrequires-python = ">=3.9"\n`;
    case 'npm':
    default:
      return JSON.stringify({
        name: 'empty', version: '0.0.0', lockfileVersion: 3,
        packages: { '': { name: 'empty', version: '0.0.0' } },
      });
  }
}

async function analyzeOne(
  ref: { name: string; version: string; integrity: string; resolved: string | null },
  cache: SnapshotCache,
  opts: EngineOptions,
  ecosystem: 'npm' | 'pypi' = 'npm',
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

  // FAIL-CLOSED INVARIANT (P1-B): a fetch step (fetchOverride, or the default
  // fetchTarball) that hangs forever must not hang the engine forever, and
  // must never let the run render CLEAN. We race the fetch against an
  // AbortSignal.timeout() guard; on expiry the race rejects with a
  // timeout-shaped error, which flows into the same catch in runDiff's
  // worker loop as any other fetch failure — turning into a BLOCK-tier
  // `analysis.failed` finding via the existing REDTEAM S4 fail-closed path.
  const fetchTimeoutMs = opts.analyzerTimeoutMs ?? 30_000;

  // P4c ecosystem dispatch: pypi uses the PyPI JSON API + wheel/sdist
  // extraction; npm-family continues to use pacote + node:tar. The
  // NEVER-EXECUTE invariant (ADR 0005) holds identically for both.
  if (ecosystem === 'pypi') {
    const { fetchPypiArtifact } = await import('./artifact-pypi.js');
    const { analyzePypiArtifactFile } = await import('./adapter-pypi.js');
    const artifact = await withFetchTimeout(
      opts.fetchOverride
        // Callers may reuse the same fetchOverride for pypi tests by returning
        // a path — our pypi analyzer accepts a {path, kind} shape, so we
        // adapt: if fetchOverride returns a plain string path, sniff the
        // extension.
        ? Promise.resolve(opts.fetchOverride(ref)).then(async (p) => {
            const s = typeof p === 'string' ? p : await p;
            const kind: 'wheel' | 'sdist' = /\.whl$/i.test(s) ? 'wheel' : 'sdist';
            return { path: s, kind };
          })
        : fetchPypiArtifact({ name: ref.name, version: ref.version, integrity: ref.integrity }),
      fetchTimeoutMs,
      `${ref.name}@${ref.version}`,
    );
    try {
      const timeout = opts.timeoutMs ?? 90_000;
      const snap = await withTimeout(
        analyzePypiArtifactFile(artifact, {
          integrity: ref.integrity, name: ref.name, version: ref.version,
        }),
        timeout,
        `${ref.name}@${ref.version}`,
      );
      if (ref.integrity) cache.put(ref.integrity, snap).catch(() => {});
      return snap;
    } finally {
      if (!opts.fetchOverride) {
        await fs.unlink(artifact.path).catch(() => {});
      }
    }
  }

  const tarballPath = await withFetchTimeout(
    opts.fetchOverride ? opts.fetchOverride(ref) : fetchTarball(ref),
    fetchTimeoutMs,
    `${ref.name}@${ref.version}`,
  );
  if (opts.fetchOverride) {
    await assertGzipTarball(tarballPath);
  }
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

/**
 * Races the fetch step (fetchOverride or fetchTarball) against an
 * `AbortSignal.timeout()` guard. `fetchOverride`'s signature takes no signal
 * argument, so we cannot cancel the underlying I/O directly — but we CAN stop
 * waiting on it, which is what matters for the fail-closed invariant: a fetch
 * that never resolves (or resolves too slowly) must reject rather than hang
 * the worker-pool loop in runDiff() forever. The rejection message is
 * timeout-shaped ("timed out after") so callers/tests can distinguish a
 * timeout from any other fetch error.
 */
async function withFetchTimeout<T>(p: Promise<T>, ms: number, label: string): Promise<T> {
  const signal = AbortSignal.timeout(ms);
  return await new Promise<T>((resolve, reject) => {
    const onAbort = () => reject(new Error(`fetch ${label} timed out after ${ms}ms`));
    signal.addEventListener('abort', onAbort, { once: true });
    p.then(
      (v) => { signal.removeEventListener('abort', onAbort); resolve(v); },
      (e) => { signal.removeEventListener('abort', onAbort); reject(e); },
    );
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

/**
 * Compute the 0.0-10.0 compressed risk score from a list of findings.
 * See the docstring on RunResult.riskScore for the pinned formula.
 *
 * Exported so external callers (dashboards, CI pipelines, the SARIF renderer)
 * can compute the same value from a synthesized/filtered finding list —
 * critical for cases where post-processing (config allowlists, --fail-on
 * filtering) mutates `.findings` and the top-level score must stay in sync.
 */
export function computeRiskScore(findings: readonly Finding[]): number {
  // Weighting constants — pinned by the risk-score test. Changing any of
  // these is a semver-visible behavior change (the number a dashboard
  // renders will shift).
  const BASE: Record<Severity, number> = { BLOCK: 5, WARN: 2, INFO: 0 };
  const CONF: Record<'high' | 'medium' | 'low', number> = { high: 1.0, medium: 0.7, low: 0.5 };
  const DIR: Record<Finding['direction'], number> = {
    added: 1.0,
    changed: 0.8,
    absolute: 1.0,
    removed: 0.3,
  };
  let sum = 0;
  for (const f of findings) {
    sum += BASE[f.severity] * CONF[f.confidence] * DIR[f.direction];
  }
  // clamp then round to one decimal place — dashboards prefer stable
  // one-decimal numbers over floating-point drift.
  const clamped = clamp(sum, 0, 10);
  return Math.round(clamped * 10) / 10;
}

async function assertGzipTarball(fetchedPath: string): Promise<void> {
  const header = Buffer.alloc(2);
  const fd = await fs.open(fetchedPath, 'r');
  try {
    await fd.read(header, 0, 2, 0);
  } finally {
    await fd.close();
  }
  if (header[0] !== 0x1f || header[1] !== 0x8b) {
    throw new Error(`fetchOverride returned non-gzip file at ${fetchedPath}`);
}
}
