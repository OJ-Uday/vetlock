/**
 * Registry of all built-in detectors + escalation + a runAll helper.
 *
 * Escalation rules (§3):
 *   1. OBF findings in a package that also has NET, INSTALL, EXEC, ENV, or FS
 *      findings are upgraded from WARN to BLOCK — the obfuscated-blob worm
 *      signature regardless of whether the exfil channel is a URL/hook/exec/
 *      env-harvest/hotpath-write (REDTEAM L9, S8).
 *   2. Typosquat candidates (DEPS WARN) upgrade to BLOCK when the added
 *      package EITHER ships any BLOCK-tier NET/INSTALL/EXEC/ENV/FS/CODE/OBF
 *      capability (original rule, broadened categories) OR has 2+ WARN-tier
 *      findings across 2+ distinct categories (REDTEAM D5).
 *   3. Compound-suspicion: a package accumulating WARN findings escalates to
 *      BLOCK when EITHER (a) warns.length >= 3 regardless of category count
 *      (closes single-category saturation — REDTEAM S5, D4) OR (b) warns.length
 *      >= 2 across 2+ distinct categories AND at least one finding is in a
 *      security-relevant category NET/INSTALL/EXEC/ENV/FS/CODE (REDTEAM D4, S5).
 */

import type {
  Detector,
  DetectorContext,
  Finding,
  SnapshotPair,
} from '@vetlock/core';
import { validateFinding } from '@vetlock/core';

import { installDetector } from './install.js';
import { maintainerDetector } from './meta.js';
import { netDetector } from './net.js';
import { netEncodedDetector } from './net-encoded.js';
import { execDetector } from './exec.js';
import { fsDetector } from './fs.js';
import { fsReadDetector } from './fs-read.js';
import { envDetector } from './env.js';
import { codeDetector } from './code.js';
import { obfDetector } from './obf.js';
import { depsManifestDetector } from './manifest-deps.js';
import { binDetector } from './bin.js';
import { typosquatDetector } from './typo.js';
import { firstVersionClusterDetector } from './first-version-cluster.js';
import { wasmDetector } from './wasm.js';
import { bundledDepsDetector } from './bundled.js';
import { advisoriesForVersion } from './advisories.js';

export const ALL_DETECTORS: readonly Detector[] = [
  installDetector,
  maintainerDetector,
  netDetector,
  netEncodedDetector,
  execDetector,
  fsDetector,
  fsReadDetector,
  envDetector,
  codeDetector,
  obfDetector,
  depsManifestDetector,
  binDetector,
  typosquatDetector,
  firstVersionClusterDetector,
  wasmDetector,
  bundledDepsDetector,
];

export {
  installDetector,
  maintainerDetector,
  netDetector,
  netEncodedDetector,
  execDetector,
  fsDetector,
  fsReadDetector,
  envDetector,
  codeDetector,
  obfDetector,
  depsManifestDetector,
  binDetector,
  typosquatDetector,
  firstVersionClusterDetector,
  wasmDetector,
  bundledDepsDetector,
};

/**
 * Run every built-in detector, apply cross-detector escalation, return findings
 * in stable sort order. Every emitted finding passes validateFinding() —
 * schema violations are hard errors, not silent drops.
 */
export function runAll(pair: SnapshotPair, ctx?: DetectorContext): Finding[] {
  const context: DetectorContext = ctx ?? {
    direction: pair.old === null ? 'added' : pair.new === null ? 'removed' : 'changed',
  };
  const all: Finding[] = [];
  for (const d of ALL_DETECTORS) {
    for (const f of d.run(pair, context)) all.push(f);
  }

  // REDTEAM L9, S8 FIX — Escalation 1: OBF/WARN → BLOCK when same package also has
  // NET, INSTALL, EXEC, ENV, or FS findings. Previously only NET and INSTALL triggered
  // this promotion; attackers who used child_process (EXEC), env-harvest (ENV), or
  // hotpath writes (FS) without any URL literals or lifecycle hooks evaded it.
  const riskyCategories = new Set(['NET', 'INSTALL', 'EXEC', 'ENV', 'FS']);
  const risky = new Set(
    all
      .filter((f) => riskyCategories.has(f.category))
      .map((f) => f.package),
  );
  for (const f of all) {
    if (f.category === 'OBF' && f.severity === 'WARN' && risky.has(f.package)) {
      f.severity = 'BLOCK';
      f.message += ' [escalated: co-occurring NET/INSTALL/EXEC/ENV/FS findings in this package]';
    }
  }

  // REDTEAM D5 FIX — Escalation 2: typosquat WARN → BLOCK when the added package EITHER
  // (a) has any BLOCK-tier NET/INSTALL/EXEC/ENV/FS/CODE/OBF finding (original rule,
  //     broadened from just NET/INSTALL/EXEC/ENV/FS), OR
  // (b) has 2+ WARN-tier findings across 2+ distinct categories (new rule — catches
  //     the typosquat+net.new-module WARN-only shape with no static URL literal).
  const dangerousCategories = new Set(['NET', 'INSTALL', 'EXEC', 'ENV', 'FS', 'CODE', 'OBF']);
  const dangerous = new Set(
    all.filter((f) => dangerousCategories.has(f.category) && f.severity === 'BLOCK').map((f) => f.package),
  );
  // Also build WARN-count-by-package for the new WARN-tier co-occurrence check (rule 2b).
  const warnByPkgForTypo = new Map<string, Set<string>>();
  for (const f of all) {
    if (f.severity !== 'WARN') continue;
    if (!warnByPkgForTypo.has(f.package)) warnByPkgForTypo.set(f.package, new Set());
    warnByPkgForTypo.get(f.package)!.add(f.category);
  }
  const multiWarnPkgs = new Set(
    [...warnByPkgForTypo.entries()]
      .filter(([, cats]) => cats.size >= 2)
      .map(([pkg]) => pkg),
  );
  for (const f of all) {
    if (f.detector === 'deps.typosquat-candidate' && f.severity === 'WARN') {
      if (dangerous.has(f.package)) {
        f.severity = 'BLOCK';
        f.message += ' [escalated: added package also ships BLOCK-tier capabilities]';
      } else if (multiWarnPkgs.has(f.package)) {
        f.severity = 'BLOCK';
        f.message += ' [escalated: typosquat candidate has 2+ WARN-tier signals across 2+ categories]';
      }
    }
  }

  // REDTEAM D4, S5 FIX — Escalation 3: compound-suspicion. Per-package, escalate ALL
  // WARN findings to BLOCK when EITHER:
  //   (a) warns.length >= 3, regardless of category count — closes the single-category
  //       saturation evasion where an attacker ships N obfuscated files (all OBF) but
  //       no other signal.
  //   (b) warns.length >= 2 across 2+ distinct categories AND at least one finding is
  //       in a security-relevant category — closes the 2-finding cross-category evasion
  //       (e.g. code.dynamic-loading-added + net.new-module staying WARN because the
  //       old rule required 3+).
  // Previously: requires warns.length >= 3 AND cats.size >= 2 (both AND'd).
  const securityCategories = new Set(['NET', 'INSTALL', 'EXEC', 'ENV', 'FS', 'CODE']);
  const warnFindingsByPkg = new Map<string, Finding[]>();
  for (const f of all) {
    if (f.severity !== 'WARN') continue;
    (warnFindingsByPkg.get(f.package) ?? warnFindingsByPkg.set(f.package, []).get(f.package)!).push(f);
  }
  for (const [pkg, warns] of warnFindingsByPkg) {
    const cats = new Set(warns.map((w) => w.category));
    const hasSecurityRelevant = warns.some((w) => securityCategories.has(w.category));
    const shouldEscalate =
      warns.length >= 3 ||
      (warns.length >= 2 && cats.size >= 2 && hasSecurityRelevant);
    if (!shouldEscalate) continue;
    for (const w of warns) {
      w.severity = 'BLOCK';
      w.message += ` [escalated: package '${pkg}' has ${warns.length} WARN findings across ${cats.size} categories]`;
    }
  }

  // GHSA correlation: for every finding, if the (package, version) has known
  // advisories, annotate the finding. This gives a second-source citation.
  // Findings that match an advisory get their confidence bumped to 'high'.
  for (const f of all) {
    const version = f.to ?? f.from;
    if (!version) continue;
    const matches = advisoriesForVersion(f.package, version);
    if (matches.length === 0) continue;
    const cite = matches
      .map((a) => `${a.ghsa}${a.cve ? ` (${a.cve})` : ''}`)
      .join(', ');
    f.message += ` [GHSA: ${cite}]`;
    f.confidence = 'high';
  }

  for (const f of all) {
    const err = validateFinding(f);
    if (err) {
      throw new Error(`Detector emitted invalid finding: ${err} — ${JSON.stringify(f)}`);
    }
  }

  return stablesort(all);
}

export function stablesort(findings: Finding[]): Finding[] {
  const rank = { BLOCK: 0, WARN: 1, INFO: 2 } as const;
  return [...findings].sort((a, b) => {
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
  });
}
