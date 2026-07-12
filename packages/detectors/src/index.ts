/**
 * Registry of all built-in detectors + escalation + a runAll helper.
 *
 * Escalation rules (§3):
 *   1. OBF findings in a package that also has NET or INSTALL findings are
 *      upgraded from WARN to BLOCK — the classic obfuscated-blob + exfil-URL
 *      + install-hook worm signature.
 *   2. Typosquat candidates (DEPS WARN) upgrade to BLOCK when the added
 *      package also ships any BLOCK-tier capability. A lookalike name next to
 *      a top-download that immediately spawns processes is the malicious-
 *      typosquat shape.
 *   3. Compound-suspicion: a package accumulating 3+ WARN findings across 2+
 *      categories has its WARN findings promoted to BLOCK. Closes the
 *      "spread the attack thin across N files to avoid tripping any single
 *      detector's threshold" evasion.
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

  // Escalation 1: OBF/WARN → BLOCK when same package also has NET or INSTALL
  const risky = new Set(
    all
      .filter((f) => f.category === 'NET' || f.category === 'INSTALL')
      .map((f) => f.package),
  );
  for (const f of all) {
    if (f.category === 'OBF' && f.severity === 'WARN' && risky.has(f.package)) {
      f.severity = 'BLOCK';
      f.message += ' [escalated: co-occurring NET/INSTALL findings in this package]';
    }
  }

  // Escalation 2: typosquat WARN → BLOCK when same package has any BLOCK-tier capability
  const dangerousCategories = new Set(['NET', 'INSTALL', 'EXEC', 'ENV', 'FS']);
  const dangerous = new Set(
    all.filter((f) => dangerousCategories.has(f.category) && f.severity === 'BLOCK').map((f) => f.package),
  );
  for (const f of all) {
    if (f.detector === 'deps.typosquat-candidate' && f.severity === 'WARN' && dangerous.has(f.package)) {
      f.severity = 'BLOCK';
      f.message += ' [escalated: added package also ships BLOCK-tier capabilities]';
    }
  }

  // Escalation 3: compound-suspicion. Per-package: if the package has 3+ WARN
  // findings AND those findings span 2+ distinct categories, promote all its
  // WARN findings to BLOCK. Closes cross-file / cross-category evasion.
  const warnFindingsByPkg = new Map<string, Finding[]>();
  for (const f of all) {
    if (f.severity !== 'WARN') continue;
    (warnFindingsByPkg.get(f.package) ?? warnFindingsByPkg.set(f.package, []).get(f.package)!).push(f);
  }
  for (const [pkg, warns] of warnFindingsByPkg) {
    if (warns.length < 3) continue;
    const cats = new Set(warns.map((w) => w.category));
    if (cats.size < 2) continue;
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
