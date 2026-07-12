/**
 * Registry of all built-in detectors + escalation + a runAll helper.
 *
 * Escalation rule (§3): OBF findings in a package that also has NET or INSTALL
 * findings are upgraded from WARN to BLOCK — the co-occurrence pattern of
 * "obfuscated blob + new endpoint + install hook" is the classic worm signature.
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
import { execDetector } from './exec.js';
import { fsDetector } from './fs.js';
import { envDetector } from './env.js';
import { codeDetector } from './code.js';
import { obfDetector } from './obf.js';
import { depsManifestDetector } from './manifest-deps.js';

export const ALL_DETECTORS: readonly Detector[] = [
  installDetector,
  maintainerDetector,
  netDetector,
  execDetector,
  fsDetector,
  envDetector,
  codeDetector,
  obfDetector,
  depsManifestDetector,
];

export {
  installDetector,
  maintainerDetector,
  netDetector,
  execDetector,
  fsDetector,
  envDetector,
  codeDetector,
  obfDetector,
  depsManifestDetector,
};

/**
 * Run every built-in detector against the pair, apply cross-detector escalation,
 * and return findings in stable sort order.
 *
 * Every returned finding is validated; anything that fails validateFinding()
 * throws (a schema failure is a detector bug, and a hard fail is louder than
 * silently dropping).
 */
export function runAll(pair: SnapshotPair, ctx?: DetectorContext): Finding[] {
  const context: DetectorContext = ctx ?? {
    direction: pair.old === null ? 'added' : pair.new === null ? 'removed' : 'changed',
  };
  const all: Finding[] = [];
  for (const d of ALL_DETECTORS) {
    for (const f of d.run(pair, context)) all.push(f);
  }

  // Escalation: OBF/WARN → BLOCK if same package also has any NET or INSTALL finding.
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
