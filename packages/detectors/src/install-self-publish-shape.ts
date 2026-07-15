/**
 * INSTALL self-publish-shape — package's install-tier code paths BOTH shell out
 * to a subprocess AND rewrite its own `package.json`.
 *
 * Port from guarddog:threat-runtime-self-propagation — audit §4 row 10.
 *
 * Attacker shape (npm-worm): a package's postinstall script triggers a code
 * path that:
 *   1. Reads the ambient `NPM_TOKEN` / npmrc,
 *   2. Rewrites the local `package.json` to insert a new install hook,
 *   3. Shells out to `npm publish` — the package re-publishes itself with
 *      a tampered manifest and new script contents.
 *
 * This is the mechanism behind shai-hulud-2025's self-propagation: infect
 * a package's own metadata, then publish. Real telemetry: every worm-shape
 * we've measured writes to `package.json` in one file and calls into
 * `child_process` in another (or the same) file, gated by an install-tier
 * lifecycle script.
 *
 * We do NOT have raw source strings in FileCapabilities (deliberate — the
 * analyzer never persists code) so we can't grep for the literal
 * "npm publish". Instead we co-occurrence-detect the STRUCTURAL shape:
 *
 *   - install-tier lifecycle script present (postinstall / install / preinstall
 *     / prepare — same tier as install.script-added tracks),
 *   - AND `execModules` first-used in some file in pair.new (or newly-added
 *     package with any execModule),
 *   - AND `fsWriteTargets` in some file includes `package.json` (path-literal
 *     write to the manifest).
 *
 * All three conditions must be new-or-strengthened in pair.new relative to
 * pair.old — a package that has always had these traits is not the shape we
 * want; we want the transition.
 *
 * FP guardrail: legit build tooling occasionally rewrites package.json (e.g.
 * `changeset version`), but rarely in an install-tier hook. Requiring both a
 * package.json write AND an exec module AND an install-tier hook keeps
 * baseline FP low.
 *
 * NEVER-EXECUTE (ADR 0005): only reads PackageSnapshot.
 */

import type { Detector, Finding, PackageSnapshot, SnapshotPair, Severity } from '@vetlock/core';

const INSTALL_TIER_SCRIPTS = ['preinstall', 'install', 'postinstall', 'prepare'];

function hasInstallTierScript(snap: PackageSnapshot): boolean {
  const scripts = snap.manifest.scripts ?? {};
  return INSTALL_TIER_SCRIPTS.some((k) => typeof scripts[k] === 'string' && (scripts[k] as string).length > 0);
}

function anyFileHasExec(snap: PackageSnapshot): string | null {
  for (const f of snap.files) {
    if ((f.execModules ?? []).length > 0) return f.path;
  }
  return null;
}

function anyFileWritesManifest(snap: PackageSnapshot): { file: string; target: string } | null {
  for (const f of snap.files) {
    for (const t of f.fsWriteTargets ?? []) {
      if (t === 'package.json' || t.endsWith('/package.json')) return { file: f.path, target: t };
    }
  }
  return null;
}

/** For test surface. */
export function selfPublishShape(snap: PackageSnapshot):
  | { install: string; exec: string; write: { file: string; target: string } }
  | null
{
  const scripts = snap.manifest.scripts ?? {};
  const hookName = INSTALL_TIER_SCRIPTS.find((k) => typeof scripts[k] === 'string' && (scripts[k] as string).length > 0);
  if (!hookName) return null;
  const exec = anyFileHasExec(snap);
  if (!exec) return null;
  const write = anyFileWritesManifest(snap);
  if (!write) return null;
  return { install: hookName, exec, write };
}

export const selfPublishShapeDetector: Detector = {
  id: 'install-self-publish-shape',
  category: 'INSTALL',
  run(pair: SnapshotPair): Finding[] {
    if (!pair.new) return [];
    const now = selfPublishShape(pair.new);
    if (!now) return [];
    // Diff discipline: require the shape to be NEW to this version. If pair.old
    // exists AND already had the exact same shape, this is a stable package
    // that has always looked like this — probably legit (rare, but preserved).
    if (pair.old) {
      const before = selfPublishShape(pair.old);
      if (before && before.install === now.install && before.write.target === now.write.target) {
        return [];
      }
    }
    const isAdd = pair.old === null;
    const hasInstallHookAdded = pair.old ? !hasInstallTierScript(pair.old) : true;
    const severity: Severity = hasInstallHookAdded ? 'BLOCK' : 'WARN';
    const confidence: 'high' | 'medium' = hasInstallHookAdded ? 'high' : 'medium';
    return [
      {
        detector: 'install.self-publish-shape',
        category: 'INSTALL',
        package: pair.new.name,
        from: pair.old?.version ?? null,
        to: pair.new.version,
        direction: isAdd ? 'added' : 'changed',
        severity,
        confidence,
        message:
          `Package exhibits self-publish worm shape: install-tier hook "${now.install}" + child_process/exec in "${now.exec}" + fs write to "${now.write.target}" from "${now.write.file}". ` +
          'Ported from guarddog:threat-runtime-self-propagation.',
        evidence: [
          {
            file: now.write.file,
            line: 1,
            snippet: `hook=${now.install}, exec-in=${now.exec}, writes=${now.write.target}`.slice(0, 240),
          },
        ],
        provenance: [],
      },
    ];
  },
};
