/**
 * BUNDLED detector — surfaces bundledDependencies field appearance and
 * bundled dep lifecycle scripts.
 *
 * N1 FIX: packages that declare bundledDependencies ship inner node_modules
 * inside their tarball.  Before the N1 fix, isAnalyzableSource() silently
 * dropped every file under node_modules/, so 13 detectors went blind to
 * malicious payload shipped in bundled deps.
 *
 * This detector emits:
 *
 *   deps.bundled-dependency-added  (WARN)
 *     When the new manifest declares a bundledDependencies field that was not
 *     present before, or when new entries are added to it.  The review-time UI
 *     needs to know that inner node_modules are now part of the install surface.
 *
 *   install.bundled-lifecycle  (BLOCK)
 *     When the outer manifest carries _bundledLifecycle (populated by the
 *     analyzer's augmentManifestWithBundledLifecycle helper) — meaning at least
 *     one bundled dep declares a lifecycle hook that npm will execute.
 */

import type { Detector, Finding, SnapshotPair } from '@vetlock/core';

const LIFECYCLE_HOOKS = new Set([
  'preinstall', 'install', 'postinstall',
  'prepare', 'preprepare', 'postprepare',
  'prepublish', 'prepublishOnly', 'publish', 'postpublish',
  'prepack', 'pack', 'postpack',
]);

export const bundledDepsDetector: Detector = {
  id: 'bundled-deps',
  category: 'DEPS',
  run(pair: SnapshotPair): Finding[] {
    if (!pair.new) return [];
    const out: Finding[] = [];

    const newManifest = pair.new.manifest;
    const oldManifest = pair.old?.manifest;

    // Collect new bundledDependencies entries
    const newBundled = getBundledNames(newManifest);
    const oldBundled = getBundledNames(oldManifest);

    // Emit WARN for each newly added bundled dep name
    const addedBundled: string[] = [];
    for (const name of newBundled) {
      if (!oldBundled.has(name)) addedBundled.push(name);
    }

    if (addedBundled.length > 0) {
      // Emit one finding covering all newly-added bundled deps
      const isNewPackage = pair.old === null;
      out.push({
        detector: 'deps.bundled-dependency-added',
        category: 'DEPS',
        package: pair.new.name,
        from: isNewPackage ? null : (pair.old?.version ?? null),
        to: pair.new.version,
        direction: isNewPackage ? 'added' : 'changed',
        severity: 'WARN',
        confidence: 'high',
        message: `Package declares bundledDependencies — inner node_modules are shipped inside the tarball and are part of the install surface: ${addedBundled.join(', ')}`,
        evidence: [
          {
            file: 'package.json',
            line: 1,
            snippet: `bundledDependencies: [${addedBundled.map((n) => `"${n}"`).join(', ')}]`,
          },
        ],
        provenance: [],
      });
    }

    // Emit BLOCK for each bundled dep that has lifecycle scripts
    const bundledLifecycle = newManifest['_bundledLifecycle'] as
      | Record<string, Record<string, string>>
      | undefined;
    if (bundledLifecycle && typeof bundledLifecycle === 'object') {
      for (const [depName, scripts] of Object.entries(bundledLifecycle)) {
        for (const [hook, body] of Object.entries(scripts)) {
          if (!LIFECYCLE_HOOKS.has(hook)) continue;
          if (typeof body !== 'string') continue;
          const isNewPackage = pair.old === null;
          out.push({
            detector: 'install.bundled-lifecycle',
            category: 'INSTALL',
            package: pair.new.name,
            from: isNewPackage ? null : (pair.old?.version ?? null),
            to: pair.new.version,
            direction: isNewPackage ? 'added' : 'changed',
            severity: 'BLOCK',
            confidence: 'high',
            message: `Bundled dependency "${depName}" declares lifecycle script "${hook}" that npm will execute at install time.`,
            evidence: [
              {
                file: `node_modules/${depName}/package.json`,
                line: 1,
                snippet: `${hook}: ${body.slice(0, 200)}`,
              },
            ],
            provenance: [],
          });
        }
      }
    }

    return out;
  },
};

function getBundledNames(manifest: { bundledDependencies?: unknown; bundleDependencies?: unknown; [key: string]: unknown } | undefined): Set<string> {
  if (!manifest) return new Set();
  const raw =
    (manifest['bundledDependencies'] as unknown) ??
    (manifest['bundleDependencies'] as unknown);
  if (!Array.isArray(raw)) return new Set();
  const names = new Set<string>();
  for (const n of raw) {
    if (typeof n === 'string' && n.length > 0) names.add(n);
  }
  return names;
}
