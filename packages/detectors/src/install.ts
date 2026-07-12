/**
 * INSTALL detector — lifecycle scripts.
 * Fires when the new manifest introduces (or changes) a lifecycle script.
 * Severity BLOCK, confidence high.
 *
 * The lifecycle list covers npm's canonical hooks + Yarn's additional lifecycle
 * events + `dependencies`-triggered rebuild scripts. Adding a hook here
 * expands what we catch; keep it a superset of what any package manager
 * actually runs.
 *
 * Reference: https://docs.npmjs.com/cli/v10/using-npm/scripts#life-cycle-scripts
 * Reference: https://yarnpkg.com/configuration/manifest#scripts
 */
import type { Detector, Finding, SnapshotPair } from '@vetlock/core';

const LIFECYCLE_KEYS: readonly string[] = [
  // npm canonical
  'preinstall', 'install', 'postinstall',
  'prepare', 'preprepare', 'postprepare',
  'prepublish', 'prepublishOnly', 'publish', 'postpublish',
  'prepack', 'pack', 'postpack',
  'preuninstall', 'uninstall', 'postuninstall',
  'preversion', 'version', 'postversion',
  // Yarn 1 legacy
  'preinstalled',
  // Yarn 2+
  'prepack',      // (duplicate — deduplicated by Set below)
  'prepublishOnly',
  // Test/deploy hooks that are commonly abused despite not being canonical
  // (some CI runs `npm run test` blindly on install).
  'test',   // opt-in — some pipelines invoke this pre-merge
];
const LIFECYCLE_SET = new Set(LIFECYCLE_KEYS);

export const installDetector: Detector = {
  id: 'install',
  category: 'INSTALL',
  run(pair: SnapshotPair): Finding[] {
    const out: Finding[] = [];
    if (!pair.new) return out;
    const newScripts = pair.new.manifest.scripts ?? {};
    const oldScripts = pair.old?.manifest.scripts ?? {};
    for (const k of LIFECYCLE_SET) {
      const newBody = newScripts[k];
      if (!newBody) continue;
      const oldBody = oldScripts[k];
      if (!oldBody) {
        // Script was not present before — a genuine addition. When the package
        // itself was also newly added (pair.old === null), we mark 'added';
        // when the package was upgraded, this is a 'changed' event on the
        // package (which contains a newly-added script).
        const isNewPackage = pair.old === null;
        out.push({
          detector: 'install.script-added',
          category: 'INSTALL',
          package: pair.new.name,
          from: isNewPackage ? null : pair.old!.version,
          to: pair.new.version,
          direction: isNewPackage ? 'added' : 'changed',
          severity: 'BLOCK',
          confidence: 'high',
          message: `Lifecycle script "${k}" was added.`,
          evidence: [
            {
              file: 'package.json',
              line: 1,
              snippet: `${k}: ${newBody.slice(0, 200)}`,
            },
          ],
          provenance: [],
        });
      } else if (oldBody !== newBody) {
        out.push({
          detector: 'install.script-changed',
          category: 'INSTALL',
          package: pair.new.name,
          from: pair.old?.version ?? null,
          to: pair.new.version,
          direction: 'changed',
          severity: 'BLOCK',
          confidence: 'high',
          message: `Lifecycle script "${k}" body changed.`,
          evidence: [
            {
              file: 'package.json',
              line: 1,
              snippet: `${k}: ${newBody.slice(0, 200)}`,
            },
          ],
          provenance: [],
        });
      }
    }
    return out;
  },
};
