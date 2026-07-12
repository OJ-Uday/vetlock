/**
 * INSTALL detector — lifecycle scripts.
 * Fires when the new manifest introduces (or changes) a pre/post/install/prepare
 * script. Severity BLOCK, confidence high.
 */
import type { Detector, Finding, SnapshotPair } from '@vetlock/core';

const LIFECYCLE_KEYS: readonly string[] = [
  'preinstall', 'install', 'postinstall', 'prepare', 'preprepare', 'postprepare',
];

export const installDetector: Detector = {
  id: 'install',
  category: 'INSTALL',
  run(pair: SnapshotPair): Finding[] {
    const out: Finding[] = [];
    if (!pair.new) return out;
    const newScripts = pair.new.manifest.scripts ?? {};
    const oldScripts = pair.old?.manifest.scripts ?? {};
    for (const k of LIFECYCLE_KEYS) {
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
