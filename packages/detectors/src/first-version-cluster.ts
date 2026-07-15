/**
 * DEPS first-version-with-cluster compound detector.
 *
 * Fires when a package is ADDED (not upgraded) AND ships three or more
 * distinct capability categories at once. Real npm packages nearly never do
 * this on their first version — a package that on day one already imports
 * network+process+fs modules AND reads sensitive env is a red flag by shape.
 *
 * BLOCK, high. Only fires on pair.old === null.
 */

import type { Detector, DetectorCategory, EnvAccess, Finding, SnapshotPair } from '@vetlock/core';
import { SENSITIVE_ENV_KEYS } from '@vetlock/core';
import { directionFor } from './direction.js';

const CLUSTER_CATEGORIES: readonly DetectorCategory[] = ['NET', 'EXEC', 'FS', 'ENV', 'CODE', 'OBF'];
const SENSITIVE_SET = new Set(SENSITIVE_ENV_KEYS);

function isSensitiveEnvAccess(access: EnvAccess): boolean {
  return access.keys === null || access.keys.some((key) => SENSITIVE_SET.has(key));
}

export const firstVersionClusterDetector: Detector = {
  id: 'deps-first-version-cluster',
  category: 'DEPS',
  run(pair: SnapshotPair): Finding[] {
    // Only ADDED packages
    if (pair.old !== null || !pair.new) return [];
    const dir = directionFor(null);
    const snap = pair.new;

    const cats = new Set<DetectorCategory>();
    let netModuleHit = false;
    let execModuleHit = false;
    let fsModuleHit = false;
    let envSensitiveHit = false;
    let codeSinkHit = false;
    let obfHit = false;

    for (const f of snap.files) {
      if (f.networkModules.length > 0) netModuleHit = true;
      if (f.execModules.length > 0) execModuleHit = true;
      if (f.fsModules.length > 0) fsModuleHit = true;
      if (f.envAccesses.some(isSensitiveEnvAccess)) envSensitiveHit = true;
      if (f.dynamicCode.length > 0) codeSinkHit = true;
      if (f.minified || f.suspiciousLiterals.length > 0) obfHit = true;
    }
    if (netModuleHit) cats.add('NET');
    if (execModuleHit) cats.add('EXEC');
    if (fsModuleHit) cats.add('FS');
    if (envSensitiveHit) cats.add('ENV');
    if (codeSinkHit) cats.add('CODE');
    if (obfHit) cats.add('OBF');

    // Threshold: 3+ categories. Below that, the individual detectors cover it.
    if (cats.size < 3) return [];

    const catList = [...cats].sort();
    return [
      {
        detector: 'deps.first-version-cluster',
        category: 'DEPS',
        package: snap.name,
        from: dir.from,
        to: snap.version,
        direction: dir.direction,
        severity: 'BLOCK',
        confidence: 'high',
        message: `Newly-installed package ships ${cats.size} capability categories on its first version: ${catList.join(', ')}. This shape is rare in legitimate packages.`,
        evidence: [
          {
            file: 'package.json',
            line: 1,
            snippet: `first-version-with-cluster: ${catList.join(', ')} across ${snap.files.length} file(s)`,
          },
        ],
        provenance: [],
      },
    ];
  },
};

// Re-exported for testing
export { CLUSTER_CATEGORIES };
