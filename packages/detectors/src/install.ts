/**
 * INSTALL detector — lifecycle scripts.
 * Fires when the new manifest introduces (or changes) a lifecycle script.
 *
 * v0.4.2 FP-STUDY §3d — severity split by hook type:
 *   - INSTALL-triggered hooks (preinstall/install/postinstall + prepare + prepack
 *     + preuninstall etc): BLOCK — these run on `npm install`, the whole point
 *     of supply-chain scanning. High-signal.
 *   - PUBLISH/VERSION/PACK hooks (prepublish/publish/postpublish + preversion
 *     etc.): WARN — these only run when the developer publishes or tags. Legit
 *     packages routinely change them (e.g. build-step migration). Attacker
 *     would still need the developer to actually publish, and vetlock scans
 *     lockfiles of *consumers*, who never execute publish scripts.
 *   - `test`: INFO — some pipelines run `npm test` on install, but that's opt-in
 *     CI behavior, not npm-default. A `test` script change is not a supply-chain
 *     signal on its own. commander@11→12 fired BLOCK on this in the v0.4.0
 *     FP study; that was noise.
 *
 * v0.4.1 kept ALL of these at BLOCK; measured FP was ~19% of routine bumps.
 *
 * Reference: https://docs.npmjs.com/cli/v10/using-npm/scripts#life-cycle-scripts
 * Reference: https://yarnpkg.com/configuration/manifest#scripts
 */
import type { Detector, Finding, SnapshotPair, Severity } from '@vetlock/core';

// Split by risk tier — see file header for rationale.
// INSTALL_TIER: run automatically on `npm install` from the registry — the
// actual supply-chain-attack vector when a consumer installs a package. BLOCK.
const INSTALL_TIER: readonly string[] = [
  'preinstall', 'install', 'postinstall',
  'preuninstall', 'uninstall', 'postuninstall',
  // Yarn 1 legacy
  'preinstalled',
];

// PUBLISH_TIER: run on `npm publish` / `npm version` / `npm pack` / git-URL
// install for `prepare`. Consumers installing from a registry never execute
// these. Change is worth WARN, not BLOCK. `prepare` is here rather than in
// INSTALL_TIER because in practice ~99% of installs come from the registry
// (where prepare doesn't run) and legit libraries routinely change `prepare`
// as their build tooling evolves. If a consumer specifically installs from
// git (`npm i github:foo/bar`), prepare DOES run — but that's an opt-in
// pattern users take with eyes open.
const PUBLISH_TIER: readonly string[] = [
  'preprepare', 'prepare', 'postprepare',
  'prepublish', 'prepublishOnly', 'publish', 'postpublish',
  'prepack', 'pack', 'postpack',
  'preversion', 'version', 'postversion',
  'preshrinkwrap', 'shrinkwrap', 'postshrinkwrap',
];

// CI_TIER: `npm test` and adjacent. Not npm-executed automatically; some CI
// pipelines run them explicitly. Change is worth INFO — visible but low-signal.
// We intentionally track only execution-capable hooks here, not arbitrary user-
// defined script names.
const CI_TIER: readonly string[] = [
  'test',
  'prestart', 'start', 'poststart',
  'prestop', 'stop', 'poststop',
  'prerestart', 'restart', 'postrestart',
];

function tierOf(script: string): { severity: Severity; confidence: 'low' | 'medium' | 'high' } | null {
  if (INSTALL_TIER.includes(script)) return { severity: 'BLOCK', confidence: 'high' };
  if (PUBLISH_TIER.includes(script)) return { severity: 'WARN', confidence: 'medium' };
  if (CI_TIER.includes(script)) return { severity: 'INFO', confidence: 'low' };
  return null;
}

// Union of all tiers, for iteration.
const ALL_TRACKED: readonly string[] = [...new Set([...INSTALL_TIER, ...PUBLISH_TIER, ...CI_TIER])];

export const installDetector: Detector = {
  id: 'install',
  category: 'INSTALL',
  run(pair: SnapshotPair): Finding[] {
    const out: Finding[] = [];
    if (!pair.new) return out;
    const newScripts = pair.new.manifest.scripts ?? {};
    const oldScripts = pair.old?.manifest.scripts ?? {};
    for (const k of ALL_TRACKED) {
      const newBody = newScripts[k];
      if (!newBody) continue;
      const tier = tierOf(k);
      if (!tier) continue;
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
          severity: tier.severity,
          confidence: tier.confidence,
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
          severity: tier.severity,
          confidence: tier.confidence,
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
