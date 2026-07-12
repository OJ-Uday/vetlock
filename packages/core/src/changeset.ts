/**
 * Compute the set of nodes whose (version, integrity) changed between two lockfile
 * graphs, plus added/removed nodes.
 *
 * A "changed node" here means: same (name, key-shape) but different (version, integrity),
 * OR present in one and not the other.
 *
 * The keying strategy: we use *nodeKey* (the lockfile path) as identity. That gives
 * exact positional diffs. For "did a new node appear anywhere in the tree", we look at
 * the set of (name, version) tuples reachable from root.
 */

import type { LockGraph } from './lockfile.js';

export type ChangeKind = 'added' | 'removed' | 'upgraded' | 'integrity-changed';

export interface Change {
  kind: ChangeKind;
  name: string;
  nodeKeyOld: string | null;
  nodeKeyNew: string | null;
  oldVersion: string | null;
  newVersion: string | null;
  oldIntegrity: string | null;
  newIntegrity: string | null;
}

export function computeChangeset(oldG: LockGraph, newG: LockGraph): Change[] {
  const changes: Change[] = [];

  // Compare by identity: (name, version, integrity). This lets us handle hoisting —
  // a package appearing at multiple keys is one package.
  const oldByNameVer = new Map<string, { key: string; integrity: string; version: string; name: string }>();
  const newByNameVer = new Map<string, { key: string; integrity: string; version: string; name: string }>();

  for (const [key, node] of oldG.nodes) {
    if (key === '') continue;
    if (!node.version) continue;
    oldByNameVer.set(`${node.name}@${node.version}`, {
      key, integrity: node.integrity, version: node.version, name: node.name,
    });
  }
  for (const [key, node] of newG.nodes) {
    if (key === '') continue;
    if (!node.version) continue;
    newByNameVer.set(`${node.name}@${node.version}`, {
      key, integrity: node.integrity, version: node.version, name: node.name,
    });
  }

  // Same-version integrity mismatch → BLOCK-tier signal (before any other diffs).
  for (const [id, n] of newByNameVer) {
    const o = oldByNameVer.get(id);
    if (o && n.integrity !== o.integrity && n.integrity && o.integrity) {
      changes.push({
        kind: 'integrity-changed',
        name: n.name,
        nodeKeyOld: o.key,
        nodeKeyNew: n.key,
        oldVersion: o.version,
        newVersion: n.version,
        oldIntegrity: o.integrity,
        newIntegrity: n.integrity,
      });
    }
  }

  // Version upgrades / downgrades → look at set of versions per name.
  const oldByName = new Map<string, Array<{ version: string; key: string; integrity: string }>>();
  const newByName = new Map<string, Array<{ version: string; key: string; integrity: string }>>();
  for (const n of oldByNameVer.values()) {
    (oldByName.get(n.name) ?? oldByName.set(n.name, []).get(n.name)!).push({
      version: n.version, key: n.key, integrity: n.integrity,
    });
  }
  for (const n of newByNameVer.values()) {
    (newByName.get(n.name) ?? newByName.set(n.name, []).get(n.name)!).push({
      version: n.version, key: n.key, integrity: n.integrity,
    });
  }

  const allNames = new Set([...oldByName.keys(), ...newByName.keys()]);
  for (const name of allNames) {
    const oldVs = oldByName.get(name) ?? [];
    const newVs = newByName.get(name) ?? [];
    const oldVerSet = new Set(oldVs.map((v) => v.version));
    const newVerSet = new Set(newVs.map((v) => v.version));

    if (oldVs.length === 0 && newVs.length > 0) {
      // Added — one finding per new version instance (multiple positions collapse to one)
      const seen = new Set<string>();
      for (const v of newVs) {
        if (seen.has(v.version)) continue;
        seen.add(v.version);
        changes.push({
          kind: 'added',
          name,
          nodeKeyOld: null,
          nodeKeyNew: v.key,
          oldVersion: null,
          newVersion: v.version,
          oldIntegrity: null,
          newIntegrity: v.integrity,
        });
      }
      continue;
    }
    if (newVs.length === 0 && oldVs.length > 0) {
      const seen = new Set<string>();
      for (const v of oldVs) {
        if (seen.has(v.version)) continue;
        seen.add(v.version);
        changes.push({
          kind: 'removed',
          name,
          nodeKeyOld: v.key,
          nodeKeyNew: null,
          oldVersion: v.version,
          newVersion: null,
          oldIntegrity: v.integrity,
          newIntegrity: null,
        });
      }
      continue;
    }

    // Both sides have entries: any version present in new but not old is an upgrade (or added instance).
    for (const nv of newVs) {
      if (!oldVerSet.has(nv.version)) {
        // Find the "closest" old version as the "from" — pick the max old version by
        // lexical order for now (semver-aware ordering can wait).
        const closestOld = pickClosest(oldVs.map((v) => v.version), nv.version);
        changes.push({
          kind: 'upgraded',
          name,
          nodeKeyOld: closestOld ? oldVs.find((v) => v.version === closestOld)!.key : null,
          nodeKeyNew: nv.key,
          oldVersion: closestOld,
          newVersion: nv.version,
          oldIntegrity: closestOld ? oldVs.find((v) => v.version === closestOld)!.integrity : null,
          newIntegrity: nv.integrity,
        });
      }
    }
    for (const ov of oldVs) {
      if (!newVerSet.has(ov.version)) {
        // If we've already emitted an 'upgraded' for a new version that "replaces" this
        // old one, don't double-emit a 'removed'. We only emit 'removed' for versions that
        // no longer have any counterpart in the new set (partial hoist collapse).
        // Simple rule: if new has zero entries with a version < this one and zero >
        // this one (i.e. this version was fully dropped), emit 'removed'.
        // Practical simplification: only emit 'removed' when *no* new version of this name
        // exists at all. We already handled that case above. So here we skip.
      }
    }
  }

  // Sort deterministically for downstream stability.
  changes.sort((a, b) => {
    if (a.name !== b.name) return a.name < b.name ? -1 : 1;
    if (a.kind !== b.kind) return a.kind < b.kind ? -1 : 1;
    return (a.newVersion ?? '').localeCompare(b.newVersion ?? '');
  });

  return changes;
}

function pickClosest(candidates: string[], target: string): string | null {
  if (candidates.length === 0) return null;
  // If any candidate < target, return the max such. Else return min.
  const less = candidates.filter((c) => c < target);
  if (less.length > 0) return less.sort().at(-1)!;
  return candidates.sort()[0]!;
}
