/**
 * pnpm-lock.yaml parser.
 *
 * Uses `js-yaml` for the YAML tokenizing pass — the same parser pnpm's own
 * tooling uses. We then walk the parsed object tree to build a LockGraph
 * matching the shape produced by lockfile.ts (the npm parser).
 *
 * Supports pnpm lockfile versions 5.x through 9.x. Format reference:
 * https://pnpm.io/lockfile
 */

import yaml from 'js-yaml';
import type { LockGraph, LockNode } from './lockfile.js';
import { UnsupportedLockfileError } from './lockfile.js';

interface RawImporter {
  dependencies?: Record<string, string | { specifier?: string; version?: string }>;
  devDependencies?: Record<string, string | { specifier?: string; version?: string }>;
  optionalDependencies?: Record<string, string | { specifier?: string; version?: string }>;
}

interface RawPnpmLock {
  lockfileVersion?: string | number;
  importers?: Record<string, RawImporter>;
  // v5-6 flat form: root deps at top level
  dependencies?: RawImporter['dependencies'];
  devDependencies?: RawImporter['devDependencies'];
  optionalDependencies?: RawImporter['optionalDependencies'];
  packages?: Record<string, {
    resolution?: { integrity?: string; tarball?: string };
    dependencies?: Record<string, string>;
    optionalDependencies?: Record<string, string>;
    peerDependencies?: Record<string, string>;
    dev?: boolean;
    optional?: boolean;
  }>;
  // pnpm v9 pushes runtime deps to a separate 'snapshots' map keyed the same way
  snapshots?: Record<string, {
    dependencies?: Record<string, string>;
    optionalDependencies?: Record<string, string>;
  }>;
}

/**
 * Parse pnpm-lock.yaml text into a LockGraph.
 * Package-map keys in pnpm look like:
 *   /chalk@5.3.1                 (v5-7 leading slash)
 *   chalk@5.3.1                  (v9 no slash)
 *   /@scope/pkg@1.0.0
 *   /pkg@1.0.0(peer@2.0.0)       (peer suffix stripped)
 */
export function parsePnpmLockText(yamlText: string): LockGraph {
  const doc = yaml.load(yamlText) as RawPnpmLock;
  if (!doc || typeof doc !== 'object') {
    throw new UnsupportedLockfileError('pnpm-lock.yaml root is not an object');
  }

  const versionField = doc.lockfileVersion;
  const version =
    typeof versionField === 'string' ? parseFloat(versionField) : Number(versionField);
  if (!Number.isFinite(version) || version < 5.0) {
    throw new UnsupportedLockfileError(
      `unsupported pnpm-lock.yaml version ${versionField}; need >= 5.0`,
    );
  }

  const nodes = new Map<string, LockNode>();
  const byName = new Map<string, string[]>();

  // Determine root importer.
  const rootImporter: RawImporter =
    doc.importers?.['.'] ?? {
      dependencies: doc.dependencies,
      devDependencies: doc.devDependencies,
      optionalDependencies: doc.optionalDependencies,
    };
  const rootDepNames = collectRootDepNames(rootImporter);

  // Insert the root node.
  const rootNode: LockNode = {
    key: '',
    name: '',
    version: '',
    integrity: '',
    resolved: null,
    dependencies: [],
  };
  nodes.set('', rootNode);

  // Insert every package. We synthesize a canonical key `node_modules/<name>`;
  // duplicates (same name at multiple versions) get `@version` disambiguator.
  const pkgs = doc.packages ?? {};
  const snapshots = doc.snapshots ?? {};

  // First pass: create nodes.
  for (const rawKey of Object.keys(pkgs)) {
    const parsed = parsePnpmPackageKey(rawKey);
    if (!parsed) continue;
    const { name, version: v } = parsed;
    const entry = pkgs[rawKey]!;

    // Canonical key. Disambiguate collisions by version.
    let key = `node_modules/${name}`;
    if (nodes.has(key)) key = `${key}@${v}`;
    // Still not unique? add the raw key hash suffix.
    while (nodes.has(key)) key = `${key}#${nodes.size}`;

    nodes.set(key, {
      key,
      name,
      version: v,
      integrity: entry.resolution?.integrity ?? '',
      resolved: entry.resolution?.tarball ?? null,
      dependencies: [],
    });
    (byName.get(name) ?? byName.set(name, []).get(name)!).push(key);
  }

  // Root's dependency list = direct deps from the importer.
  for (const depName of rootDepNames) {
    const keys = byName.get(depName) ?? [];
    if (keys[0]) rootNode.dependencies.push(keys[0]);
  }

  // Second pass: attach each package's own dependencies. In v6-8 the deps are
  // inline in `packages`; in v9 they live in `snapshots`. Merge both.
  for (const rawKey of Object.keys(pkgs)) {
    const parsed = parsePnpmPackageKey(rawKey);
    if (!parsed) continue;
    const keys = byName.get(parsed.name) ?? [];
    const nodeKey = keys[0];
    if (!nodeKey) continue;
    const node = nodes.get(nodeKey);
    if (!node) continue;

    const inline = pkgs[rawKey];
    const snap = snapshots[rawKey];
    const deps: Record<string, string> = {
      ...(inline?.dependencies ?? {}),
      ...(inline?.optionalDependencies ?? {}),
      ...(snap?.dependencies ?? {}),
      ...(snap?.optionalDependencies ?? {}),
    };

    for (const depName of Object.keys(deps)) {
      const dks = byName.get(depName) ?? [];
      if (dks[0]) node.dependencies.push(dks[0]);
    }
    node.dependencies = [...new Set(node.dependencies)];
  }

  return {
    lockfileVersion: version,
    rootName: '',
    rootVersion: '',
    nodes,
    byName,
    // pnpm-lock.yaml has no `link: true` shape today; workspace projects
    // appear in `importers:` but we don't extract them here yet. Empty array
    // satisfies the LockGraph contract added for the npm-parser F2 fix.
    workspaceLinks: [],
  };
}

function collectRootDepNames(importer: RawImporter): string[] {
  const names: string[] = [];
  for (const map of [importer.dependencies, importer.devDependencies, importer.optionalDependencies]) {
    if (!map) continue;
    for (const k of Object.keys(map)) names.push(k);
  }
  return [...new Set(names)];
}

/** Parse a pnpm package-key like `/chalk@5.3.1(peer@2.0.0)` or `chalk@5.3.1`. */
export function parsePnpmPackageKey(raw: string): { name: string; version: string } | null {
  let key = raw.startsWith('/') ? raw.slice(1) : raw;
  const paren = key.indexOf('(');
  if (paren !== -1) key = key.slice(0, paren);
  const at = key.lastIndexOf('@');
  if (at <= 0) return null;
  const name = key.slice(0, at);
  const version = key.slice(at + 1);
  if (!name || !version) return null;
  return { name, version };
}
