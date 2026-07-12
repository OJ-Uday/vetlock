/**
 * Lockfile parsing → in-memory graph.
 *
 * Supports package-lock.json v2 and v3 (the shape we see from npm ≥ 7).
 * v1 (npm 6) is not supported and yields a helpful error — it's rare in 2026.
 *
 * A `LockGraph` is the shared substrate for changeset compute and provenance.
 */

export interface LockNode {
  /** Unique key: the lockfile path, e.g. 'node_modules/foo' or ''
   * (root). We use path-keyed identity because a package can appear at multiple
   * positions (hoisting) — we still treat those as distinct nodes and dedup
   * by (name, version, integrity) downstream when we want the *package* view.
   */
  key: string;
  name: string;
  version: string;
  /** ssri integrity, e.g. 'sha512-…'. Empty for the root project. */
  integrity: string;
  /** URL/tarball resolved field, if present. */
  resolved: string | null;
  /** Children by nodeKey — the flat 'packages' shape of v2/v3 lockfiles has
   * an implicit parent relationship we recompute here. */
  dependencies: string[];
}

export interface LockGraph {
  lockfileVersion: number;
  rootName: string;
  rootVersion: string;
  /** All nodes keyed by their lockfile path. */
  nodes: Map<string, LockNode>;
  /** For quick lookup: name → set of nodeKeys where it appears. */
  byName: Map<string, string[]>;
}

export interface LockfileV2V3 {
  name?: string;
  version?: string;
  lockfileVersion: number;
  packages: Record<string, {
    name?: string;
    version?: string;
    integrity?: string;
    resolved?: string;
    dependencies?: Record<string, string>;
    devDependencies?: Record<string, string>;
    optionalDependencies?: Record<string, string>;
    peerDependencies?: Record<string, string>;
    hasInstallScript?: boolean;
    link?: boolean;
    dev?: boolean;
  }>;
}

export class UnsupportedLockfileError extends Error {
  constructor(msg: string) {
    super(msg);
    this.name = 'UnsupportedLockfileError';
  }
}

/**
 * Parse a package-lock.json (v2 or v3) into a graph.
 * v1 or unknown shapes throw UnsupportedLockfileError.
 */
export function parseLockfile(raw: unknown): LockGraph {
  if (!raw || typeof raw !== 'object') {
    throw new UnsupportedLockfileError('lockfile is not an object');
  }
  const lock = raw as LockfileV2V3;
  if (typeof lock.lockfileVersion !== 'number') {
    throw new UnsupportedLockfileError(
      'missing lockfileVersion field (v1 lockfiles are not supported — please regenerate with npm ≥ 7)',
    );
  }
  if (lock.lockfileVersion < 2) {
    throw new UnsupportedLockfileError(
      `lockfileVersion ${lock.lockfileVersion} is not supported (need ≥ 2)`,
    );
  }
  if (!lock.packages || typeof lock.packages !== 'object') {
    throw new UnsupportedLockfileError('lockfile has no packages map');
  }

  const nodes = new Map<string, LockNode>();
  const byName = new Map<string, string[]>();

  for (const [key, val] of Object.entries(lock.packages)) {
    if (val.link) continue; // symlinked workspace entries — not shipped packages
    const name = val.name ?? deriveNameFromKey(key);
    if (!name) continue;
    const node: LockNode = {
      key,
      name,
      version: val.version ?? '',
      integrity: val.integrity ?? '',
      resolved: val.resolved ?? null,
      dependencies: [],
    };
    nodes.set(key, node);
    const list = byName.get(name) ?? [];
    list.push(key);
    byName.set(name, list);
  }

  // Root name/version comes from the '' entry OR from the top-level fields.
  const rootEntry = lock.packages[''];
  const rootName = rootEntry?.name ?? lock.name ?? '';
  const rootVersion = rootEntry?.version ?? lock.version ?? '';

  // Rebuild parent → children relationships. In v2/v3, dependencies are resolved
  // to the nearest ancestor path where the name is available. We approximate:
  // for each dep name of a node at key K, we look for candidate nodes at
  //   K + '/node_modules/' + name
  //   ancestor + '/node_modules/' + name   (walking up)
  // and take the deepest one that exists.
  for (const [key, val] of Object.entries(lock.packages)) {
    if (val.link) continue;
    const parentNode = nodes.get(key);
    if (!parentNode) continue;
    const allDeps = {
      ...val.dependencies,
      ...val.optionalDependencies,
      ...val.peerDependencies,
    };
    for (const depName of Object.keys(allDeps)) {
      const resolvedKey = resolveDepKey(key, depName, nodes);
      if (resolvedKey) {
        parentNode.dependencies.push(resolvedKey);
      }
    }
    // Dedup
    parentNode.dependencies = [...new Set(parentNode.dependencies)];
  }

  return {
    lockfileVersion: lock.lockfileVersion,
    rootName,
    rootVersion,
    nodes,
    byName,
  };
}

function deriveNameFromKey(key: string): string | null {
  if (key === '') return null;
  // 'node_modules/foo' → 'foo'; 'node_modules/@scope/bar' → '@scope/bar';
  // 'node_modules/a/node_modules/b' → 'b'.
  // Real npm keys always look like 'node_modules/<name>' with possibly nested
  // '/node_modules/<name>' segments.
  const idx = key.lastIndexOf('node_modules/');
  if (idx === -1) return null;
  const suffix = key.slice(idx + 'node_modules/'.length);
  return suffix || null;
}

function resolveDepKey(
  parentKey: string,
  depName: string,
  nodes: Map<string, LockNode>,
): string | null {
  // Walk up the parent's path, checking for node_modules/<depName> at each level.
  let path = parentKey;
  // First try in the parent's own node_modules:
  const first =
    parentKey === ''
      ? `node_modules/${depName}`
      : `${parentKey}/node_modules/${depName}`;
  if (nodes.has(first)) return first;
  // Then walk up until we hit root.
  while (path !== '') {
    // Trim one level.
    const idx = path.lastIndexOf('/node_modules/');
    if (idx === -1) {
      // We were one segment deep; drop to root.
      path = '';
    } else {
      path = path.slice(0, idx);
    }
    const candidate = path === '' ? `node_modules/${depName}` : `${path}/node_modules/${depName}`;
    if (nodes.has(candidate)) return candidate;
  }
  return null;
}

/**
 * All shortest paths from root ('') to a target node, BFS. Returns up to `maxPaths`
 * paths — we render "+N more" at the caller if there are more.
 */
export function shortestPaths(
  graph: LockGraph,
  targetKey: string,
  maxPaths = 3,
): string[][] {
  const results: string[][] = [];
  if (!graph.nodes.has(targetKey)) return results;
  const queue: Array<{ key: string; path: string[] }> = [
    { key: '', path: [graph.rootName || '(root)'] },
  ];
  const seenAtLen = new Map<string, number>();
  let shortestLen = Infinity;
  while (queue.length > 0) {
    const cur = queue.shift()!;
    if (cur.path.length > shortestLen) break;
    if (cur.key === targetKey && cur.path.length > 1) {
      results.push(cur.path);
      if (results.length === 1) shortestLen = cur.path.length;
      if (results.length >= maxPaths) break;
      continue;
    }
    const seen = seenAtLen.get(cur.key);
    if (seen !== undefined && seen < cur.path.length) continue;
    seenAtLen.set(cur.key, cur.path.length);
    const node = graph.nodes.get(cur.key);
    if (!node) continue;
    for (const childKey of node.dependencies) {
      const child = graph.nodes.get(childKey);
      if (!child) continue;
      // Avoid trivial cycles
      if (cur.path.some((seg, i) => i > 0 && seg === child.name)) continue;
      queue.push({ key: childKey, path: [...cur.path, child.name] });
    }
  }
  return results;
}
