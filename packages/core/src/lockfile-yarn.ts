/**
 * yarn.lock parser (yarn classic v1 + yarn berry v2+).
 *
 * Uses the official yarn parsers:
 *   - `@yarnpkg/lockfile`  → classic v1 format
 *   - `@yarnpkg/parsers`   → berry format via parseSyml
 *
 * Both produce a `{name@spec: {version, resolved, integrity, dependencies?}}`-shaped
 * object; we convert to our LockGraph.
 *
 * Yarn keys look like:
 *   'foo@^1.0.0'                    (classic)
 *   'foo@npm:^1.0.0, foo@^1.0.0'    (classic — multiple range aliases)
 *   'foo@npm:1.2.3'                 (berry)
 */

// eslint-disable-next-line @typescript-eslint/consistent-type-imports
import * as yarnLockfileNs from '@yarnpkg/lockfile';
import { parseSyml } from '@yarnpkg/parsers';
import type { LockGraph, LockNode } from './lockfile.js';
import { UnsupportedLockfileError } from './lockfile.js';

// @yarnpkg/lockfile is CommonJS. Depending on the toolchain (tsc emits ESM,
// esbuild in tests, Node's own CJS-to-ESM interop) `parse` may live at either
// `yarnLockfileNs.parse` OR `yarnLockfileNs.default.parse`. Probe both.
const parseClassic: (text: string) => {
  type: 'success' | string;
  object: Record<string, { version?: string; resolved?: string; integrity?: string; dependencies?: Record<string, string>; optionalDependencies?: Record<string, string> }>;
} = (() => {
  const ns = yarnLockfileNs as unknown as {
    parse?: unknown;
    default?: { parse?: unknown };
  };
  if (typeof ns.parse === 'function') return ns.parse as never;
  if (ns.default && typeof ns.default.parse === 'function') return ns.default.parse as never;
  throw new Error('unable to resolve @yarnpkg/lockfile parse export');
})();

interface YarnEntry {
  version?: string;
  resolved?: string;
  integrity?: string;
  dependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
}

/**
 * Detect classic vs berry and dispatch. Classic files start with the marker
 * comment `# yarn lockfile v1`; berry files start with `__metadata:` or have
 * a `__metadata:\n  version: 6+` section.
 */
export function parseYarnLockText(text: string): LockGraph {
  const isBerry = /^\s*__metadata:/m.test(text) || /^__metadata\b/m.test(text);
  return isBerry ? parseBerryLockText(text) : parseClassicLockText(text);
}

export function parseClassicLockText(text: string): LockGraph {
  const parsed = parseClassic(text);
  if (parsed.type !== 'success') {
    throw new UnsupportedLockfileError(`yarn.lock parse failed: ${parsed.type}`);
  }
  return objectToGraph(
    parsed.object as Record<string, YarnEntry>,
    /* lockfileVersion */ 1,
  );
}

export function parseBerryLockText(text: string): LockGraph {
  const parsed = parseSyml(text) as Record<string, unknown>;
  // Strip __metadata block — it's not a package
  const packages: Record<string, YarnEntry> = {};
  let version = 6;
  for (const [k, v] of Object.entries(parsed)) {
    if (k === '__metadata') {
      const meta = v as { version?: string | number };
      if (meta?.version !== undefined) version = Number(meta.version);
      continue;
    }
    packages[k] = v as YarnEntry;
  }
  return objectToGraph(packages, version);
}

function objectToGraph(
  packages: Record<string, YarnEntry>,
  lockfileVersion: number,
): LockGraph {
  const nodes = new Map<string, LockNode>();
  const byName = new Map<string, string[]>();

  // Root
  nodes.set('', {
    key: '',
    name: '',
    version: '',
    integrity: '',
    resolved: null,
    dependencies: [],
  });

  // Yarn lockfile entries can be keyed by MULTIPLE aliases joined with commas,
  // e.g. 'foo@^1.0.0, foo@^1.1.0'. Deduplicate by (name, version).
  const seen = new Map<string, string>(); // 'name@version' → nodeKey
  for (const [rawKey, entry] of Object.entries(packages)) {
    const aliases = rawKey.split(',').map((a) => a.trim()).filter(Boolean);
    for (const alias of aliases) {
      const parsed = parseYarnAlias(alias);
      if (!parsed) continue;
      const { name } = parsed;
      const version = entry.version ?? '';
      if (!version) continue;
      const nvKey = `${name}@${version}`;
      if (seen.has(nvKey)) continue;

      let key = `node_modules/${name}`;
      if (nodes.has(key)) key = `${key}@${version}`;
      while (nodes.has(key)) key = `${key}#${nodes.size}`;

      nodes.set(key, {
        key,
        name,
        version,
        integrity: entry.integrity ?? '',
        resolved: entry.resolved ?? null,
        dependencies: [], // filled below
      });
      (byName.get(name) ?? byName.set(name, []).get(name)!).push(key);
      seen.set(nvKey, key);
    }
  }

  // Second pass: dependencies.
  for (const [rawKey, entry] of Object.entries(packages)) {
    const firstAlias = rawKey.split(',')[0]!.trim();
    const parsed = parseYarnAlias(firstAlias);
    if (!parsed) continue;
    const version = entry.version ?? '';
    const nvKey = `${parsed.name}@${version}`;
    const nodeKey = seen.get(nvKey);
    if (!nodeKey) continue;
    const node = nodes.get(nodeKey);
    if (!node) continue;
    const deps: Record<string, string> = {
      ...(entry.dependencies ?? {}),
      ...(entry.optionalDependencies ?? {}),
    };
    for (const depName of Object.keys(deps)) {
      const dks = byName.get(depName) ?? [];
      if (dks[0]) node.dependencies.push(dks[0]);
    }
    node.dependencies = [...new Set(node.dependencies)];
  }

  return {
    lockfileVersion,
    rootName: '',
    rootVersion: '',
    nodes,
    byName,
  };
}

/**
 * Parse a single yarn.lock alias like:
 *   'foo@^1.0.0'
 *   '@scope/foo@^1.0.0'
 *   'foo@npm:^1.0.0'   (yarn berry)
 */
export function parseYarnAlias(alias: string): { name: string; spec: string } | null {
  const s = alias.trim();
  const atIdx = s.startsWith('@') ? s.indexOf('@', 1) : s.indexOf('@');
  if (atIdx <= 0) return null;
  const name = s.slice(0, atIdx);
  const spec = s.slice(atIdx + 1);
  if (!name || !spec) return null;
  return { name, spec };
}
