/**
 * graph-dos — package-lock.json v3 with pathological graph shapes (packet §2.1 Graph DoS).
 *
 * @vetlock/core's runDiff pipeline is:
 *   parseLockfileText -> parseLockfile (graph build) -> computeChangeset (per-name diff)
 *   -> concurrent analyzeOne (per changed node) -> runDetectors -> finding emission.
 *
 * Realistic npm lockfiles have hundreds of nodes, dozens of direct deps, nesting depths in
 * the single digits. This generator produces JSON lockfiles that are still SYNTACTICALLY
 * valid v3 (npm ≥ 7) but semantically hostile — the shapes an attacker could deliver via
 * a compromised publish or a typo-squat's own dependency tree.
 *
 * Modes (all yield a `package-lock.json`-shaped v3 lockfile):
 *
 *   million-nodes         — N flat entries at `node_modules/pkg<i>`, no dep edges. Stresses
 *                           parseLockfile's node-map build (Map<string,LockNode>), byName
 *                           insertions, and the "added" enumeration in computeChangeset.
 *
 *   deep-transitive-chain — a single dep chain N deep:
 *                             root → pkg0 → pkg1 → … → pkg(N-1)
 *                           key of deepest node has O(N) segments. Stresses parseLockfile's
 *                           resolveDepKey walk (which strips `/node_modules/<name>` suffixes)
 *                           and any downstream code that indexes by key length.
 *
 *   wide-fanout           — root declares N direct dependencies, all resolved at top-level
 *                           `node_modules/dep<i>`. Stresses the rollup/subtree walk in
 *                           engine.computeRollup and shortestPaths' BFS breadth.
 *
 *   duplicate-heavy       — the same package name `foo` at N distinct versions at N distinct
 *                           paths (hoisted collisions). byName['foo'] balloons to N; the
 *                           per-name diff loop in computeChangeset iterates O(N) versions;
 *                           pickClosest is called O(N) times.
 *
 * Determinism: same (seed, params) → byte-identical output. Seed is currently unused (shape
 * is fully determined by params) but reserved for future variants that randomize package
 * names to defeat V8 string interning across runs.
 *
 * Bounds: scale ≤ 1_000_000 (a hard cap to prevent the generator itself OOM-ing before the
 * runner gets its chance). Baseline for CI is scale=100; stress cases (10_000+) live in
 * longer-timeout tests. Above ~100k the JSON we emit approaches Node's max string length
 * on some V8 builds, which is a generator-side limit — not an engine gap.
 */

import type { RobustnessGenerator, LockfileInput } from './types.js';

export type GraphDosMode =
  | 'million-nodes'
  | 'deep-transitive-chain'
  | 'wide-fanout'
  | 'duplicate-heavy';

export interface GraphDosParams {
  readonly mode: GraphDosMode;
  /** Interpretation depends on mode — see module doc. Must be a non-negative integer. */
  readonly scale: number;
}

const MAX_SCALE = 1_000_000;

/**
 * Deterministic 40-char hex string keyed on (seed, name, version). Not a real hash — we
 * only need distinct integrity-looking values so the parser accepts them and byName-diff
 * distinguishes changed integrities. Real ssri would drag @vetlock/core into the generator's
 * dep set for no assurance benefit.
 */
function fakeSha512(seed: number, name: string, version: string): string {
  // FNV-1a-ish rolling hash over the three inputs, unrolled into two u32 lanes so we get
  // 64 bits of state — enough distinct values across 1M packages that collisions won't
  // change parser behavior. This is not cryptographic; it doesn't need to be.
  const inputs = `${seed}\0${name}\0${version}`;
  let h1 = 0x811c9dc5 ^ seed;
  let h2 = 0xdeadbeef ^ (seed * 2654435761);
  for (let i = 0; i < inputs.length; i++) {
    const c = inputs.charCodeAt(i);
    h1 = Math.imul(h1 ^ c, 16777619) >>> 0;
    h2 = Math.imul(h2 ^ c, 2246822519) >>> 0;
  }
  // 88 base64 chars is standard for sha512; we mimic the shape with a hex-of-fixed-length
  // that npm's ssri accepts leniently. The core parser only stores the string; it doesn't
  // validate the payload.
  const hex1 = h1.toString(16).padStart(8, '0');
  const hex2 = h2.toString(16).padStart(8, '0');
  return `sha512-${hex1}${hex2}${hex1}${hex2}${hex1}${hex2}${hex1}${hex2}${hex1}${hex2}==`;
}

/** Zero-pad an integer to a fixed width so lexical order matches numeric order for the
 *  package-name stream — helps determinism in downstream sorts. Width is chosen once from
 *  scale so pkg000000000 vs pkg0 never mix. */
function pad(n: number, width: number): string {
  return n.toString().padStart(width, '0');
}

function widthFor(scale: number): number {
  // ceil(log10(scale)); minimum 1 so scale=0 or 1 still yields a valid pad.
  if (scale <= 1) return 1;
  return Math.max(1, Math.ceil(Math.log10(scale)));
}

// ------------------------------------------------------------------------------------------
// Mode builders. Each returns a v3 lockfile string. We JSON.stringify in one shot per entry
// rather than building the whole object in memory — for scale=1M that saves ~500MB of RAM.

/**
 * Emit a v3 lockfile whose `packages` map contains the given entries. We stream-write to a
 * string via array push+join to bound memory: one entry's JSON is short (~200 bytes), so
 * even 1M entries stays under ~200MB in the intermediate array — still risky at 1M but the
 * generator's MAX_SCALE guard bounds us there.
 */
interface LockEntry {
  readonly key: string;
  readonly name?: string;
  readonly version?: string;
  readonly integrity?: string;
  readonly dependencies?: Record<string, string>;
}

function buildV3Lockfile(rootEntry: LockEntry, packages: LockEntry[]): string {
  // We hand-format the JSON so we don't have to materialize a giant object. The v3 spec is
  // relaxed about field order but strict about the top-level required keys.
  const parts: string[] = [];
  parts.push('{\n');
  parts.push('  "name": "graph-dos-test",\n');
  parts.push('  "version": "1.0.0",\n');
  parts.push('  "lockfileVersion": 3,\n');
  parts.push('  "requires": true,\n');
  parts.push('  "packages": {\n');
  // Root entry always first.
  parts.push('    "": ');
  parts.push(entryToJson(rootEntry));
  const total = packages.length;
  if (total > 0) parts.push(',');
  parts.push('\n');
  for (let i = 0; i < total; i++) {
    const e = packages[i]!;
    parts.push('    ');
    parts.push(JSON.stringify(e.key));
    parts.push(': ');
    parts.push(entryToJson(e));
    if (i < total - 1) parts.push(',');
    parts.push('\n');
  }
  parts.push('  }\n');
  parts.push('}\n');
  return parts.join('');
}

function entryToJson(e: LockEntry): string {
  // Minimal per-entry shape. Only the fields the engine actually reads. Ordered stably
  // (name, version, integrity, resolved, dependencies) for deterministic output.
  const obj: Record<string, unknown> = {};
  if (e.name !== undefined) obj.name = e.name;
  if (e.version !== undefined) obj.version = e.version;
  if (e.integrity !== undefined) obj.integrity = e.integrity;
  if (e.dependencies !== undefined) obj.dependencies = e.dependencies;
  return JSON.stringify(obj);
}

function buildMillionNodes(seed: number, scale: number): string {
  const width = widthFor(scale);
  const root: LockEntry = {
    key: '',
    name: 'graph-dos-test',
    version: '1.0.0',
  };
  const packages: LockEntry[] = new Array(scale);
  for (let i = 0; i < scale; i++) {
    const name = `pkg${pad(i, width)}`;
    const version = '1.0.0';
    packages[i] = {
      key: `node_modules/${name}`,
      version,
      integrity: fakeSha512(seed, name, version),
    };
  }
  return buildV3Lockfile(root, packages);
}

function buildDeepTransitiveChain(seed: number, scale: number): string {
  const width = widthFor(scale);
  // Root depends on pkg0; pkg0 depends on pkg1 at node_modules/pkg0/node_modules/pkg1; etc.
  const root: LockEntry = {
    key: '',
    name: 'graph-dos-test',
    version: '1.0.0',
    dependencies: scale > 0 ? { [`pkg${pad(0, width)}`]: '1.0.0' } : undefined,
  };
  const packages: LockEntry[] = new Array(scale);
  // Build the cumulative path prefix once per level so we don't re-concatenate O(N²) chars.
  const segments: string[] = [];
  for (let i = 0; i < scale; i++) {
    const name = `pkg${pad(i, width)}`;
    segments.push(`node_modules/${name}`);
    const key = segments.join('/');
    const nextName = i + 1 < scale ? `pkg${pad(i + 1, width)}` : null;
    packages[i] = {
      key,
      version: '1.0.0',
      integrity: fakeSha512(seed, name, '1.0.0'),
      dependencies: nextName !== null ? { [nextName]: '1.0.0' } : undefined,
    };
  }
  return buildV3Lockfile(root, packages);
}

function buildWideFanout(seed: number, scale: number): string {
  const width = widthFor(scale);
  const deps: Record<string, string> = {};
  const packages: LockEntry[] = new Array(scale);
  for (let i = 0; i < scale; i++) {
    const name = `dep${pad(i, width)}`;
    deps[name] = '1.0.0';
    packages[i] = {
      key: `node_modules/${name}`,
      version: '1.0.0',
      integrity: fakeSha512(seed, name, '1.0.0'),
    };
  }
  const root: LockEntry = {
    key: '',
    name: 'graph-dos-test',
    version: '1.0.0',
    dependencies: scale > 0 ? deps : undefined,
  };
  return buildV3Lockfile(root, packages);
}

function buildDuplicateHeavy(seed: number, scale: number): string {
  // The victim name we duplicate at N versions.
  const victim = 'foo';
  const width = widthFor(scale);
  const packages: LockEntry[] = [];
  // First copy sits at the top-level path. Subsequent copies are nested under a unique
  // "holder<i>" package so the lockfile path is unique — but the parsed `name` is still
  // `foo`, so byName['foo'] balloons to N.
  //
  // A copy count of 0 or 1 emits the trivial variant (no holders); higher scales create
  // one holder per additional copy.
  for (let i = 0; i < scale; i++) {
    const version = `1.0.${i}`;
    if (i === 0) {
      packages.push({
        key: `node_modules/${victim}`,
        version,
        integrity: fakeSha512(seed, victim, version),
      });
      continue;
    }
    const holderName = `holder${pad(i, width)}`;
    // Holder package itself — the engine's parseLockfile will insert it into byName too.
    packages.push({
      key: `node_modules/${holderName}`,
      version: '1.0.0',
      integrity: fakeSha512(seed, holderName, '1.0.0'),
      dependencies: { [victim]: version },
    });
    // The nested victim copy.
    packages.push({
      key: `node_modules/${holderName}/node_modules/${victim}`,
      version,
      integrity: fakeSha512(seed, victim, version),
    });
  }
  const rootDeps: Record<string, string> = {};
  if (scale > 0) rootDeps[victim] = '1.0.0';
  // Also declare each holder as a direct dep so resolveDepKey has fuel to walk.
  for (let i = 1; i < scale; i++) {
    rootDeps[`holder${pad(i, width)}`] = '1.0.0';
  }
  const root: LockEntry = {
    key: '',
    name: 'graph-dos-test',
    version: '1.0.0',
    dependencies: scale > 0 ? rootDeps : undefined,
  };
  return buildV3Lockfile(root, packages);
}

export const graphDos: RobustnessGenerator<GraphDosParams> = {
  id: 'graph-dos',
  description:
    'package-lock.json v3 with pathological graph shapes (million-nodes / deep-transitive-chain / wide-fanout / duplicate-heavy). Exercises parseLockfile + computeChangeset.',
  format: 'npm',
  generate(seed, params): LockfileInput {
    if (!params) {
      throw new Error(`graph-dos: params is required (must specify mode and scale)`);
    }
    const { mode, scale } = params;
    if (!Number.isInteger(scale) || scale < 0 || scale > MAX_SCALE) {
      throw new Error(
        `graph-dos: scale must be a non-negative integer ≤ ${MAX_SCALE}; got ${scale}`,
      );
    }
    let text: string;
    switch (mode) {
      case 'million-nodes':
        text = buildMillionNodes(seed, scale);
        break;
      case 'deep-transitive-chain':
        text = buildDeepTransitiveChain(seed, scale);
        break;
      case 'wide-fanout':
        text = buildWideFanout(seed, scale);
        break;
      case 'duplicate-heavy':
        text = buildDuplicateHeavy(seed, scale);
        break;
      default: {
        const _exhaustive: never = mode;
        throw new Error(`graph-dos: unknown mode ${JSON.stringify(_exhaustive)}`);
      }
    }
    return {
      text,
      filename: 'package-lock.json',
      format: 'npm',
    };
  },
};
