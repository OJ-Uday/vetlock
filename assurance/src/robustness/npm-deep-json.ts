/**
 * npm-deep-json — package-lock.json with pathologically deep / wide / escape-heavy shapes.
 *
 * Real npm v3 lockfiles have hundreds to low thousands of flat entries under `packages`,
 * with modest per-entry payloads. This generator produces syntactically valid npm v3
 * lockfiles that push one axis at a time:
 *
 *   nested-dependencies — `packages` keys are deeply nested `node_modules/a0/node_modules/a1/...`
 *                         paths. Each entry declares a dependency on a name that only exists
 *                         at the root, forcing `resolveDepKey` to walk from the entry's depth
 *                         all the way up. Depth = scale ⇒ O(scale^2) work in the edge pass.
 *   wide-packages       — `packages` has `scale` flat entries at a single depth. Exercises
 *                         `Object.entries` iteration, Map allocation for `nodes` + `byName`.
 *   escaped-unicode     — a small lockfile whose version string is `scale` copies of `A`
 *                         (letter 'A'). JSON.parse must materialize each escape; the resulting
 *                         string is then stored in the graph. Tests parse-time + retention.
 *
 * `parseLockfileText` on `.json` input runs `JSON.parse(text)` (iterative in V8) then hands
 * the parsed object to `parseLockfile`. The `parseLockfile` graph-build pass is the target.
 *
 * Deterministic. Same seed + params → identical bytes.
 */

import type { RobustnessGenerator, LockfileInput } from './types.js';

export interface NpmDeepJsonParams {
  readonly mode: 'nested-dependencies' | 'wide-packages' | 'escaped-unicode';
  /** Interpretation depends on mode: depth for nested, entry count for wide, repetitions for unicode. */
  readonly scale: number;
}

/** The dep name every nested entry declares — resolves only at root, forcing full walk-up. */
const WALKUP_TARGET = 'target-package';

function buildNestedDependencies(depth: number): string {
  // Build a package-lock.json where entry N is at depth N (node_modules/a0/node_modules/a1/...).
  // Every entry declares a dep on WALKUP_TARGET. The target exists at the root's node_modules,
  // so resolveDepKey walks from the entry's position all the way up to root for each.
  const packages: Record<string, unknown> = {};
  packages[''] = {
    name: 'test',
    version: '1.0.0',
    dependencies: { [WALKUP_TARGET]: '1.0.0', a0: '1.0.0' },
  };
  packages[`node_modules/${WALKUP_TARGET}`] = {
    version: '1.0.0',
    resolved: 'https://registry.npmjs.org/target-package/-/target-package-1.0.0.tgz',
    // No integrity — we deliberately avoid live-looking hashes; defang-guard scans corpus fixtures.
    dependencies: {},
  };
  let path = '';
  for (let d = 0; d < depth; d++) {
    const parentPath = path;
    const name = `a${d}`;
    const key = parentPath === '' ? `node_modules/${name}` : `${parentPath}/node_modules/${name}`;
    const nextName = `a${d + 1}`;
    packages[key] = {
      version: '1.0.0',
      // Depend on the next segment (which will exist directly below) AND on the walkup target
      // (which forces the walk-up scan). Having both means each edge pass does the direct
      // lookup PLUS the up-walk.
      dependencies: {
        [nextName]: '1.0.0',
        [WALKUP_TARGET]: '1.0.0',
      },
    };
    path = key;
  }
  return JSON.stringify({
    name: 'test',
    version: '1.0.0',
    lockfileVersion: 3,
    requires: true,
    packages,
  });
}

function buildWidePackages(count: number): string {
  // Flat: N entries at depth 1, each with a unique name. Every entry declares one dep on
  // the walkup target so the resolver does one hop per entry (bounded work per entry, O(N)
  // total in the loop, plus Map growth).
  const packages: Record<string, unknown> = {};
  const rootDeps: Record<string, string> = { [WALKUP_TARGET]: '1.0.0' };
  for (let i = 0; i < count; i++) {
    rootDeps[`p${i}`] = '1.0.0';
  }
  packages[''] = {
    name: 'test',
    version: '1.0.0',
    dependencies: rootDeps,
  };
  packages[`node_modules/${WALKUP_TARGET}`] = {
    version: '1.0.0',
    resolved: 'https://registry.npmjs.org/target-package/-/target-package-1.0.0.tgz',
    dependencies: {},
  };
  for (let i = 0; i < count; i++) {
    packages[`node_modules/p${i}`] = {
      version: '1.0.0',
      dependencies: { [WALKUP_TARGET]: '1.0.0' },
    };
  }
  return JSON.stringify({
    name: 'test',
    version: '1.0.0',
    lockfileVersion: 3,
    requires: true,
    packages,
  });
}

function buildEscapedUnicode(repetitions: number): string {
  // Legal JSON escape: A (letter 'A'). Repeat `repetitions` times in the version string.
  // JSON.parse must decode each escape; the resulting string is retained in the graph node.
  // We emit the escapes RAW in the JSON source so JSON.parse actually sees them (not a
  // JSON.stringify'd plain 'A' string).
  const escapes = '\\u0041'.repeat(repetitions);
  const inner = `{
    "name": "test",
    "version": "${escapes}",
    "lockfileVersion": 3,
    "requires": true,
    "packages": {
      "": {"name": "test", "version": "${escapes}"},
      "node_modules/target": {"version": "${escapes}"}
    }
  }`;
  return inner;
}

export const npmDeepJson: RobustnessGenerator<NpmDeepJsonParams> = {
  id: 'npm-deep-json',
  description:
    'package-lock.json v3 with pathological shape (deeply nested paths, very wide packages map, or escape-heavy strings). Exercises parseLockfile graph-build + JSON.parse.',
  format: 'npm',
  generate(seed, params): LockfileInput {
    // Seed is currently unused — the shape is fully determined by (mode, scale). The signature
    // is stable for future variants that randomize per-entry names or dep declarations.
    void seed;
    if (!params) {
      throw new Error('npm-deep-json: params are required (mode + scale)');
    }
    const { mode, scale } = params;
    if (!Number.isInteger(scale) || scale < 0 || scale > 1_000_000) {
      throw new Error(`npm-deep-json: scale must be a non-negative integer ≤ 1_000_000; got ${scale}`);
    }
    let text: string;
    switch (mode) {
      case 'nested-dependencies':
        text = buildNestedDependencies(scale);
        break;
      case 'wide-packages':
        text = buildWidePackages(scale);
        break;
      case 'escaped-unicode':
        text = buildEscapedUnicode(scale);
        break;
      default: {
        const _exhaustive: never = mode;
        throw new Error(`npm-deep-json: unknown mode ${JSON.stringify(_exhaustive)}`);
      }
    }
    return {
      text,
      filename: 'package-lock.json',
      format: 'npm',
    };
  },
};
