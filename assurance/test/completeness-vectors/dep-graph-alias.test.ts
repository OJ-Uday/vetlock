/**
 * dep-graph-alias — completeness-vector transform self-tests.
 *
 * Contract every transform satisfies:
 *   • PURITY / DETERMINISM — `transform(src, seed) === transform(src, seed)` byte-identical.
 *   • NON-TRIVIALITY       — when the target pattern is present in `src`, `transform !== src`.
 *   • SYNTACTIC VALIDITY   — output parses as valid JSON.
 *   • SEMANTIC PRESERVATION MARKER — the alias form (`npm:<name>@<version>`) appears in the output.
 */

import { describe, it, expect } from 'vitest';
import { namedAliasToNodeModulesPath } from '../../src/completeness-vectors/dep-graph-alias.js';

const SEEDS: readonly number[] = [0, 1, 7, 42, 1337, 2_147_483_647];

/** A package.json with a plain dependency spec — the transform must alias it. */
const PKG_WITH_PLAIN_DEP = JSON.stringify(
  {
    name: 'defanged-fixture',
    version: '0.0.0',
    dependencies: {
      foo: '^1.2.3',
    },
  },
  null,
  2,
);

/** A package.json whose ONLY dependency is already aliased. The transform must
 *  no-op (there's no non-aliased entry to rewrite). */
const PKG_WITH_ALIAS_ONLY = JSON.stringify(
  {
    name: 'defanged-fixture',
    version: '0.0.0',
    dependencies: {
      foo: 'npm:already-aliased@1.0.0',
    },
  },
  null,
  2,
);

/** A package.json with no dependencies — every transform should be a no-op. */
const PKG_NO_DEPS = JSON.stringify(
  {
    name: 'defanged-fixture',
    version: '0.0.0',
  },
  null,
  2,
);

describe('completeness-vectors — dep-graph-alias', () => {
  it('declares the dep-graph-anomaly targetClass and required metadata fields', () => {
    expect(namedAliasToNodeModulesPath.targetClass).toBe('dep-graph-anomaly');
    expect(namedAliasToNodeModulesPath.id.length).toBeGreaterThan(0);
    expect(namedAliasToNodeModulesPath.family.length).toBeGreaterThan(0);
    expect(namedAliasToNodeModulesPath.description.length).toBeGreaterThan(0);
  });

  it('is pure/deterministic: same (source, seed) → byte-identical output', () => {
    for (const seed of SEEDS) {
      const a = namedAliasToNodeModulesPath.transform(PKG_WITH_PLAIN_DEP, seed);
      const b = namedAliasToNodeModulesPath.transform(PKG_WITH_PLAIN_DEP, seed);
      expect(b).toBe(a);
    }
  });

  it('is non-trivial: output DIFFERS from input when a plain dep is present', () => {
    for (const seed of SEEDS) {
      const out = namedAliasToNodeModulesPath.transform(PKG_WITH_PLAIN_DEP, seed);
      expect(out).not.toBe(PKG_WITH_PLAIN_DEP);
    }
  });

  it('produces syntactically valid JSON output', () => {
    for (const seed of SEEDS) {
      const out = namedAliasToNodeModulesPath.transform(PKG_WITH_PLAIN_DEP, seed);
      expect(() => JSON.parse(out)).not.toThrow();
    }
  });

  it('rewrites the plain spec into `npm:<name>@<version>` alias form (semantic-preservation)', () => {
    for (const seed of SEEDS) {
      const out = namedAliasToNodeModulesPath.transform(PKG_WITH_PLAIN_DEP, seed);
      const parsed = JSON.parse(out) as { dependencies?: Record<string, string> };
      expect(parsed.dependencies?.foo).toBe('npm:foo@1.2.3');
    }
  });

  it('the original plain spec is no longer present in the dependency value', () => {
    const out = namedAliasToNodeModulesPath.transform(PKG_WITH_PLAIN_DEP, 0);
    const parsed = JSON.parse(out) as { dependencies?: Record<string, string> };
    // The original spec was `^1.2.3`; the rewritten value must not equal it.
    expect(parsed.dependencies?.foo).not.toBe('^1.2.3');
    // And the semantic dep name is preserved.
    expect(parsed.dependencies?.foo).toContain('foo');
  });

  it('is a no-op when every dependency is already aliased', () => {
    for (const seed of SEEDS) {
      const out = namedAliasToNodeModulesPath.transform(PKG_WITH_ALIAS_ONLY, seed);
      expect(out).toBe(PKG_WITH_ALIAS_ONLY);
    }
  });

  it('is a no-op on a package.json with no dependencies field', () => {
    for (const seed of SEEDS) {
      const out = namedAliasToNodeModulesPath.transform(PKG_NO_DEPS, seed);
      expect(out).toBe(PKG_NO_DEPS);
    }
  });

  it('is a no-op on non-JSON input', () => {
    const notJson = 'const x = 1;\nconsole.log(x);\n';
    for (const seed of SEEDS) {
      const out = namedAliasToNodeModulesPath.transform(notJson, seed);
      expect(out).toBe(notJson);
    }
  });
});
