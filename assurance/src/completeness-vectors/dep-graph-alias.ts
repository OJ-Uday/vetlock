/**
 * dep-graph-alias — rewrite an npm dependency spec into the `npm:` alias form.
 * The dep-graph-anomaly class (STARTUP extension; packet §3.5 covers the
 * dependency-graph shape at large) covers surfaces where a package's DECLARED
 * name diverges from what it actually installs — a shape aliased packages take
 * naturally, and one attackers exploit via alias-injection to make a manifest
 * and a resolved package disagree.
 *
 * Two equivalent shapes exist for expressing a dependency in package.json:
 *
 *   • plain:  "foo": "^1.0.0"
 *     — declared name `foo`, resolves to registry package `foo`.
 *   • alias:  "foo": "npm:actual-package@1.0.0"
 *     — declared name `foo`, RESOLVES to a DIFFERENT registry package.
 *
 * A scanner that keys on `dependencies` entries but doesn't parse the `npm:`
 * alias prefix misses the shape where the manifest-declared name differs from
 * the installed identity. Both shapes populate the same package.json field; the
 * only difference is the version-string SYNTAX.
 *
 * The transform shipped here — `namedAliasToNodeModulesPath` — walks a
 * package.json JSON string, finds the FIRST dependency in `dependencies`, and
 * rewrites its version spec to the alias form:
 *
 *     "foo": "^1.0.0"
 *   →
 *     "foo": "npm:foo@1.0.0"
 *
 * The alias TARGET is the same package name (so the semantic dependency is
 * preserved — this is a completeness probe, not an integrity attack). A scanner
 * that understands the alias syntax should treat `npm:foo@1.0.0` as installing
 * the same `foo` package as `^1.0.0`; a scanner that doesn't will see the
 * verbatim version string diverge.
 *
 * Input contract: a JSON string parseable as an object with a `dependencies`
 * field. If the input isn't parseable JSON, or has no dependencies, or all
 * dependencies are already aliased, the transform is a no-op.
 */

import type { CompletenessTransform } from './types.js';

/** Extract a version number from a semver-y string, or fall back to `1.0.0`.
 *  We don't need semver-correctness; we need a version string that scans as
 *  valid to `npm:` alias parsers. */
function extractVersion(spec: string): string {
  // Strip leading range operators ^, ~, >=, <=, >, <, = and whitespace.
  const trimmed = spec.replace(/^[\s^~<>=]+/, '');
  // Match a semver-shape prefix — digits[.digits[.digits]] with optional pre-release.
  const m = trimmed.match(/^\d+(?:\.\d+){0,2}(?:-[\w.]+)?/);
  return m ? m[0] : '1.0.0';
}

export const namedAliasToNodeModulesPath: CompletenessTransform = {
  id: 'named-alias-to-node-modules-path',
  family: 'sink-family-widening',
  targetClass: 'dep-graph-anomaly',
  description:
    'Rewrite the first dependencies entry from "foo": "^1.0.0" to "foo": "npm:foo@1.0.0" alias form. Same semantic dependency, different manifest shape (the alias axis of the dep-graph-anomaly class).',
  transform(source, _seed): string {
    let parsed: unknown;
    try {
      parsed = JSON.parse(source);
    } catch {
      return source;
    }
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      return source;
    }
    const pkg = parsed as Record<string, unknown>;
    const deps = pkg.dependencies;
    if (typeof deps !== 'object' || deps === null || Array.isArray(deps)) {
      return source;
    }
    const depMap = deps as Record<string, unknown>;
    // Find the first entry whose value is a non-alias string. Iteration order is
    // insertion order for string-keyed object literals (ES2015+); JSON.parse
    // preserves it in every mainstream runtime.
    let targetKey: string | null = null;
    for (const [k, v] of Object.entries(depMap)) {
      if (typeof v !== 'string') continue;
      if (v.startsWith('npm:')) continue; // already aliased
      targetKey = k;
      break;
    }
    if (targetKey === null) return source;
    const originalSpec = depMap[targetKey] as string;
    const version = extractVersion(originalSpec);
    depMap[targetKey] = `npm:${targetKey}@${version}`;
    return JSON.stringify(pkg, null, 2);
  },
};
