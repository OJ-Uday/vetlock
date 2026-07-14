/**
 * python-supply-chain-normalization — completeness-vector transform for the
 * `python-supply-chain` class (STARTUP §3.5 sink:
 * `typosquat-underscore-hyphen`).
 *
 * The class covers Python-ecosystem supply-chain shape issues, most notably
 * the PEP 503 name-normalization edge case: PyPI treats `foo_bar`, `foo-bar`,
 * and `foo.bar` as the SAME package (all normalize to `foo-bar`), so
 * distributing a package under one spelling while installing another lets a
 * typosquat pass through name-based scanners keyed on the raw registry key.
 *
 * The transform shipped here — `pyHyphenToUnderscoreName` — rewrites a
 * package NAME token in a pyproject.toml `[project]` section from
 * `hyphen-form` to `underscore_form` (or vice versa). Given
 * `name = "some-package"` it emits `name = "some_package"`. Both resolve to
 * the same registry entry per PEP 503; a scanner keying on the raw string
 * misses the sibling spelling.
 *
 * The `family` is `string-normalization` — a name literal is rewritten to an
 * equivalent syntactic form, and the scanner should normalize both before
 * matching (per PEP 503).
 *
 * ENGINE ROUTING NOTE — routed to `NO_ENGINE_DETECTOR_YET`. The engine's
 * python-supply-chain detector operates over a package artifact + a registry
 * name; there's no assurance scenario feeding a pyproject.toml through it
 * today. When such a scenario ships, this transform migrates into the
 * standard survives loop.
 */

import type { CompletenessTransform } from './types.js';

export const pyHyphenToUnderscoreName: CompletenessTransform = {
  id: 'py-hyphen-to-underscore-name',
  family: 'string-normalization',
  targetClass: 'python-supply-chain',
  description:
    "Rewrite a pyproject.toml [project] name from hyphen-form (\"foo-bar\") to underscore-form (\"foo_bar\"). Per PEP 503 the two normalize to the same registry key — completeness probe for the python-supply-chain class's underscore/hyphen sink.",
  transform(source, _seed): string {
    // Match a `name = "value"` line inside a pyproject-shaped body. We don't
    // parse TOML — the transform is a targeted rewrite on the exact line shape
    // pyproject.toml uses, tolerant to leading whitespace.
    const lines = source.split('\n');
    let rewrote = false;
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const m = line.match(/^(\s*name\s*=\s*)(['"])([A-Za-z0-9][A-Za-z0-9._-]*)\2(\s*(?:#.*)?)$/);
      if (!m) continue;
      const nameValue = m[3];
      // Only rewrite when the name contains a hyphen — that's the sink axis.
      // No hyphens → no-op (already in canonical underscore form, or a single-token name).
      if (!nameValue.includes('-')) continue;
      const swapped = nameValue.replace(/-/g, '_');
      lines[i] = `${m[1]}${m[2]}${swapped}${m[2]}${m[4]}`;
      rewrote = true;
      // Only rewrite the first hit — pyproject.toml has exactly one [project].name.
      break;
    }
    return rewrote ? lines.join('\n') : source;
  },
};
