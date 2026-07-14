/**
 * python-env-access-widening — completeness-vector transform for the
 * `python-env-access` class (STARTUP §3.5 sink: `os-environ-read`; detector
 * chokepoint: `capabilities.pyEnvAccesses`).
 *
 * The class covers Python's environment-variable reads — `os.environ["FOO"]`,
 * `os.environ.get("FOO")`, and `os.getenv("FOO")`. The engine's Python
 * capability extractor keys on `os.environ` and `os.getenv` patterns to emit
 * an `envAccess` finding of class `python-env-access`.
 *
 * The transform shipped here — `pyOsEnvironToGetenv` — rewrites
 * `os.environ["FOO"]` (indexed dict access) to `os.getenv("FOO")` (function
 * call). Both retrieve the same env var; the class is invariant. If the
 * scanner keys on `os.environ` but not `os.getenv`, the class is
 * spelling-incomplete.
 *
 * Line-based rewrite (see python-code-exec-widening.ts for rationale). Matches
 * `os.environ["KEY"]`, `os.environ['KEY']`, and `os.environ.get("KEY")` and
 * emits `os.getenv("KEY")` in place. Preserves surrounding text.
 *
 * ENGINE ROUTING NOTE — same as python-code-exec-widening.ts: routed to
 * `NO_ENGINE_DETECTOR_YET` until an assurance Python scenario ships.
 */

import type { CompletenessTransform } from './types.js';

/** Rewrite os.environ["KEY"] and os.environ.get("KEY") to os.getenv("KEY"). */
function rewriteEnvironToGetenv(source: string): string {
  let out = source;
  let rewrote = false;

  // os.environ["KEY"]  or  os.environ['KEY']
  const bracketRe = /os\.environ\[\s*(['"])([A-Za-z_][A-Za-z0-9_]*)\1\s*\]/g;
  const newOut1 = out.replace(bracketRe, (_m, _q, key) => {
    rewrote = true;
    return `os.getenv("${key}")`;
  });
  out = newOut1;

  // os.environ.get("KEY")
  const getRe = /os\.environ\.get\(\s*(['"])([A-Za-z_][A-Za-z0-9_]*)\1(?:\s*,\s*[^)]*)?\s*\)/g;
  const newOut2 = out.replace(getRe, (_m, _q, key) => {
    rewrote = true;
    return `os.getenv("${key}")`;
  });
  out = newOut2;

  return rewrote ? out : source;
}

export const pyOsEnvironToGetenv: CompletenessTransform = {
  id: 'py-os-environ-to-getenv',
  family: 'sink-family-widening',
  targetClass: 'python-env-access',
  description:
    'Rewrite os.environ["KEY"] (indexed) and os.environ.get("KEY") to os.getenv("KEY"). Same class (Python env read), sibling API — completeness probe for the python-env-access class.',
  transform(source, _seed): string {
    return rewriteEnvironToGetenv(source);
  },
};
