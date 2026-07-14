/**
 * python-code-exec — completeness-vector transform for the `python-code-exec`
 * class (STARTUP §3.5 sinks: `b64-plus-exec`, `marshal-loads`; detector
 * chokepoint: `capabilities.pyDynamicCode`).
 *
 * The `python-code-exec` class covers Python's dynamic-code primitives — the
 * builtin `exec(...)` and `eval(...)` calls, plus `compile(_, _, "exec")` and
 * `marshal.loads(...)`. The engine's `extractPythonCapabilities` (packages/core/
 * src/capability-pypi.ts) records these as `dynamicCode[]` sites when it sees
 * them in a `.py` file.
 *
 * The transform shipped here — `pyExecToEval` — rewrites Python `exec(payload)`
 * calls to `eval(compile(payload, "<string>", "exec"))`. Both spellings execute
 * the payload as Python code; the class the scanner should assign is
 * `python-code-exec` in either case. If a Python-aware scanner keys ONLY on
 * `exec(` and misses the `eval(compile(_, _, "exec"))` idiom (a documented,
 * cross-Python-2/3-compatible spelling), the class is spelling-incomplete.
 *
 * Transform contract:
 *   • Line-based rewrite on `.py`-shaped text. NOT AST-based — the assurance
 *     surface doesn't ship a Python parser; the engine's own extractor is
 *     regex-based for the same reason. We match the exact idiom
 *     `<optional whitespace>exec(<...>)` at the start of a line-comment-free line.
 *   • Preserves indentation. Rewriting the head token doesn't change control
 *     flow — Python's `exec` and `eval(compile(...))` both return None-ish and
 *     leave any assigned bindings intact.
 *   • Is a no-op if no matching `exec(` call is found.
 *
 * ENGINE ROUTING NOTE
 * -------------------
 * The assurance runner's `engine:extractCapabilities` scenario dispatches to
 * `engine.extractCapabilities` (the JavaScript AST scanner), NOT to
 * `engine.extractPythonCapabilities`. Feeding a `.py` file through the JS
 * extractor either parseErrors (`fail-safe`) or produces no capability findings
 * — either way, the finding-survives oracle has nothing to compare. Until the
 * assurance runner grows a Python-routed scenario, this transform is routed to
 * `NO_ENGINE_DETECTOR_YET` in evasion-catch-rate.test.ts. Same protocol as
 * Wave 6-Y's crypto-mine transform: coverage-map class covered by an assurance
 * transform, but the engine detector isn't wired through the current runner
 * scenarios.
 */

import type { CompletenessTransform } from './types.js';

/** Rewrite `exec(payload)` calls in Python source. Preserves the exact
 *  argument text (this is line-based, not AST-based — mirrors the extractor).
 *  Idempotent: if the source is already in the eval(compile(...)) shape, the
 *  regex won't match `exec(` at the head of a line, so it's a no-op. */
function rewriteExecToEvalCompile(source: string): string {
  const lines = source.split('\n');
  let rewrote = false;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    // Match leading whitespace + `exec(` (not inside a comment, not a member
    // access — `obj.exec(...)` is a different method). Simple heuristic: the
    // `exec` token must be at the start of the line's non-whitespace content.
    const m = line.match(/^(\s*)exec\((.*)\)\s*$/);
    if (!m) continue;
    const indent = m[1];
    const payload = m[2];
    lines[i] = `${indent}eval(compile(${payload}, "<string>", "exec"))`;
    rewrote = true;
  }
  return rewrote ? lines.join('\n') : source;
}

export const pyExecToEvalCompile: CompletenessTransform = {
  id: 'py-exec-to-eval-compile',
  family: 'sink-family-widening',
  targetClass: 'python-code-exec',
  description:
    'Rewrite Python exec(payload) to eval(compile(payload, "<string>", "exec")). Same class (dynamic code execution), sibling spelling — completeness probe for the python-code-exec class boundary.',
  transform(source, _seed): string {
    return rewriteExecToEvalCompile(source);
  },
};
