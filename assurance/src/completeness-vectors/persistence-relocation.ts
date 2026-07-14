/**
 * persistence-relocation — rewrite an npm-lifecycle hook so the SAME payload string
 * fires from a DIFFERENT lifecycle key. The persistence class (packet §3.5) covers
 * the family of npm install-hook entry points (STARTUP names this family
 * `install-hook`): a scanner that watches `scripts.postinstall` but doesn't watch
 * `scripts.preinstall` or `scripts.prepare` has a coverage gap along the exact axis
 * this class describes — the SAME hostile string, invoked at a DIFFERENT hook, is
 * still persistence.
 *
 * The transform shipped here — `preinstallToPostinstall` — walks a package.json
 * JSON string, locates `scripts.preinstall`, and renames the key to
 * `scripts.postinstall` (or vice versa if the input already has `postinstall`).
 * The command body is unchanged; only the hook key changes. This is the minimal
 * possible transform that exercises the persistence class's completeness surface:
 *
 *   • If the scanner catches `scripts.preinstall: "echo hi"` but misses
 *     `scripts.postinstall: "echo hi"` (or vice versa), that's a persistence-class
 *     completeness gap.
 *   • The transform is a NO-OP if the input has neither key (no persistence hook
 *     to relocate).
 *
 * Input contract: a JSON string parseable as an object with a `scripts` field.
 * If the input isn't parseable JSON, the transform returns it unchanged — this
 * keeps the transform pure and lets callers pass non-JSON payloads without
 * blowing up (the transform is a no-op on shapes it doesn't recognize).
 *
 * The rewrite target is intentionally scoped to `preinstall` ↔ `postinstall`. Both
 * are the highest-yield npm lifecycle hooks (both fire on `npm install`), so
 * swapping between them is a small, focused completeness probe. Broader lifecycle
 * enumeration (prepare, prepublish, install) is out of scope for this transform —
 * one transform per class per Wave 6-Y, per the wave's coverage-floor scope.
 */

import type { CompletenessTransform } from './types.js';

export const preinstallToPostinstall: CompletenessTransform = {
  id: 'preinstall-to-postinstall',
  family: 'code-location',
  targetClass: 'persistence',
  description:
    'Rewrite a package.json lifecycle script from scripts.preinstall to scripts.postinstall (or vice versa). Same payload, different hook — completeness gap along the persistence class axis.',
  transform(source, _seed): string {
    // Parse the JSON string. If it doesn't parse, return unchanged (transform is a
    // no-op on shapes it doesn't recognize).
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
    const scripts = pkg.scripts;
    if (typeof scripts !== 'object' || scripts === null || Array.isArray(scripts)) {
      return source;
    }
    const s = scripts as Record<string, unknown>;
    // Prefer preinstall → postinstall (the packet's canonical direction). If only
    // postinstall exists, flip the other way so the transform is still non-trivial.
    if (typeof s.preinstall === 'string') {
      const body = s.preinstall;
      delete s.preinstall;
      s.postinstall = body;
    } else if (typeof s.postinstall === 'string') {
      const body = s.postinstall;
      delete s.postinstall;
      s.preinstall = body;
    } else {
      // No relocatable hook — the transform is a no-op.
      return source;
    }
    return JSON.stringify(pkg, null, 2);
  },
};
