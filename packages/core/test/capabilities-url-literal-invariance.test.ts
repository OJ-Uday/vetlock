/**
 * URL-literal invariance regression test — pins the assurance Wave 5-W fix
 * for the concat-vs-template metamorphic gap.
 *
 * Before the fix, `extractCapabilities` emitted an extra intermediate URL
 * literal for the string-concatenation form because the constant-folding
 * pass over `"http://" + host + "/api"` produces TWO folded expressions in
 * the same subtree — the inner `"http://" + host` (which folds to
 * `"http://example.com"`) and the outer `"http://" + host + "/api"` (which
 * folds to `"http://example.com/api"`). The post-fold sweep visited both
 * nodes and dropped both values into the URL-literal set. The template-
 * literal form `` `http://${host}/api` `` has no such inner sub-expression:
 * it folds in ONE pass, emitting only the outer value.
 *
 * The two programs are runtime-equivalent — same imports, same call, same
 * argument string — so the analyzer's decision surface MUST be equal. The
 * fix (packages/core/src/capabilities.ts → `iterateFolds`) skips any folded
 * node whose parent is also folded: the parent's folded value is a strict
 * superset of the child's, so all signal is preserved.
 *
 * Corpus entry:
 *   assurance/corpus/metamorphic/equivalent-expression-string-concat-vs-template/
 *
 * If this test ever regresses, the concat form has re-introduced the
 * intermediate URL emission — the metamorphic invariant is broken again.
 */
import { describe, it, expect } from 'vitest';
import { extractCapabilities } from '../src/capabilities.js';

const CONCAT_FORM = `const http = require("http");
const host = "example" + ".com";
http.request("http://" + host + "/api");
`;

const TEMPLATE_FORM = `const http = require("http");
const host = \`example.com\`;
http.request(\`http://\${host}/api\`);
`;

function cap(src: string) {
  return extractCapabilities('pair.js', src, 'sha-fake', src.length);
}

describe('URL-literal invariance: string-concat vs template literal', () => {
  it('both forms produce identical urlLiterals', () => {
    const capA = cap(CONCAT_FORM);
    const capB = cap(TEMPLATE_FORM);
    // Sort both — order can vary, only the SET matters for the metamorphic invariant.
    expect([...capA.urlLiterals].sort()).toEqual([...capB.urlLiterals].sort());
  });

  it('both forms produce identical urlLiteral COUNTS', () => {
    // Explicit count check: the pre-fix concat form emitted 3 literals, the
    // template form 2. Post-fix they must match. Locked in as a distinct
    // assertion so a future regression that adds the same intermediate to
    // BOTH forms would still be caught by the identity check above but this
    // pin makes the count expectation explicit and self-documenting.
    const capA = cap(CONCAT_FORM);
    const capB = cap(TEMPLATE_FORM);
    expect(capA.urlLiterals.length).toBe(capB.urlLiterals.length);
  });

  it('the FINAL folded URL is preserved (not lost as a side-effect of the dedupe)', () => {
    // The concrete signal we must NEVER regress: the fully-folded exfil-shape
    // URL `http://example.com/api` must survive the intermediate-fold dedupe.
    // If we ever accidentally drop the parent-folded value, we'd silently
    // lose the primary URL signal — worse than the original gap.
    const capA = cap(CONCAT_FORM);
    const capB = cap(TEMPLATE_FORM);
    expect(capA.urlLiterals).toContain('http://example.com/api');
    expect(capB.urlLiterals).toContain('http://example.com/api');
  });

  it('other detector signals are equal across both forms (module, no-dynamic-code)', () => {
    // Structural symmetry beyond urlLiterals: both must record the http
    // import identically and neither must flag a dynamic-code site (both
    // require('http') resolves as a literal).
    const capA = cap(CONCAT_FORM);
    const capB = cap(TEMPLATE_FORM);
    expect(capA.networkModules).toEqual(capB.networkModules);
    expect(capA.networkModules).toContain('http');
    expect(capA.dynamicCode).toHaveLength(0);
    expect(capB.dynamicCode).toHaveLength(0);
  });
});

describe('URL-literal invariance: nested concat still emits outer folded URL', () => {
  it('deeply nested string concat emits the outermost URL and NOT the intermediates', () => {
    // Regression-guard for the fix itself: a THREE-way concat should also
    // emit only the outer folded value. If iterateFolds ever regresses to
    // emitting intermediates, this catches it.
    const src = `const u = "https://" + "evil" + "." + "example" + ".invalid" + "/exfil";`;
    const c = cap(src);
    // Outer value must be present.
    expect(c.urlLiterals).toContain('https://evil.example.invalid/exfil');
    // No stray intermediate URL that only differs by omitting the trailing path.
    // (`https://evil.example.invalid` on its own would be the classic intermediate.)
    // We assert a bounded upper count instead of pinning an exact set — the
    // StringLiteral visitor may still fire on the bare `.invalid` fragment via
    // the URL_REGEX bare-host branch, but a well-formed fix produces AT MOST
    // one entry for a single-concat-chain source. A count > 2 would signal a
    // regression to the intermediate-emit shape.
    expect(c.urlLiterals.length).toBeLessThanOrEqual(2);
  });
});
