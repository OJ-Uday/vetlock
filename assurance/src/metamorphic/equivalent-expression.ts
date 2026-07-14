/**
 * equivalent-expression — same expression written two syntactically-different ways.
 *
 * Semantically-equivalent rewrites at the expression level. Examples:
 *   `!!x`      ↔ `Boolean(x)`
 *   `a + 0`    ↔ `a`             (only when `a` is guaranteed numeric — we pin numeric
 *                                  literals to avoid the string-coercion trap)
 *   `x - -1`   ↔ `x + 1`
 *   `x === y ? true : false` ↔ `x === y`
 *
 * These are boring in isolation, but the invariant they defend is not: an analyzer
 * that key-matches on `Boolean(` (e.g. to skip "safe" transformations) would silently
 * change verdicts when the same construct is written as `!!`. Wrapped around a
 * sensitive call (`Boolean(process.env.NPM_TOKEN)` vs `!!process.env.NPM_TOKEN`), both
 * should produce the same env-read finding.
 *
 * Target edge case: expression-level shape-matchers should route on semantics, not
 * on `CallExpression(Identifier("Boolean"))`.
 */

import type { PairGenerator, MetamorphicPair } from './types.js';
import { makeRng, pick } from './prng.js';

interface Case {
  readonly tag: string;
  readonly a: string;
  readonly b: string;
  readonly description: string;
}

/** Every case is context-complete: full JS a browser or Node could parse. */
const CASES: readonly Case[] = [
  {
    tag: 'not-not-vs-boolean',
    a: `const has = !!process.env.NPM_TOKEN;\n`,
    b: `const has = Boolean(process.env.NPM_TOKEN);\n`,
    description:
      '!!x vs Boolean(x) around process.env access — env-read must be detected in both forms',
  },
  {
    tag: 'add-zero-numeric',
    a: `const n = 42 + 0;\nconst fs = require("fs");\nfs.writeFileSync("/tmp/x", String(n));\n`,
    b: `const n = 42;\nconst fs = require("fs");\nfs.writeFileSync("/tmp/x", String(n));\n`,
    description:
      'a + 0 vs a (numeric literal) — surrounding fs-write must be detected identically',
  },
  {
    tag: 'ternary-vs-comparison',
    a: `const cp = require("child_process");\nconst run = 1 === 1 ? true : false;\nif (run) cp.exec("echo defanged");\n`,
    b: `const cp = require("child_process");\nconst run = 1 === 1;\nif (run) cp.exec("echo defanged");\n`,
    description:
      '(x?true:false) vs x — dead-code around child_process.exec must not hide the capability',
  },
  {
    tag: 'string-concat-vs-template',
    a: `const http = require("http");\nconst host = "example" + ".com";\nhttp.request("http://" + host + "/api");\n`,
    b: `const http = require("http");\nconst host = \`example.com\`;\nhttp.request(\`http://\${host}/api\`);\n`,
    description:
      'string concat vs template literal — http/URL detection must survive constant-folding form',
  },
  {
    tag: 'double-negation-in-conditional',
    a: `const fs = require("fs");\nif (!!fs) fs.readFileSync("/etc/passwd");\n`,
    b: `const fs = require("fs");\nif (fs) fs.readFileSync("/etc/passwd");\n`,
    description:
      '!!x vs x in conditional — fs-read detection must be identical',
  },
];

export const equivalentExpression: PairGenerator = {
  family: 'equivalent-expression',
  description:
    'Semantically-equivalent expression forms. Detectors must route on semantics.',
  generate(seed): MetamorphicPair {
    const rng = makeRng(seed);
    const c = pick(rng, CASES);
    return {
      id: `equivalent-expression-${c.tag}`,
      family: 'equivalent-expression',
      a: c.a,
      b: c.b,
      description: c.description,
    };
  },
};
