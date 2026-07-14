/**
 * statement-reorder — swap two independent top-level statements.
 *
 * Semantically identical when the statements are independent (no shared bindings,
 * no side-effect ordering that matters, no hoisting-dependent references). We
 * generate cases where BOTH statements are `const` declarations of distinct
 * identifiers, or a require() alias + a distinct require() alias — the analyzer's
 * per-file capability set must be commutative under statement order.
 *
 * Target edge case: any analyzer pass that tracks "the first require() found" or
 * "the require() reachable from the top" would misfire on B when the sensitive
 * import moves down the list. The capability set is a SET; order must not matter.
 */

import type { PairGenerator, MetamorphicPair } from './types.js';
import { makeRng, pick } from './prng.js';

/**
 * Two statements chosen from this table. Each pair is:
 *   { s1, s2, tag }
 * where s1 and s2 are ORDER-INDEPENDENT (distinct LHS names, distinct callees).
 * The "tag" is used to name the pair id deterministically.
 *
 * We deliberately mix a *sensitive* statement with a *benign* one so the
 * question "does swap change the capability finding?" is testable.
 */
const CASES: readonly {
  readonly tag: string;
  readonly s1: string;
  readonly s2: string;
  readonly description: string;
}[] = [
  {
    tag: 'exec-then-fs',
    s1: `const cp = require("child_process");`,
    s2: `const fs = require("fs");`,
    description: 'child_process + fs requires — swap must not drop either capability',
  },
  {
    tag: 'net-then-env',
    s1: `const http = require("http");`,
    s2: `const token = process.env.NPM_TOKEN;`,
    description: 'net-egress import + env-read — capability set must be commutative',
  },
  {
    tag: 'exec-then-benign',
    s1: `const cp = require("child_process");`,
    s2: `const path = require("path");`,
    description: 'sensitive + benign require — swap must not lose the sensitive one',
  },
  {
    tag: 'fs-then-benign',
    s1: `const fs = require("fs");`,
    s2: `const os = require("os");`,
    description: 'fs + benign require — swap must not lose the fs capability',
  },
  {
    tag: 'dns-then-benign',
    s1: `const dns = require("dns");`,
    s2: `const util = require("util");`,
    description: 'dns exfil channel + benign — dns detection must be order-independent',
  },
];

export const statementReorder: PairGenerator = {
  family: 'statement-reorder',
  description:
    'Swap two independent top-level statements. Capability sets must be commutative.',
  generate(seed): MetamorphicPair {
    const rng = makeRng(seed);
    const c = pick(rng, CASES);
    // A: statement 1 then statement 2. B: statement 2 then statement 1.
    const a = `${c.s1}\n${c.s2}\n`;
    const b = `${c.s2}\n${c.s1}\n`;
    return {
      id: `statement-reorder-${c.tag}`,
      family: 'statement-reorder',
      a,
      b,
      description: c.description,
    };
  },
};
