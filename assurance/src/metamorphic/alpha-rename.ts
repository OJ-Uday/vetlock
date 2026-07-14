/**
 * alpha-rename — rename an LHS binding without changing its usage semantics.
 *
 * A `const foo = require('child_process'); foo.exec(...)` and
 * `const bar = require('child_process'); bar.exec(...)` are the same program up
 * to alpha-conversion. Any analyzer that pattern-matches on the local name of a
 * module alias (rather than the value bound to it) will produce different
 * findings on the two, and that's a completeness gap. The engine's real design
 * tracks aliases via a moduleAliases map — this pair family stresses that
 * behavior end-to-end.
 *
 * Target edge case: identifier-based heuristics that string-match on names like
 * `cp`, `child_process`, `spawn` should be defeated by any renaming; the
 * capability class remains code-execution regardless of the alias.
 */

import type { PairGenerator, MetamorphicPair } from './types.js';
import { makeRng, pick } from './prng.js';

/** Bounded rename pool. Every name is a valid JS identifier and safe on Windows. */
const IDENT_POOL: readonly string[] = [
  'cp', 'proc', 'kids', 'shell', 'launcher',
  'net', 'client', 'http1', 'req',
  'fsx', 'io', 'disk',
  'env', 'e', 'venv',
];

interface Case {
  readonly tag: string;
  readonly renameFrom: string;
  /** Template producing the source. `${name}` is substituted with the identifier. */
  readonly template: (name: string) => string;
  readonly description: string;
}

const CASES: readonly Case[] = [
  {
    tag: 'child-process-exec',
    renameFrom: 'cp',
    template: (n) =>
      `const ${n} = require("child_process");\n${n}.exec("echo defanged");\n`,
    description: 'child_process alias renamed — exec capability must not depend on alias name',
  },
  {
    tag: 'child-process-spawn',
    renameFrom: 'cp',
    template: (n) =>
      `const ${n} = require("child_process");\n${n}.spawn("echo", []);\n`,
    description: 'child_process alias renamed — spawn capability must not depend on alias name',
  },
  {
    tag: 'http-request',
    renameFrom: 'http',
    template: (n) =>
      `const ${n} = require("http");\n${n}.request("http://example.com/api");\n`,
    description: 'http alias renamed — net-egress capability must not depend on alias name',
  },
  {
    tag: 'fs-writeFile',
    renameFrom: 'fs',
    template: (n) =>
      `const ${n} = require("fs");\n${n}.writeFileSync("/tmp/x.txt", "hi");\n`,
    description: 'fs alias renamed — fs-write capability must not depend on alias name',
  },
  {
    tag: 'process-env-alias',
    renameFrom: 'env',
    template: (n) =>
      `const ${n} = process.env;\nconst t = ${n}.NPM_TOKEN;\n`,
    description: 'process.env alias renamed — env-read capability must not depend on alias name',
  },
];

export const alphaRename: PairGenerator = {
  family: 'alpha-rename',
  description:
    'Rename an LHS binding without changing usage. Capability class must be alias-independent.',
  generate(seed): MetamorphicPair {
    const rng = makeRng(seed);
    const c = pick(rng, CASES);
    // Deterministically pick a *different* identifier than the original.
    let candidate = pick(rng, IDENT_POOL);
    // If we happen to pick the same name as the baseline, walk the pool
    // deterministically until we find one that differs.
    for (let i = 0; candidate === c.renameFrom && i < IDENT_POOL.length; i++) {
      candidate = IDENT_POOL[(IDENT_POOL.indexOf(candidate) + 1) % IDENT_POOL.length];
    }
    const a = c.template(c.renameFrom);
    const b = c.template(candidate);
    return {
      id: `alpha-rename-${c.tag}`,
      family: 'alpha-rename',
      a,
      b,
      description: c.description,
    };
  },
};
