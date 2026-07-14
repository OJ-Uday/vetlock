/**
 * whitespace-comments — inject comments and whitespace without changing semantics.
 *
 * Program B is program A with:
 *   • a leading block comment
 *   • extra blank lines between statements
 *   • line comments on the end of each statement
 *   • an inline block comment somewhere in the middle of an expression
 *
 * A parser strips comments; a naive text-based matcher does not. Any capability
 * detector that skips a file based on a leading comment marker (e.g. "// generated
 * by rollup") or that pattern-matches the raw text rather than the AST would
 * change verdicts. Even worse: any detector that BOUNDS ANALYSIS BY LINE NUMBER
 * (e.g. "only scan the first 200 lines") would miss a finding pushed down by
 * comment injection.
 *
 * The transform is byte-invasive but semantically zero — the AST for A and B
 * (comments stripped) is identical.
 */

import type { PairGenerator, MetamorphicPair } from './types.js';
import { makeRng, pick } from './prng.js';

interface Case {
  readonly tag: string;
  /** Program A: the "plain" form. */
  readonly a: string;
  readonly description: string;
}

/**
 * The comment payloads inserted into B. Kept defang-clean (no domains, no exec targets).
 * These strings must pass the defang guard when B is embedded in any corpus file.
 */
const HEADER_COMMENTS: readonly string[] = [
  `/**\n * Auto-injected header. Semantics unchanged.\n */\n`,
  `/* generated-by build; do not edit */\n`,
  `// SPDX-License-Identifier: MIT\n`,
];

const INLINE_COMMENTS: readonly string[] = [
  ` /* pin */`,
  ` /* noop */`,
  ` /* keepalive */`,
];

const CASES: readonly Case[] = [
  {
    tag: 'require-then-call',
    a: `const cp = require("child_process");\ncp.exec("echo defanged");\n`,
    description: 'child_process require + exec — comments+whitespace must not hide the capability',
  },
  {
    tag: 'env-read',
    a: `const token = process.env.NPM_TOKEN;\nconst _ = token;\n`,
    description: 'env-read then use — comment injection must not affect env detection',
  },
  {
    tag: 'fs-write',
    a: `const fs = require("fs");\nfs.writeFileSync("/tmp/pinned", "ok");\n`,
    description: 'fs.writeFileSync — comment injection must not affect fs-write detection',
  },
  {
    tag: 'http-import-call',
    a: `const http = require("http");\nhttp.request("http://example.com/p");\n`,
    description: 'net-egress via http.request — comment injection must not hide it',
  },
  {
    tag: 'dns-lookup',
    a: `const dns = require("dns");\ndns.lookup("example.com", () => {});\n`,
    description: 'dns lookup channel — comment injection must not affect dns detection',
  },
];

function inject(a: string, header: string, inline: string): string {
  const lines = a.split('\n');
  // Insert a blank line between every real statement line to expand line numbers,
  // and append `inline` to the first non-empty line.
  const out: string[] = [];
  let injected = false;
  for (const line of lines) {
    if (line.trim().length > 0 && !injected) {
      out.push(`${line}${inline}`);
      injected = true;
    } else {
      out.push(line);
    }
    // Blank line after each non-empty content line (except the last, which is empty already).
    if (line.trim().length > 0) out.push('');
  }
  return `${header}\n${out.join('\n')}`;
}

export const whitespaceComments: PairGenerator = {
  family: 'whitespace-comments',
  description:
    'Inject comments + whitespace into A to produce B. Detectors must ignore trivia.',
  generate(seed): MetamorphicPair {
    const rng = makeRng(seed);
    const c = pick(rng, CASES);
    const header = pick(rng, HEADER_COMMENTS);
    const inline = pick(rng, INLINE_COMMENTS);
    const b = inject(c.a, header, inline);
    return {
      id: `whitespace-comments-${c.tag}`,
      family: 'whitespace-comments',
      a: c.a,
      b,
      description: c.description,
    };
  },
};
