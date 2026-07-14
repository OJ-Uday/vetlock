/**
 * member-access-form — `obj.foo` vs `obj["foo"]` (identical semantics, different AST).
 *
 * In JS, `child_process.exec` and `child_process["exec"]` bind to the exact same
 * function. A static analyzer that walks MemberExpressions must handle both:
 *   • `.foo` — MemberExpression with `computed: false`, `property: Identifier("foo")`.
 *   • `["foo"]` — MemberExpression with `computed: true`, `property: StringLiteral("foo")`.
 *
 * Any detector that only checks the non-computed shape will silently miss the second
 * form. This is one of the classic evasion primitives (mentioned in the packet's
 * evasion mutation family). The metamorphic pair here is the identity check: the
 * detector must produce the SAME capability finding on both, or the map has a gap.
 *
 * Target edge case: MemberExpression walkers that only match `property.name` and
 * skip `computed && StringLiteral` — the analyzer must normalize both forms.
 */

import type { PairGenerator, MetamorphicPair } from './types.js';
import { makeRng, pick } from './prng.js';

interface Case {
  readonly tag: string;
  /** The base expression producing the object (e.g. `require("child_process")`). */
  readonly base: string;
  /** The member name (used as both `.name` and `["name"]`). */
  readonly member: string;
  /** Suffix — everything after the member access. Usually a call. */
  readonly suffix: string;
  readonly description: string;
}

const CASES: readonly Case[] = [
  {
    tag: 'child-process-exec',
    base: `require("child_process")`,
    member: 'exec',
    suffix: `("echo defanged")`,
    description:
      'child_process.exec vs child_process["exec"] — capability class must be identical',
  },
  {
    tag: 'child-process-spawn',
    base: `require("child_process")`,
    member: 'spawn',
    suffix: `("echo", [])`,
    description:
      'child_process.spawn vs computed form — capability class must be identical',
  },
  {
    tag: 'fs-writeFileSync',
    base: `require("fs")`,
    member: 'writeFileSync',
    suffix: `("/tmp/x", "hi")`,
    description:
      'fs.writeFileSync vs computed form — fs-write must be caught in both',
  },
  {
    tag: 'process-env-token',
    base: `process.env`,
    member: 'NPM_TOKEN',
    suffix: ``,
    description:
      'process.env.NPM_TOKEN vs process.env["NPM_TOKEN"] — env-read must be caught in both',
  },
  {
    tag: 'http-request',
    base: `require("http")`,
    member: 'request',
    suffix: `("http://example.com/p")`,
    description:
      'http.request vs http["request"] — net-egress must be caught in both',
  },
  {
    tag: 'vm-run',
    base: `require("vm")`,
    member: 'runInThisContext',
    suffix: `("1+1")`,
    description:
      'vm.runInThisContext vs computed form — code-execution must be caught in both',
  },
];

export const memberAccessForm: PairGenerator = {
  family: 'member-access-form',
  description:
    'Dot vs computed member access. AST differs; capability class must not.',
  generate(seed): MetamorphicPair {
    const rng = makeRng(seed);
    const c = pick(rng, CASES);
    // Program A: dot form. Program B: computed form.
    const a = `${c.base}.${c.member}${c.suffix};\n`;
    const b = `${c.base}[${JSON.stringify(c.member)}]${c.suffix};\n`;
    return {
      id: `member-access-form-${c.tag}`,
      family: 'member-access-form',
      a,
      b,
      description: c.description,
    };
  },
};
