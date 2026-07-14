/**
 * deep-nested-yaml — pnpm-lock.yaml with pathologically deep nesting.
 *
 * Real pnpm-lock.yaml files nest 3-6 levels: root → packages → <spec> → dependencies →
 * <name> → …. This generator emits YAML with configurable nesting depth. `js-yaml` (the
 * parser pnpm-lock uses) is implemented iteratively but many downstream consumers of the
 * parsed tree recurse — including any code that walks the graph structure.
 *
 * The generator produces a document that IS syntactically valid YAML. The question is
 * whether the engine's downstream traversal (walk-the-graph patterns) survives.
 *
 * Deterministic. Same seed + depth → identical bytes.
 */

import type { RobustnessGenerator, LockfileInput } from './types.js';

export interface DeepNestedYamlParams {
  /** Nesting depth. Practical caps: 100 (baseline), 1_000 (stress), 10_000 (DoS). */
  readonly depth: number;
}

const HEADER = `lockfileVersion: '6.0'\nsettings:\n  autoInstallPeers: true\n`;

function buildNested(depth: number): string {
  // Build the nested structure iteratively (we can't recurse to 10k in JS). Each level
  // introduces two spaces of indent and a "child:" key.
  const lines: string[] = ['root:'];
  for (let d = 0; d < depth; d++) {
    lines.push(`${'  '.repeat(d + 1)}child:`);
  }
  // Terminal leaf so the last "child:" has a value.
  lines.push(`${'  '.repeat(depth + 1)}leaf: 'yes'`);
  return lines.join('\n');
}

export const deepNestedYaml: RobustnessGenerator<DeepNestedYamlParams> = {
  id: 'deep-nested-yaml',
  description:
    'pnpm-lock.yaml-shaped YAML with N levels of `child:` nesting. Exercises js-yaml + downstream graph walkers.',
  format: 'pnpm',
  generate(seed, params): LockfileInput {
    // Seed is currently unused (the input shape is fully determined by depth), but the
    // signature is stable — future variants (e.g. randomizing key names to avoid caching)
    // will use it.
    void seed;
    const depth = params?.depth ?? 100;
    if (!Number.isInteger(depth) || depth < 0 || depth > 100_000) {
      throw new Error(`deep-nested-yaml: depth must be a non-negative integer ≤ 100000; got ${depth}`);
    }
    const body = buildNested(depth);
    return {
      text: `${HEADER}${body}\n`,
      filename: 'pnpm-lock.yaml',
      format: 'pnpm',
    };
  },
};
