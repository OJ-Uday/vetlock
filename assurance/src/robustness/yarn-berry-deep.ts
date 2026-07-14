/**
 * yarn-berry-deep — yarn.lock v2+ (berry, syml format) with pathological shapes.
 *
 * Berry lockfiles are YAML-ish (syml — Yarn's variant) parsed via @yarnpkg/parsers'
 * `parseSyml`. The engine's parseYarnLockText detects berry via `/^\s*__metadata:/m`
 * and dispatches to parseBerryLockText. Three shapes:
 *
 *   deep-nesting     — a single package entry whose `dependencies:` map nests N
 *                      levels deep (child -> child -> ...). Stresses the syml parser's
 *                      internal recursion depth and any downstream tree walker.
 *   wide-deps        — one package with N entries in its dependencies map on one line
 *                      (flat, wide). Stresses map allocation + graph second-pass.
 *   escaped-strings  — package specs with many backslash escape sequences in the key
 *                      and resolution URL. Stresses the syml tokenizer's escape
 *                      handling.
 *
 * The `__metadata:` header is MANDATORY — without it the dispatcher routes to
 * classic and the wrong parser gets exercised.
 *
 * Deterministic. Same (seed, params) → identical bytes.
 */

import type { RobustnessGenerator, LockfileInput } from './types.js';

export interface YarnBerryDeepParams {
  /** Which pathological shape to emit. */
  readonly mode: 'deep-nesting' | 'wide-deps' | 'escaped-strings';
  /** Shape-specific magnitude. Baseline 10 (safe), stress 100/1000+ pins current behavior. */
  readonly scale: number;
}

// Berry v6 header — `__metadata:` tells the dispatcher this is berry, not classic.
// `cacheKey: 8` matches what recent yarn versions emit so this looks like real output.
const HEADER = `__metadata:
  version: 6
  cacheKey: 8

`;

const FAKE_INTEGRITY = `sha512-${'a'.repeat(88)}`;

function pkgName(i: number): string {
  return `pkg${i}`;
}

/**
 * deep-nesting: emit one package entry whose dependency structure spirals inward.
 * Berry doesn't natively support "dependencies of dependencies inline" — the syml
 * format is flat like classic — so we produce an unusual but valid-looking structure
 * that abuses arbitrary nested keys under a `dependenciesMeta` block. The syml
 * parser must still walk the tree; that's what we're stressing.
 */
function buildDeepNesting(depth: number): string {
  const lines: string[] = ['"pkg0@npm:1.0.0":', '  version: 1.0.0'];
  lines.push(`  resolution: "pkg0@npm:1.0.0"`);
  lines.push(`  checksum: ${FAKE_INTEGRITY}`);
  lines.push(`  languageName: node`);
  lines.push(`  linkType: hard`);
  lines.push(`  dependenciesMeta:`);
  // Build "  " * (2 + d) indentation nesting `k0:\n    k1:\n      ...`
  for (let d = 0; d < depth; d++) {
    const indent = '  '.repeat(d + 2);
    lines.push(`${indent}k${d}:`);
  }
  const leafIndent = '  '.repeat(depth + 2);
  lines.push(`${leafIndent}optional: false`);
  return lines.join('\n');
}

/**
 * wide-deps: one package with N dependency entries. Each entry is a valid npm-style
 * spec so parseSyml keeps a large map alive; the second pass through the graph
 * builder must dereference every one.
 */
function buildWideDeps(count: number): string {
  const lines: string[] = ['"pkg0@npm:1.0.0":', '  version: 1.0.0'];
  lines.push(`  resolution: "pkg0@npm:1.0.0"`);
  lines.push(`  checksum: ${FAKE_INTEGRITY}`);
  lines.push(`  languageName: node`);
  lines.push(`  linkType: hard`);
  lines.push(`  dependencies:`);
  for (let i = 0; i < count; i++) {
    lines.push(`    ${pkgName(i)}: "npm:^1.0.0"`);
  }
  return lines.join('\n');
}

/**
 * escaped-strings: emit N package entries with many backslash escape sequences in
 * quoted keys and resolution URLs. Real berry lockfiles quote strings that contain
 * special chars; we stack `\\\\\\\\...` sequences to make the tokenizer burn cycles
 * processing escapes.
 */
function buildEscapedStrings(count: number): string {
  const parts: string[] = [];
  // Each part is a small entry with escaped strings; count total entries.
  // The escape burden lives in a stacked backslash sequence inside the resolution.
  const escBurden = '\\\\'.repeat(64); // 64 backslash pairs per entry
  for (let i = 0; i < count; i++) {
    const name = pkgName(i);
    parts.push(
      `"${name}@npm:1.0.0":\n` +
        `  version: 1.0.0\n` +
        `  resolution: "${name}@npm:1.0.0::__archiveUrl=https%3A%2F%2Fregistry.npmjs.org${escBurden}%2F${name}"\n` +
        `  checksum: ${FAKE_INTEGRITY}\n` +
        `  languageName: node\n` +
        `  linkType: hard`,
    );
  }
  return parts.join('\n\n');
}

export const yarnBerryDeep: RobustnessGenerator<YarnBerryDeepParams> = {
  id: 'yarn-berry-deep',
  description:
    'yarn.lock berry (syml) with pathological deep-nesting / wide-deps / escaped-strings shapes.',
  format: 'yarn-berry',
  generate(seed, params): LockfileInput {
    void seed;
    if (!params) throw new Error('yarn-berry-deep: params required');
    const { mode, scale } = params;
    if (!Number.isInteger(scale) || scale < 0 || scale > 100_000) {
      throw new Error(
        `yarn-berry-deep: scale must be a non-negative integer <= 100000; got ${scale}`,
      );
    }
    let body: string;
    switch (mode) {
      case 'deep-nesting':
        body = buildDeepNesting(scale);
        break;
      case 'wide-deps':
        body = buildWideDeps(scale);
        break;
      case 'escaped-strings':
        body = buildEscapedStrings(scale);
        break;
      default: {
        const _exhaustive: never = mode;
        throw new Error(`yarn-berry-deep: unknown mode ${String(_exhaustive)}`);
      }
    }
    return {
      text: `${HEADER}${body}\n`,
      filename: 'yarn.lock',
      format: 'yarn-berry',
    };
  },
};
