/**
 * Regression test for the pnpm parser's YAML maxDepth fail-safe wrapper.
 *
 * The js-yaml library caps nested-mapping depth at 100 with a YAMLException. Real
 * pnpm-lock.yaml files nest 3-6 levels; anything past that is a DoS-shaped input.
 * The parser must translate this (and any other js-yaml throw) into
 * UnsupportedLockfileError so callers (engine.runDiff, the assurance runner) can
 * treat it as a fail-safe give-up instead of a crash.
 *
 * Wave 4-T (2026-07-14): closes the deep-nested-yaml gap the assurance harness
 * surfaced in P1.3. The corpus README + no-crash.test.ts assertion get flipped
 * in the same commit.
 */

import { describe, it, expect } from 'vitest';
import { parsePnpmLockText } from '../src/lockfile-pnpm.js';
import { UnsupportedLockfileError } from '../src/lockfile.js';

/**
 * Build a pnpm-lock.yaml-shaped document that nests `depth` levels of `child:`
 * mappings under `packages: chalk@5.3.1: dependencies:`. depth=100 is enough
 * to trip js-yaml's built-in maxDepth guard.
 */
function buildDeepNestedYaml(depth: number): string {
  const header = `lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      chalk:
        specifier: ^5.3.0
        version: 5.3.1
packages:
  chalk@5.3.1:
    resolution: {integrity: sha512-abc==, tarball: https://registry/chalk-5.3.1.tgz}
    dependencies:
`;
  // Build nested `child:` chain. Indent grows by 2 spaces per level; start at
  // depth 6 (existing indent under `dependencies:`).
  let body = '';
  const baseIndent = 6;
  for (let i = 0; i < depth; i++) {
    body += ' '.repeat(baseIndent + i * 2) + 'child:\n';
  }
  // Terminal leaf so the YAML is well-formed.
  body += ' '.repeat(baseIndent + depth * 2) + 'leaf: value\n';
  return header + body;
}

describe('parsePnpmLockText — YAML maxDepth fail-safe (wave 4-T)', () => {
  it('throws UnsupportedLockfileError on depth=100 (js-yaml maxDepth exceeded)', () => {
    const yamlText = buildDeepNestedYaml(100);
    expect(() => parsePnpmLockText(yamlText)).toThrow(UnsupportedLockfileError);
  });

  it('the thrown error message references the maxDepth cause', () => {
    const yamlText = buildDeepNestedYaml(100);
    try {
      parsePnpmLockText(yamlText);
      // If we reach here the wrapper failed to catch the underlying throw.
      throw new Error('expected parsePnpmLockText to throw, but it succeeded');
    } catch (err) {
      expect(err).toBeInstanceOf(UnsupportedLockfileError);
      const msg = err instanceof Error ? err.message : String(err);
      // Message must be recognizable — either js-yaml's own text is included
      // (name: YAMLException, or "maxDepth") or the wrapper's own hint fires.
      expect(msg).toMatch(/maxDepth|YAMLException|not parseable/);
    }
  });

  it('does NOT leak the raw YAMLException — wrapper rewraps as UnsupportedLockfileError', () => {
    const yamlText = buildDeepNestedYaml(150);
    try {
      parsePnpmLockText(yamlText);
      throw new Error('expected parsePnpmLockText to throw, but it succeeded');
    } catch (err) {
      // The escaping error's .name must NOT be 'YAMLException' — the whole
      // point of the wrapper is to give callers the engine's convention name.
      const name = err instanceof Error ? err.name : 'unknown';
      expect(name).toBe('UnsupportedLockfileError');
    }
  });

  it('shallow depth still parses cleanly (baseline: real pnpm-lock depth)', () => {
    // Real pnpm-lock files nest 3-6 levels deep. Depth=5 must parse without
    // any error — the wrapper is a fail-safe for hostile input only.
    const yamlText = buildDeepNestedYaml(5);
    expect(() => parsePnpmLockText(yamlText)).not.toThrow();
  });
});
