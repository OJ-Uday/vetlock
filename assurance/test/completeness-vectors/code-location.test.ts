/**
 * code-location — completeness-vector transform self-tests.
 *
 * These transforms don't produce standalone JavaScript files — they produce
 * WRAPPED payloads (a package.json fragment or a multi-file marker + source).
 * The contract we can enforce statically:
 *
 *   • PURITY / DETERMINISM — `transform(src, seed) === transform(src, seed)` byte-identical.
 *   • NON-TRIVIALITY       — output is DIFFERENT from input (a wrapper was applied).
 *   • WRAPPER SHAPE        — output has the specific shape the transform advertises:
 *       - intoLifecycleScript → valid JSON with `scripts.postinstall` populated.
 *       - intoNestedFile      → starts with the `// FILE: <path>` marker and the
 *         payload appears verbatim after the marker.
 *   • SEMANTIC PRESERVATION — the payload appears (properly escaped or unchanged)
 *     inside the wrapper; no character is lost or corrupted.
 */

import { describe, it, expect } from 'vitest';
import {
  intoLifecycleScript,
  intoNestedFile,
  NESTED_FILE_MARKER_PREFIX,
} from '../../src/completeness-vectors/index.js';

const SEEDS: readonly number[] = [0, 1, 7, 42, 1337, 2_147_483_647];

const PAYLOAD = 'require("child_process").exec("echo hi");';

describe('completeness-vectors — code-location', () => {
  describe('intoLifecycleScript', () => {
    it('declares the code-location family and metadata fields', () => {
      expect(intoLifecycleScript.family).toBe('code-location');
      expect(intoLifecycleScript.targetClass.length).toBeGreaterThan(0);
      expect(intoLifecycleScript.id.length).toBeGreaterThan(0);
      expect(intoLifecycleScript.description.length).toBeGreaterThan(0);
    });

    it('is pure/deterministic: same (source, seed) → byte-identical output', () => {
      for (const seed of SEEDS) {
        const a = intoLifecycleScript.transform(PAYLOAD, seed);
        const b = intoLifecycleScript.transform(PAYLOAD, seed);
        expect(b).toBe(a);
      }
    });

    it('is non-trivial: output DIFFERS from input', () => {
      for (const seed of SEEDS) {
        const out = intoLifecycleScript.transform(PAYLOAD, seed);
        expect(out).not.toBe(PAYLOAD);
      }
    });

    it('output is valid JSON with a populated scripts.postinstall field', () => {
      for (const seed of SEEDS) {
        const out = intoLifecycleScript.transform(PAYLOAD, seed);
        const parsed = JSON.parse(out) as { scripts?: { postinstall?: string } };
        expect(parsed.scripts).toBeDefined();
        expect(typeof parsed.scripts?.postinstall).toBe('string');
        expect(parsed.scripts?.postinstall?.length ?? 0).toBeGreaterThan(0);
      }
    });

    it('the postinstall body is `node -e <json-escaped source>` and round-trips to the payload', () => {
      const out = intoLifecycleScript.transform(PAYLOAD, 0);
      const parsed = JSON.parse(out) as { scripts: { postinstall: string } };
      const post = parsed.scripts.postinstall;
      expect(post.startsWith('node -e ')).toBe(true);
      // The tail is the JSON.stringify of the payload — parsing it back must
      // yield the exact payload string. This is the semantic-preservation check.
      const jsonTail = post.slice('node -e '.length);
      const roundTripped = JSON.parse(jsonTail) as unknown;
      expect(roundTripped).toBe(PAYLOAD);
    });
  });

  describe('intoNestedFile', () => {
    it('declares the code-location family and metadata fields', () => {
      expect(intoNestedFile.family).toBe('code-location');
      expect(intoNestedFile.targetClass.length).toBeGreaterThan(0);
      expect(intoNestedFile.id.length).toBeGreaterThan(0);
      expect(intoNestedFile.description.length).toBeGreaterThan(0);
    });

    it('is pure/deterministic: same (source, seed) → byte-identical output', () => {
      for (const seed of SEEDS) {
        const a = intoNestedFile.transform(PAYLOAD, seed);
        const b = intoNestedFile.transform(PAYLOAD, seed);
        expect(b).toBe(a);
      }
    });

    it('is non-trivial: output DIFFERS from input', () => {
      for (const seed of SEEDS) {
        const out = intoNestedFile.transform(PAYLOAD, seed);
        expect(out).not.toBe(PAYLOAD);
      }
    });

    it('output starts with the FILE marker naming lib/util.js', () => {
      for (const seed of SEEDS) {
        const out = intoNestedFile.transform(PAYLOAD, seed);
        expect(out.startsWith(`${NESTED_FILE_MARKER_PREFIX}lib/util.js\n`)).toBe(true);
      }
    });

    it('the payload appears verbatim after the marker (semantic-preservation)', () => {
      const out = intoNestedFile.transform(PAYLOAD, 0);
      const markerLine = `${NESTED_FILE_MARKER_PREFIX}lib/util.js\n`;
      const body = out.slice(markerLine.length);
      // Trailing newline is enforced by the transform to keep marker parsing simple;
      // strip it before comparing.
      const bodyTrimmed = body.endsWith('\n') ? body.slice(0, -1) : body;
      expect(bodyTrimmed).toBe(PAYLOAD);
    });

    it('preserves an existing trailing newline in the payload (no double-nl)', () => {
      const payloadWithNl = `${PAYLOAD}\n`;
      const out = intoNestedFile.transform(payloadWithNl, 0);
      // The output should not contain a double newline before EOF.
      expect(out.endsWith('\n\n')).toBe(false);
      expect(out.endsWith('\n')).toBe(true);
    });
  });
});
