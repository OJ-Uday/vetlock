/**
 * clipboard-normalization — completeness-vector transform self-tests.
 *
 * Contract every transform satisfies:
 *   • PURITY / DETERMINISM — `transform(src, seed) === transform(src, seed)` byte-identical.
 *   • NON-TRIVIALITY       — when the target pattern is present in `src`, `transform !== src`.
 *   • SEMANTIC PRESERVATION MARKER — the output references the sibling utility name.
 *
 * Defang note: all fixture inputs use `echo <marker>` as the pipeline data source,
 * which is on the defang guard's allow-list. The transform preserves shape, so
 * outputs stay defang-clean.
 */

import { describe, it, expect } from 'vitest';
import { execClipboardCall } from '../../src/completeness-vectors/clipboard-normalization.js';

const SEEDS: readonly number[] = [0, 1, 7, 42, 1337, 2_147_483_647];

/** A defanged shell pipeline that pipes an echo marker to pbcopy. */
const SOURCE_WITH_PBCOPY = "const cmd = 'echo defanged-clip-marker | pbcopy';";

/** A defanged shell pipeline using xclip — used to prove the transform flips the
 *  OTHER direction too. */
const SOURCE_WITH_XCLIP = "const cmd = 'echo defanged-clip-marker | xclip -selection clipboard';";

/** Source with no clipboard utility — every transform should be a no-op. */
const SOURCE_NO_CLIP = "const cmd = 'echo just-a-marker';";

describe('completeness-vectors — clipboard-normalization', () => {
  it('declares the clipboard targetClass and required metadata fields', () => {
    expect(execClipboardCall.targetClass).toBe('clipboard');
    expect(execClipboardCall.id.length).toBeGreaterThan(0);
    expect(execClipboardCall.family.length).toBeGreaterThan(0);
    expect(execClipboardCall.description.length).toBeGreaterThan(0);
  });

  it('is pure/deterministic: same (source, seed) → byte-identical output', () => {
    for (const seed of SEEDS) {
      const a = execClipboardCall.transform(SOURCE_WITH_PBCOPY, seed);
      const b = execClipboardCall.transform(SOURCE_WITH_PBCOPY, seed);
      expect(b).toBe(a);
    }
  });

  it('is non-trivial: output DIFFERS from input when pbcopy is present', () => {
    for (const seed of SEEDS) {
      const out = execClipboardCall.transform(SOURCE_WITH_PBCOPY, seed);
      expect(out).not.toBe(SOURCE_WITH_PBCOPY);
    }
  });

  it('output contains the xclip sibling utility (semantic-preservation)', () => {
    for (const seed of SEEDS) {
      const out = execClipboardCall.transform(SOURCE_WITH_PBCOPY, seed);
      expect(out).toContain('xclip');
    }
  });

  it('preserves the echo pipeline body (defang-clean)', () => {
    for (const seed of SEEDS) {
      const out = execClipboardCall.transform(SOURCE_WITH_PBCOPY, seed);
      // The `echo <marker>` prefix must survive verbatim — the transform only
      // touches the trailing utility, not the pipeline data source.
      expect(out).toContain('echo defanged-clip-marker |');
    }
  });

  it('the original pbcopy utility is no longer present verbatim after transform', () => {
    for (const seed of SEEDS) {
      const out = execClipboardCall.transform(SOURCE_WITH_PBCOPY, seed);
      // No literal "| pbcopy" chunk should remain.
      expect(out).not.toMatch(/\|\s*pbcopy\b/);
    }
  });

  it('also flips the reverse direction: xclip → pbcopy', () => {
    const out = execClipboardCall.transform(SOURCE_WITH_XCLIP, 0);
    expect(out).not.toBe(SOURCE_WITH_XCLIP);
    expect(out).toContain('pbcopy');
    expect(out).not.toContain('xclip');
  });

  it('is a no-op on source with no clipboard pipeline', () => {
    for (const seed of SEEDS) {
      const out = execClipboardCall.transform(SOURCE_NO_CLIP, seed);
      expect(out).toBe(SOURCE_NO_CLIP);
    }
  });
});
