/**
 * persistence-relocation — completeness-vector transform self-tests.
 *
 * Contract every transform satisfies:
 *   • PURITY / DETERMINISM — `transform(src, seed) === transform(src, seed)` byte-identical.
 *   • NON-TRIVIALITY       — when the target pattern is present in `src`, `transform !== src`.
 *   • SYNTACTIC VALIDITY   — output parses as valid JSON.
 *   • SEMANTIC PRESERVATION MARKER — the payload string appears verbatim in the new key.
 */

import { describe, it, expect } from 'vitest';
import { preinstallToPostinstall } from '../../src/completeness-vectors/persistence-relocation.js';

const SEEDS: readonly number[] = [0, 1, 7, 42, 1337, 2_147_483_647];

/** A package.json with a `scripts.preinstall` we can relocate. Defang-clean:
 *  `echo` is on the guard's allow-list. */
const PKG_WITH_PREINSTALL = JSON.stringify(
  {
    name: 'defanged-fixture',
    version: '0.0.0',
    scripts: {
      preinstall: 'echo relocated',
    },
  },
  null,
  2,
);

/** A package.json with a `scripts.postinstall` — used to prove the transform
 *  flips the OTHER direction too. */
const PKG_WITH_POSTINSTALL = JSON.stringify(
  {
    name: 'defanged-fixture',
    version: '0.0.0',
    scripts: {
      postinstall: 'echo relocated',
    },
  },
  null,
  2,
);

/** A package.json with neither hook. The transform must no-op. */
const PKG_WITH_NEITHER = JSON.stringify(
  {
    name: 'defanged-fixture',
    version: '0.0.0',
    scripts: {
      build: 'echo build',
    },
  },
  null,
  2,
);

describe('completeness-vectors — persistence-relocation', () => {
  it('declares the persistence targetClass and the required metadata fields', () => {
    expect(preinstallToPostinstall.targetClass).toBe('persistence');
    expect(preinstallToPostinstall.id.length).toBeGreaterThan(0);
    expect(preinstallToPostinstall.family.length).toBeGreaterThan(0);
    expect(preinstallToPostinstall.description.length).toBeGreaterThan(0);
  });

  it('is pure/deterministic: same (source, seed) → byte-identical output', () => {
    for (const seed of SEEDS) {
      const a = preinstallToPostinstall.transform(PKG_WITH_PREINSTALL, seed);
      const b = preinstallToPostinstall.transform(PKG_WITH_PREINSTALL, seed);
      expect(b).toBe(a);
    }
  });

  it('is non-trivial: output DIFFERS from input when preinstall is present', () => {
    for (const seed of SEEDS) {
      const out = preinstallToPostinstall.transform(PKG_WITH_PREINSTALL, seed);
      expect(out).not.toBe(PKG_WITH_PREINSTALL);
    }
  });

  it('produces syntactically valid JSON output', () => {
    for (const seed of SEEDS) {
      const out = preinstallToPostinstall.transform(PKG_WITH_PREINSTALL, seed);
      expect(() => JSON.parse(out)).not.toThrow();
    }
  });

  it('relocates the hook body from preinstall to postinstall (semantic-preservation)', () => {
    const out = preinstallToPostinstall.transform(PKG_WITH_PREINSTALL, 0);
    const parsed = JSON.parse(out) as {
      scripts?: { preinstall?: string; postinstall?: string };
    };
    // The original preinstall key must be gone.
    expect(parsed.scripts?.preinstall).toBeUndefined();
    // The postinstall key must contain the ORIGINAL body verbatim.
    expect(parsed.scripts?.postinstall).toBe('echo relocated');
  });

  it('also flips the reverse direction: postinstall → preinstall', () => {
    // If only postinstall is present, the transform flips to preinstall so the
    // transform is still non-trivial on that shape.
    const out = preinstallToPostinstall.transform(PKG_WITH_POSTINSTALL, 0);
    expect(out).not.toBe(PKG_WITH_POSTINSTALL);
    const parsed = JSON.parse(out) as {
      scripts?: { preinstall?: string; postinstall?: string };
    };
    expect(parsed.scripts?.postinstall).toBeUndefined();
    expect(parsed.scripts?.preinstall).toBe('echo relocated');
  });

  it('is a no-op on a package.json with neither preinstall nor postinstall', () => {
    for (const seed of SEEDS) {
      const out = preinstallToPostinstall.transform(PKG_WITH_NEITHER, seed);
      expect(out).toBe(PKG_WITH_NEITHER);
    }
  });

  it('is a no-op on non-JSON input', () => {
    const notJson = 'const x = 1;\nconsole.log(x);\n';
    for (const seed of SEEDS) {
      const out = preinstallToPostinstall.transform(notJson, seed);
      expect(out).toBe(notJson);
    }
  });
});
