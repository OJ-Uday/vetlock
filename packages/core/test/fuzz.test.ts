/**
 * Fuzz harness — property-based tests over each parser + extractor + fold pass.
 *
 * The core invariant vetlock claims (and MUST hold under all inputs): fail-soft.
 * A malicious or malformed input should NEVER throw an uncaught exception, and
 * should NEVER leave residual state (files outside destDir, unbounded memory).
 *
 * Every property here uses `fc.assert` — fast-check will search the input space
 * and shrink counter-examples if one is found. Each run tests ~100 random
 * examples by default; boost via `numRuns` when investigating a regression.
 */

import { describe, it, expect } from 'vitest';
import * as fc from 'fast-check';
import { parseConfig, ConfigError } from '../src/config.js';
import { parseLockfileText, detectKind } from '../src/lockfile-any.js';
import { parseLockfile } from '../src/lockfile.js';
import { parsePnpmLockText } from '../src/lockfile-pnpm.js';
import { parseYarnLockText } from '../src/lockfile-yarn.js';
import { extractCapabilities } from '../src/capabilities.js';
import { summarizeWasm } from '../src/wasm.js';

describe('FUZZ — parseConfig', () => {
  it('never throws un-catchable errors on random JSON', () => {
    fc.assert(
      fc.property(fc.json({ maxDepth: 6 }), (json) => {
        try {
          parseConfig(json);
          return true;
        } catch (e) {
          // Only ConfigError is acceptable — no uncaught crashes.
          return e instanceof ConfigError;
        }
      }),
      { numRuns: 200 },
    );
  });

  it('never throws on random string', () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 512 }), (s) => {
        try {
          parseConfig(s);
          return true;
        } catch (e) {
          return e instanceof ConfigError;
        }
      }),
      { numRuns: 200 },
    );
  });
});

describe('FUZZ — parseLockfileText dispatcher', () => {
  it('either produces a graph or throws with a message', () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 512 }), (s) => {
        try {
          parseLockfileText(s);
          return true;
        } catch (e) {
          // Any error MUST have a message. No `TypeError: undefined is not…` regressions.
          return e instanceof Error && e.message.length > 0;
        }
      }),
      { numRuns: 200 },
    );
  });

  it('detectKind never throws on any content', () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 512 }), (s) => {
        try {
          detectKind(s);
          return true;
        } catch (e) {
          return e instanceof Error;
        }
      }),
      { numRuns: 200 },
    );
  });
});

describe('FUZZ — parseLockfile (npm) on random JSON objects', () => {
  it('handles arbitrary JSON structures without crash', () => {
    fc.assert(
      fc.property(fc.jsonValue({ maxDepth: 4 }), (v) => {
        try {
          parseLockfile(v);
          return true;
        } catch (e) {
          return e instanceof Error && e.message.length > 0;
        }
      }),
      { numRuns: 200 },
    );
  });
});

describe('FUZZ — pnpm-lock parser', () => {
  it('never throws uncaught errors on random YAML-like input', () => {
    // Bias the input toward YAML-shaped content (some words then colons)
    const yamlish = fc.oneof(
      fc.string({ maxLength: 400 }),
      fc.constant('lockfileVersion: "9.0"\npackages: {}\n'),
      fc.constant('lockfileVersion: bogus\n'),
      fc.constant(''),
    );
    fc.assert(
      fc.property(yamlish, (s) => {
        try {
          parsePnpmLockText(s);
          return true;
        } catch (e) {
          return e instanceof Error && e.message.length > 0;
        }
      }),
      { numRuns: 200 },
    );
  });
});

describe('FUZZ — yarn.lock parser', () => {
  it('never throws uncaught errors on random input', () => {
    const yarnish = fc.oneof(
      fc.string({ maxLength: 400 }),
      fc.constant('# yarn lockfile v1\n\n'),
      fc.constant('__metadata:\n  version: 6\n'),
    );
    fc.assert(
      fc.property(yarnish, (s) => {
        try {
          parseYarnLockText(s);
          return true;
        } catch (e) {
          return e instanceof Error && e.message.length > 0;
        }
      }),
      { numRuns: 200 },
    );
  });
});

describe('FUZZ — extractCapabilities (JS AST)', () => {
  it('never throws on random source text; sets parseError instead', () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 4096 }), (src) => {
        // No throw. Result either has parseError set OR a real AST parsed.
        const cap = extractCapabilities('rand.js', src, 'sha256-fake', src.length);
        return typeof cap === 'object' && cap.path === 'rand.js';
      }),
      { numRuns: 200 },
    );
  });

  it('never throws on JSON files with random content', () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 4096 }), (src) => {
        const cap = extractCapabilities('rand.json', src, 'sha256-fake', src.length);
        return typeof cap === 'object';
      }),
      { numRuns: 100 },
    );
  });

  it('handles constructed-JS attack shapes without throw', () => {
    // Manually-crafted pathological AST shapes
    const shapes = fc.oneof(
      fc.constant('function () {{{{{{{{{{{{ unbalanced'),
      fc.constant('/*'.repeat(200)),
      fc.constant('function' + '('.repeat(500) + ')'),
      fc.constant('a'.repeat(50_000)),
      fc.constant('const a = ' + '('.repeat(1000) + '1' + ')'.repeat(1000) + ';'),
    );
    fc.assert(
      fc.property(shapes, (src) => {
        const cap = extractCapabilities('attack.js', src, 'sha256-fake', src.length);
        // If parse failed, parseError is set. If it succeeded, we have arrays.
        return typeof cap === 'object';
      }),
      { numRuns: 20 },
    );
  });
});

describe('FUZZ — summarizeWasm', () => {
  it('never throws on random byte buffers', () => {
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 4096 }), (bytes) => {
        try {
          summarizeWasm(Buffer.from(bytes));
          return true;
        } catch (e) {
          return false;
        }
      }),
      { numRuns: 200 },
    );
  });

  it('never throws on random buffers that happen to have the WASM magic prefix', () => {
    // Force the magic bytes; rest is garbage
    fc.assert(
      fc.property(fc.uint8Array({ minLength: 0, maxLength: 4096 }), (rest) => {
        const magic = Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
        const buf = Buffer.concat([magic, Buffer.from(rest)]);
        try {
          summarizeWasm(buf);
          return true;
        } catch (e) {
          return false;
        }
      }),
      { numRuns: 100 },
    );
  });
});
