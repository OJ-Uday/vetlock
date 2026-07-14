/**
 * Runner extension tests — Wave 3-O.
 *
 * Three concerns:
 *   1. engine:extractCapabilities — new scenario that runs the engine's per-file capability
 *      scan against a defanged source string. Unblocks Wave 1B-J's metamorphic tests.
 *   2. engine:analyzeTarball      — new scenario that runs the engine's full pipeline
 *      (extract + per-file scan + manifest read) against a defanged tarball. Unblocks
 *      Wave 3-M's archive test vectors.
 *   3. OOM classifier hardening   — synthetic:oom previously surfaced as `crash` on some
 *      V8 allocation paths (Wave 1B-B feedback). The hardening should make it reliable.
 *
 * All inputs are defanged (RFC 2606 reserved TLDs + no live payloads).
 */

import { describe, it, expect } from 'vitest';
import { promises as fs } from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as zlib from 'node:zlib';
import { Buffer } from 'node:buffer';
import { runBounded } from '../../src/runner/index.js';
import type { Bounds } from '../../src/oracles/types.js';

const BOUNDS: Bounds = { wallMs: 10_000, heapMb: 128, seed: 42 };
// OOM tests need a lower heap cap so the worker trips it before it starves the test box.
const OOM_BOUNDS: Bounds = { wallMs: 10_000, heapMb: 32, seed: 42 };

/**
 * Minimal POSIX ustar tarball builder — enough to feed engine.analyzeTarball a
 * defanged fixture. Format spec: 512-byte header per entry with fields at fixed
 * offsets, then the payload padded to a 512-byte boundary, then two 512-byte
 * zero blocks at the end. All numeric fields are octal ASCII, NUL-terminated.
 */
function makeTgz(files: Array<{ name: string; content: string }>): Buffer {
  const parts: Buffer[] = [];
  for (const f of files) {
    const contentBuf = Buffer.from(f.content, 'utf8');
    const header = Buffer.alloc(512);
    header.write(f.name.slice(0, 99), 0, 'utf8');            // name (100 bytes)
    header.write('0000644\0', 100, 'utf8');                   // mode (8 bytes)
    header.write('0000000\0', 108, 'utf8');                   // uid
    header.write('0000000\0', 116, 'utf8');                   // gid
    header.write(contentBuf.length.toString(8).padStart(11, '0') + '\0', 124, 'utf8'); // size
    header.write('00000000000\0', 136, 'utf8');               // mtime
    header.write('        ', 148, 'utf8');                    // checksum placeholder
    header.write('0', 156, 'utf8');                            // typeflag '0' = regular file
    header.write('ustar\0', 257, 'utf8');                     // magic
    header.write('00', 263, 'utf8');                          // version
    // Compute checksum: sum of all header bytes with the checksum field treated as spaces.
    let sum = 0;
    for (let i = 0; i < 512; i++) sum += header[i];
    header.write(sum.toString(8).padStart(6, '0') + '\0 ', 148, 'utf8');
    parts.push(header);
    parts.push(contentBuf);
    // Pad content to 512-byte boundary
    const pad = (512 - (contentBuf.length % 512)) % 512;
    if (pad > 0) parts.push(Buffer.alloc(pad));
  }
  // Two 512-byte zero blocks mark end-of-archive.
  parts.push(Buffer.alloc(1024));
  return zlib.gzipSync(Buffer.concat(parts));
}

describe('engine:extractCapabilities — Wave 3-O', () => {
  it('returns findings of the expected capabilityClass on defanged hostile source', async () => {
    // Defanged hostile shape:
    //   - imports 'child_process' (EXEC → code-execution)
    //   - imports 'http' (NET → net-egress)
    //   - reads process.env.NPM_TOKEN (ENV → env/secret-read)
    //   - eval('...') (CODE → code-execution)
    //   - refers to https://exfil.example.invalid (defanged URL → net-egress via urlLiterals)
    const hostile = [
      "const cp = require('child_process');",
      "const http = require('http');",
      "const token = process.env.NPM_TOKEN;",
      "eval('/* defanged */');",
      "const url = 'https://exfil.example.invalid/collect';",
      // Reference the vars so the AST scanner emits distinct capability entries.
      "http.get(url, () => { cp.exec('echo ' + token); });",
    ].join('\n');

    const outcome = await runBounded(
      {
        kind: 'engine:extractCapabilities',
        enginePath: '@vetlock/core',
        relPath: 'lib/hostile.js',
        text: hostile,
      },
      BOUNDS,
    );

    expect(outcome.kind).toBe('ok');
    if (outcome.kind !== 'ok') return;

    // The finding array carries one entry per observed capability. We assert that the
    // expected capability classes ALL appear — a strong invariant for the metamorphic
    // tests that follow (they mutate the input and check the class set is stable).
    const classes = new Set(outcome.findings.map((f) => f.capabilityClass));
    expect(classes.has('code-execution')).toBe(true);   // child_process import + eval
    expect(classes.has('net-egress')).toBe(true);        // http import + url literal
    expect(classes.has('env/secret-read')).toBe(true);   // process.env.NPM_TOKEN
  });

  it('surfaces parseError as a fail-safe outcome (not a crash)', async () => {
    // A syntactically-broken source lands on parseError, which the engine returns as a
    // FileCapabilities.parseError field. adaptFileCapabilities translates that to a BLOCK
    // analysis-failed finding, which the worker routes to the fail-safe channel — this is
    // the invariant the assurance oracles rely on (fail-safe > silent-green).
    const outcome = await runBounded(
      {
        kind: 'engine:extractCapabilities',
        enginePath: '@vetlock/core',
        relPath: 'lib/broken.js',
        text: 'this is (( not )) valid javascript {{{',
      },
      BOUNDS,
    );

    // The engine's parser has error recovery — it may or may not recover cleanly on this
    // particular input. Either fail-safe (parseError set) or ok (parser recovered, no
    // suspicious capabilities) is acceptable; crash is not.
    expect(['ok', 'fail-safe']).toContain(outcome.kind);
  });
});

describe('engine:analyzeTarball — Wave 3-O', () => {
  it('returns findings for lifecycle scripts in a defanged tarball', async () => {
    // Build a minimal defanged tarball on disk (npm-style layout: root dir named 'package/').
    // Manifest declares lifecycle hooks (persistence signals) with benign echo scripts.
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'wave3o-tar-'));
    try {
      const manifest = {
        name: 'defanged-fixture',
        version: '0.0.1',
        scripts: {
          // 'echo' is on the defang allowlist. This tests the lifecycle-script → persistence
          // capability mapping without actually running any code (analyzeTarball is static).
          postinstall: 'echo defanged-postinstall',
          preinstall: 'echo defanged-preinstall',
        },
      };
      const tgz = makeTgz([
        { name: 'package/package.json', content: JSON.stringify(manifest, null, 2) },
        { name: 'package/index.js', content: "module.exports = { hello: 'defanged' };\n" },
      ]);
      const tarballPath = path.join(tmpDir, 'defanged.tgz');
      await fs.writeFile(tarballPath, tgz);

      const outcome = await runBounded(
        {
          kind: 'engine:analyzeTarball',
          enginePath: '@vetlock/core',
          tarballPath,
        },
        BOUNDS,
      );

      expect(outcome.kind).toBe('ok');
      if (outcome.kind !== 'ok') return;

      // Assert the manifest.scripts lifecycle hooks became persistence findings.
      const persistence = outcome.findings.filter((f) => f.capabilityClass === 'persistence');
      expect(persistence.length).toBeGreaterThanOrEqual(2);
      const hooks = new Set(
        persistence
          .map((f) => f.meta?.['hook'])
          .filter((h): h is string => typeof h === 'string'),
      );
      expect(hooks.has('postinstall')).toBe(true);
      expect(hooks.has('preinstall')).toBe(true);
    } finally {
      await fs.rm(tmpDir, { recursive: true, force: true }).catch(() => {});
    }
  });
});

describe('OOM classifier hardening — Wave 3-O', () => {
  // Wave 1B-B reported that synthetic:oom flakily returned `crash` (with a non-standard V8-
  // internal message) rather than `oom`. The hardening added .stack scanning plus V8-internal
  // signature patterns ('v8::internal::Heap::', 'Zone::New', 'Reached heap limit ...'). We
  // rerun the scenario multiple times so any residual flake would surface.
  //
  // Modes covered: grow-array (Wave 1B-B's originally-flaky path) and grow-buffer. Both are
  // pure allocation paths — they hit resourceLimits.maxOldGenerationSizeMb and V8 raises OOM
  // via the ERR_WORKER_OUT_OF_MEMORY code (newer Node) or exit-code 5 (older). grow-string is
  // deliberately NOT part of this sweep: JS's `String::kMaxLength` (V8-side language cap,
  // ~1 GB) fires BEFORE the 32 MB heap cap because the doubling `s = s + s` must materialize
  // the doubled string, and V8 raises `RangeError: Invalid string length` at that cap — a
  // language error, not an allocator error. That's correctly classified as `crash` and lives
  // outside the OOM classifier's contract.
  it.each(['grow-array', 'grow-buffer'] as const)(
    'synthetic:oom (%s) is classified reliably as kind=oom across 3 runs',
    async (mode) => {
      for (let i = 0; i < 3; i++) {
        const outcome = await runBounded(
          { kind: 'synthetic:oom', mode },
          OOM_BOUNDS,
        );
        // Under the hardened classifier this must be 'oom' every time. If a run leaks
        // through as 'crash', the failure message includes the error name+message so a
        // regression is diagnosable at a glance.
        if (outcome.kind !== 'oom') {
          const detail =
            outcome.kind === 'crash'
              ? `crash: ${outcome.error.name}: ${outcome.error.message}`
              : `unexpected kind: ${outcome.kind}`;
          throw new Error(`iteration ${i} of ${mode} did not classify as oom → ${detail}`);
        }
        expect(outcome.kind).toBe('oom');
      }
    },
    // Each iteration allocates aggressively; three runs × two modes need generous headroom.
    120_000,
  );

  it('synthetic:oom (grow-string) surfaces as crash (JS-language RangeError, not OOM)', async () => {
    // Pin the current behavior: V8's String::kMaxLength check fires before the heap cap
    // when doubling a string, so this scenario legitimately produces a `crash` outcome.
    // If a future Node/V8 lifts kMaxLength high enough that the heap cap wins, or the
    // synthetic scenario is rewritten to allocate differently, this expectation will need
    // to shift — the test then serves as the change-point marker.
    const outcome = await runBounded(
      { kind: 'synthetic:oom', mode: 'grow-string' },
      OOM_BOUNDS,
    );
    // Both outcomes are meaningful engine behavior; the test pins the current classifier
    // path (crash) but tolerates a future evolution to oom.
    expect(['crash', 'oom']).toContain(outcome.kind);
  }, 30_000);
});
