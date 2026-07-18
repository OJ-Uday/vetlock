/**
 * OBF image-decode-exec — image asset + fs read + dynamic-code co-occurrence.
 *
 * Test contract:
 *  - New image asset + read of that image + dynamic-code sink in same version
 *    → fires.
 *  - Missing any one leg → does NOT fire.
 *  - Image extension matching is case-insensitive.
 *  - Reader lookup falls back to basename when literal-arg is unqualified.
 *  - Diff discipline: only NEW/CHANGED images trigger.
 *
 * Ports from guarddog:threat-runtime-obfuscation-steganography, per §4 row 9.
 */

import { describe, it, expect } from 'vitest';
import { imageDecodeExecDetector } from '../src/obf-image-decode-exec.js';
import { mkSnap, mkFile } from './helpers.js';

describe('obf.image-decode-exec — steganography shape', () => {
  it('fires when new PNG + read of it + dynamic-code all co-occur', () => {
    const pair = {
      old: null,
      new: mkSnap({
        name: 'evil-package',
        version: '1.0.0',
        files: [
          // Image asset (byte-level scanners see valid PNG).
          mkFile({ path: 'assets/logo.png', bytes: 512 }),
          // Reader references the image via fsReadTargets literal-arg.
          mkFile({
            path: 'lib/init.js',
            fsReadTargets: ['assets/logo.png'],
          }),
          // Dynamic-code sink somewhere in the same package.
          mkFile({
            path: 'lib/decode.js',
            dynamicCode: [{ line: 3, kind: 'new-function', snippet: 'new Function(code)' }],
          }),
        ],
      }),
    };
    const findings = imageDecodeExecDetector.run(pair, { direction: 'added' });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.detector).toBe('obf.image-decode-exec');
    expect(findings[0]!.severity).toBe('WARN');
    expect(findings[0]!.message).toMatch(/logo\.png/);
    expect(findings[0]!.message).toMatch(/dynamic-code sink/);
  });

  it('falls back to basename match when literal-arg is unqualified', () => {
    // Attacker calls `readFileSync('logo.png')` even though the shipped path
    // is `assets/logo.png`. Detector should still connect them.
    const pair = {
      old: null,
      new: mkSnap({
        name: 'evil-package',
        version: '1.0.0',
        files: [
          mkFile({ path: 'assets/logo.png', bytes: 512 }),
          mkFile({ path: 'lib/init.js', fsReadTargets: ['logo.png'] }),
          mkFile({
            path: 'lib/decode.js',
            dynamicCode: [{ line: 3, kind: 'eval', snippet: 'eval(code)' }],
          }),
        ],
      }),
    };
    expect(imageDecodeExecDetector.run(pair, { direction: 'added' })).toHaveLength(1);
  });

  it('does NOT fire without a dynamic-code sink', () => {
    const pair = {
      old: null,
      new: mkSnap({
        name: 'legit-package',
        version: '1.0.0',
        files: [
          mkFile({ path: 'assets/logo.png' }),
          mkFile({ path: 'lib/init.js', fsReadTargets: ['assets/logo.png'] }),
          // No dynamic-code sinks anywhere.
        ],
      }),
    };
    expect(imageDecodeExecDetector.run(pair, { direction: 'added' })).toHaveLength(0);
  });

  it('does NOT fire without an image asset', () => {
    const pair = {
      old: null,
      new: mkSnap({
        name: 'code-only-package',
        version: '1.0.0',
        files: [
          mkFile({
            path: 'lib/main.js',
            dynamicCode: [{ line: 1, kind: 'eval', snippet: 'eval(x)' }],
          }),
        ],
      }),
    };
    expect(imageDecodeExecDetector.run(pair, { direction: 'added' })).toHaveLength(0);
  });

  it('does NOT fire when the image is not read by any code', () => {
    const pair = {
      old: null,
      new: mkSnap({
        name: 'legit-with-eval',
        version: '1.0.0',
        files: [
          mkFile({ path: 'assets/logo.png' }),
          mkFile({
            path: 'lib/main.js',
            dynamicCode: [{ line: 1, kind: 'eval', snippet: 'eval(x)' }],
          }),
        ],
      }),
    };
    // No file reads the image path — no steganography shape.
    expect(imageDecodeExecDetector.run(pair, { direction: 'added' })).toHaveLength(0);
  });

  it('does NOT fire when only unchanged image + unchanged sink between versions', () => {
    const before = [
      mkFile({ path: 'assets/logo.png', sha256: 'sha256-same' }),
      mkFile({ path: 'lib/init.js', fsReadTargets: ['assets/logo.png'] }),
      mkFile({
        path: 'lib/decode.js',
        dynamicCode: [{ line: 3, kind: 'new-function', snippet: 'new Function()' }],
      }),
    ];
    const after = [
      mkFile({ path: 'assets/logo.png', sha256: 'sha256-same' }),
      mkFile({ path: 'lib/init.js', fsReadTargets: ['assets/logo.png'] }),
      mkFile({
        path: 'lib/decode.js',
        dynamicCode: [{ line: 3, kind: 'new-function', snippet: 'new Function()' }],
      }),
    ];
    const pair = {
      old: mkSnap({ name: 'stable-package', version: '1.0.0', files: before }),
      new: mkSnap({ name: 'stable-package', version: '1.0.1', files: after }),
    };
    // Image unchanged (same sha256) + sink unchanged → nothing NEW in the diff.
    expect(imageDecodeExecDetector.run(pair, { direction: 'changed' })).toHaveLength(0);
  });

  it('fires when a previously-existing image gets replaced (sha256 changed)', () => {
    const pair = {
      old: mkSnap({
        name: 'evil-package',
        version: '1.0.0',
        files: [
          mkFile({ path: 'assets/logo.png', sha256: 'sha256-old' }),
          mkFile({ path: 'lib/init.js', fsReadTargets: ['assets/logo.png'] }),
          mkFile({
            path: 'lib/decode.js',
            dynamicCode: [{ line: 3, kind: 'eval', snippet: 'eval' }],
          }),
        ],
      }),
      new: mkSnap({
        name: 'evil-package',
        version: '1.0.1',
        files: [
          mkFile({ path: 'assets/logo.png', sha256: 'sha256-new' }),
          mkFile({ path: 'lib/init.js', fsReadTargets: ['assets/logo.png'] }),
          mkFile({
            path: 'lib/decode.js',
            dynamicCode: [{ line: 3, kind: 'eval', snippet: 'eval' }],
          }),
        ],
      }),
    };
    expect(imageDecodeExecDetector.run(pair, { direction: 'changed' })).toHaveLength(1);
  });

  it('matches multiple image extensions', () => {
    for (const ext of ['png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp', 'ico']) {
      const pair = {
        old: null,
        new: mkSnap({
          name: 'evil-package',
          version: '1.0.0',
          files: [
            mkFile({ path: `assets/hidden.${ext}` }),
            mkFile({ path: 'lib/init.js', fsReadTargets: [`assets/hidden.${ext}`] }),
            mkFile({
              path: 'lib/decode.js',
              dynamicCode: [{ line: 3, kind: 'vm', snippet: 'vm.runInThisContext' }],
            }),
          ],
        }),
      };
      const findings = imageDecodeExecDetector.run(pair, { direction: 'added' });
      expect(findings.length, `should fire for .${ext}`).toBe(1);
    }
  });
});
