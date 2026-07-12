/**
 * WASM detector — flags suspicious imports in WebAssembly binaries.
 */

import { describe, it, expect } from 'vitest';
import { wasmDetector, isSuspiciousImport } from '../src/wasm.js';
import { mkSnap } from './helpers.js';

describe('WASM detector — suspicious import classifier', () => {
  it.each([
    ['env', 'eval'],
    ['env', 'fetch'],
    ['env', 'exec'],
    ['env', 'Function'],
    ['wasi_snapshot_preview1', 'fd_write'],
    ['wasi_snapshot_preview1', 'path_open'],
    ['wasi_snapshot_preview1', 'sock_send'],
    ['wasi_snapshot_preview2', 'fd_read'],
  ])('flags %s.%s as suspicious', (mod, name) => {
    expect(isSuspiciousImport(mod, name)).toBe(true);
  });

  it.each([
    ['env', 'memory'],                     // legitimate memory import
    ['env', '__linear_memory'],            // emscripten default
    ['wasi_snapshot_preview1', 'clock_time_get'], // reading clock is fine
    ['GOT.mem', 'stackPointer'],            // dynamic linking marker
    ['env', '__stack_pointer'],
  ])('does NOT flag %s.%s (legitimate)', (mod, name) => {
    expect(isSuspiciousImport(mod, name)).toBe(false);
  });
});

describe('WASM detector — diff behavior', () => {
  it('fires when new suspicious import appears between versions', () => {
    const pair = {
      old: mkSnap({
        name: 'wasm-pkg',
        version: '1.0.0',
        files: [],
        nativeArtifacts: [
          { path: 'build/mod.wasm', bytes: 200, sha256: 'oldhash', kind: 'wasm',
            wasmImports: [{ module: 'env', name: 'memory', kind: 'func' }] },
        ],
      }),
      new: mkSnap({
        name: 'wasm-pkg',
        version: '1.0.1',
        files: [],
        nativeArtifacts: [
          { path: 'build/mod.wasm', bytes: 220, sha256: 'newhash', kind: 'wasm',
            wasmImports: [
              { module: 'env', name: 'memory', kind: 'func' },
              { module: 'env', name: 'eval', kind: 'func' },
            ] },
        ],
      }),
    };
    const findings = wasmDetector.run(pair, { direction: 'changed' });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.detector).toBe('wasm.suspicious-import');
    expect(findings[0]!.severity).toBe('BLOCK');
    expect(findings[0]!.message).toMatch(/env\.eval/);
  });

  it('does not fire when only benign imports are added', () => {
    const pair = {
      old: mkSnap({
        name: 'wasm-pkg', version: '1.0.0', files: [],
        nativeArtifacts: [{ path: 'm.wasm', bytes: 100, sha256: 'a', kind: 'wasm', wasmImports: [] }],
      }),
      new: mkSnap({
        name: 'wasm-pkg', version: '1.0.1', files: [],
        nativeArtifacts: [{ path: 'm.wasm', bytes: 120, sha256: 'b', kind: 'wasm',
          wasmImports: [{ module: 'env', name: '__linear_memory', kind: 'memory' }] }],
      }),
    };
    expect(wasmDetector.run(pair, { direction: 'changed' })).toHaveLength(0);
  });

  it('flags unparseable WASM binaries as OBF/WARN', () => {
    const pair = {
      old: mkSnap({ name: 'wasm-pkg', version: '1.0.0', files: [], nativeArtifacts: [] }),
      new: mkSnap({
        name: 'wasm-pkg', version: '1.0.1', files: [],
        nativeArtifacts: [{ path: 'evil.wasm', bytes: 100, sha256: 'x', kind: 'wasm',
          wasmParseError: 'invalid section length' }],
      }),
    };
    const findings = wasmDetector.run(pair, { direction: 'changed' });
    expect(findings.some((f) => f.detector === 'wasm.unparseable')).toBe(true);
  });
});
