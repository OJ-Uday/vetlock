/**
 * WASM detector tests.
 *
 * We synthesize minimal WASM binaries by hand — each is a real, spec-compliant
 * WASM module. This proves the detector reads the binary, not just its filename.
 *
 * The imports we craft are the ones we'd want to catch in a real attack:
 *   - env.eval — JS globals exposed to the WASM sandbox
 *   - wasi_snapshot_preview1.fd_write — full filesystem via WASI
 */

import { describe, it, expect } from 'vitest';
import { summarizeWasm, isWasmBinary } from '../src/wasm.js';

/** LEB128 unsigned encode — variable-length int used throughout the WASM format. */
function leb128(n: number): number[] {
  const out: number[] = [];
  do {
    let b = n & 0x7f;
    n >>>= 7;
    if (n !== 0) b |= 0x80;
    out.push(b);
  } while (n !== 0);
  return out;
}

function utf8(s: string): number[] {
  return [...Buffer.from(s, 'utf8')];
}

/**
 * Build a minimal WASM binary with one import.
 *   Type section: 1 type, () -> void  (type 0)
 *   Import section: import `${moduleName}`.`${importName}` : func of type 0
 */
function makeMinimalWasmWithImport(moduleName: string, importName: string): Buffer {
  const magic = [0x00, 0x61, 0x73, 0x6d];
  const version = [0x01, 0x00, 0x00, 0x00];

  // Type section (id=1): one type -> (func () -> ())
  const typeSection = [
    0x01,        // section id: type
    0x04,        // section size: 4 bytes
    0x01,        // number of types: 1
    0x60, 0x00, 0x00, // func () -> ()
  ];

  // Import section (id=2): one import
  const moduleNameBytes = utf8(moduleName);
  const importNameBytes = utf8(importName);
  const importBody = [
    0x01,                                            // number of imports
    ...leb128(moduleNameBytes.length), ...moduleNameBytes,
    ...leb128(importNameBytes.length), ...importNameBytes,
    0x00,                                            // import kind: func
    0x00,                                            // type index: 0
  ];
  const importSection = [
    0x02,                                            // section id: import
    ...leb128(importBody.length),
    ...importBody,
  ];

  return Buffer.from([...magic, ...version, ...typeSection, ...importSection]);
}

describe('isWasmBinary', () => {
  it('recognizes valid WASM magic', () => {
    const buf = Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
    expect(isWasmBinary(buf)).toBe(true);
  });

  it('rejects non-WASM buffers', () => {
    expect(isWasmBinary(Buffer.from('hello'))).toBe(false);
    expect(isWasmBinary(Buffer.from([]))).toBe(false);
    expect(isWasmBinary(Buffer.from([0xff, 0xff, 0xff, 0xff]))).toBe(false);
  });
});

describe('summarizeWasm — real binary parsing', () => {
  it('extracts a benign env.foo import', () => {
    const wasm = makeMinimalWasmWithImport('env', 'foo');
    const s = summarizeWasm(wasm);
    expect(s.parsed).toBe(true);
    expect(s.imports).toHaveLength(1);
    expect(s.imports[0]).toEqual({ module: 'env', name: 'foo', kind: 'func' });
  });

  it('extracts a suspicious env.eval import', () => {
    const wasm = makeMinimalWasmWithImport('env', 'eval');
    const s = summarizeWasm(wasm);
    expect(s.parsed).toBe(true);
    expect(s.imports[0]).toMatchObject({ module: 'env', name: 'eval' });
  });

  it('extracts a WASI filesystem import', () => {
    const wasm = makeMinimalWasmWithImport('wasi_snapshot_preview1', 'fd_write');
    const s = summarizeWasm(wasm);
    expect(s.parsed).toBe(true);
    expect(s.imports[0]).toMatchObject({
      module: 'wasi_snapshot_preview1',
      name: 'fd_write',
    });
  });

  it('fail-softs on non-WASM input (no throw)', () => {
    const s = summarizeWasm(Buffer.from('not a wasm binary at all'));
    expect(s.parsed).toBe(false);
    expect(s.parseError).toMatch(/magic bytes/);
  });

  it('fail-softs on truncated WASM (no throw; may parse as empty)', () => {
    // Magic + version + partial section — the parser is deliberately permissive
    // (an attacker could ship a "technically-valid" WASM whose broken sections
    // are ignored). The safety invariant we care about is: it does NOT throw.
    const wasm = Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0xff]);
    expect(() => summarizeWasm(wasm)).not.toThrow();
  });

  it('fail-softs on random-garbage-that-happens-to-have-magic bytes', () => {
    const bad = Buffer.concat([
      Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]),
      Buffer.from(Array.from({ length: 100 }, () => Math.floor(Math.random() * 256))),
    ]);
    // Should complete regardless of what the parser does.
    expect(() => summarizeWasm(bad)).not.toThrow();
  });

  it('caps oversized inputs without attempting to parse', () => {
    // Header + a bogus 100 MB section length claim
    const huge = Buffer.alloc(25 * 1024 * 1024);
    huge[0] = 0x00; huge[1] = 0x61; huge[2] = 0x73; huge[3] = 0x6d;
    huge[4] = 0x01;
    const s = summarizeWasm(huge);
    expect(s.parsed).toBe(false);
    expect(s.parseError).toMatch(/too large/);
  });
});
