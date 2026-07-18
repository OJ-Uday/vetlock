import { describe, it, expect } from 'vitest';
import { validateFinding } from '@vetlock/core';
import { obfJsManglerSignatureDetector, mangledIdsInFile } from '../src/obf-js-mangler.js';
import { mkSnap, mkFile } from './helpers.js';

describe('obf.js-mangler-signature (port from guarddog:threat-runtime-obfuscation-js-mangling)', () => {
  it('POS: fires on ADDED file with 3+ distinct _0x mangled identifiers across tracked-API snippets', () => {
    // Simulate a mangler-obfuscated file: the AST-tracked API snippets contain
    // multiple distinct _0x hex identifiers (typical of javascript-obfuscator).
    const manglerFile = mkFile({
      path: 'dist/index.js',
      dynamicCode: [
        {
          line: 1,
          kind: 'new-function',
          snippet: 'var _0x1a2b = new Function(_0x3c4d);',
        },
        {
          line: 2,
          kind: 'char-arithmetic-decoder',
          snippet: 'file uses String.fromCharCode + charCodeAt — per-char decoder shape',
        },
      ],
      envAccesses: [
        {
          line: 3,
          keys: ['NPM_TOKEN'],
          snippet: 'var _0x5e6f = process.env[_0x1a2b(0)];',
        },
      ],
      suspiciousLiterals: [
        {
          line: 4,
          length: 512,
          entropy: 5.2,
          preview: '_0x9ab0=["Y29uc3Rf","YXR0YWNrZXI="]',
        },
      ],
    });
    const pair = {
      old: null,
      new: mkSnap({ name: 'evil-pkg', version: '1.0.0', files: [manglerFile] }),
    };
    const findings = obfJsManglerSignatureDetector.run(pair, { direction: 'added' });
    expect(findings).toHaveLength(1);
    const f = findings[0]!;
    expect(f.detector).toBe('obf.js-mangler-signature');
    expect(f.category).toBe('OBF');
    expect(f.severity).toBe('WARN');
    expect(f.evidence[0]!.file).toBe('dist/index.js');
    expect(f.message).toMatch(/mangled identifiers/);
    expect(validateFinding(f)).toBeNull();
  });

  it('NEG: does not fire on a clean file with no mangled identifiers', () => {
    const cleanFile = mkFile({
      path: 'src/index.js',
      dynamicCode: [{ line: 1, kind: 'eval', snippet: 'eval(userInput)' }],
      envAccesses: [{ line: 2, keys: ['PATH'], snippet: 'process.env.PATH' }],
    });
    const pair = {
      old: null,
      new: mkSnap({ name: 'legit-pkg', version: '1.0.0', files: [cleanFile] }),
    };
    expect(obfJsManglerSignatureDetector.run(pair, { direction: 'added' })).toEqual([]);
  });

  it('NEG: does not fire when only 2 distinct mangled identifiers are present (below threshold)', () => {
    const undershoot = mkFile({
      path: 'a.js',
      dynamicCode: [
        { line: 1, kind: 'new-function', snippet: 'var _0x1a2b = _0x3c4d(x)' },
      ],
    });
    const pair = {
      old: null,
      new: mkSnap({ name: 'benign-pkg', version: '1.0.0', files: [undershoot] }),
    };
    expect(obfJsManglerSignatureDetector.run(pair, { direction: 'added' })).toEqual([]);
  });

  it('NEG: does not fire on non-JS files even if their snippets contain _0x tokens (path filter)', () => {
    const jsonFile = mkFile({
      path: 'data.json',
      // JSON files never come with populated dynamicCode/envAccesses in real
      // extractCapabilities output, but defensively test the path filter here.
      suspiciousLiterals: [
        { line: 1, length: 200, entropy: 5.0, preview: '_0x111 _0x222 _0x333 _0x444' },
      ],
    });
    const pair = {
      old: null,
      new: mkSnap({ name: 'data-pkg', version: '1.0.0', files: [jsonFile] }),
    };
    expect(obfJsManglerSignatureDetector.run(pair, { direction: 'added' })).toEqual([]);
  });

  it('DIFF-SAFE: does not fire when the same mangled ids were already in the OLD version', () => {
    const manglerSnippets = {
      dynamicCode: [
        { line: 1, kind: 'new-function' as const, snippet: 'var _0x1a2b = Fn(_0x3c4d); _0x5e6f();' },
      ],
    };
    const oldFile = mkFile({ path: 'dist/index.js', ...manglerSnippets });
    const newFile = mkFile({ path: 'dist/index.js', ...manglerSnippets });
    const pair = {
      old: mkSnap({ name: 'evil-pkg', version: '1.0.0', files: [oldFile] }),
      new: mkSnap({ name: 'evil-pkg', version: '1.0.1', files: [newFile] }),
    };
    expect(obfJsManglerSignatureDetector.run(pair, { direction: 'changed' })).toEqual([]);
  });

  it('DIFF: fires when NEW mangled identifiers appear in an existing file', () => {
    const oldFile = mkFile({
      path: 'dist/index.js',
      dynamicCode: [{ line: 1, kind: 'eval', snippet: 'eval("x")' }],
    });
    const newFile = mkFile({
      path: 'dist/index.js',
      dynamicCode: [
        { line: 1, kind: 'new-function', snippet: 'var _0x1a2b = new Function(_0x3c4d);' },
        { line: 2, kind: 'eval', snippet: '_0x5e6f(_0x789a);' },
      ],
      envAccesses: [{ line: 3, keys: ['NPM_TOKEN'], snippet: 'const _0xdead = process.env.NPM_TOKEN' }],
    });
    const pair = {
      old: mkSnap({ name: 'foo', version: '1.0.0', files: [oldFile] }),
      new: mkSnap({ name: 'foo', version: '1.0.1', files: [newFile] }),
    };
    const findings = obfJsManglerSignatureDetector.run(pair, { direction: 'changed' });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.direction).toBe('changed');
    expect(findings[0]!.from).toBe('1.0.0');
    expect(findings[0]!.to).toBe('1.0.1');
  });

  it('helper: mangledIdsInFile collects distinct _0x identifiers across all snippet fields', () => {
    const f = mkFile({
      path: 'a.js',
      dynamicCode: [{ line: 1, kind: 'eval', snippet: '_0xaaa1(_0xaaa2)' }],
      envAccesses: [{ line: 2, keys: null, snippet: '_0xbbb3(process.env)' }],
      suspiciousLiterals: [
        { line: 3, length: 40, entropy: 5.0, preview: '_0xccc4=[]; _0xaaa1(_0xccc4);' },
      ],
    });
    const ids = mangledIdsInFile(f);
    expect([...ids].sort()).toEqual(['_0xaaa1', '_0xaaa2', '_0xbbb3', '_0xccc4']);
  });
});
