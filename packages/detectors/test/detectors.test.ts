import { describe, it, expect } from 'vitest';
import { validateFinding } from '@vetlock/core';
import {
  ALL_DETECTORS,
  runAll,
  installDetector,
  maintainerDetector,
  netDetector,
  execDetector,
  fsDetector,
  envDetector,
  codeDetector,
  obfDetector,
  depsManifestDetector,
  stablesort,
} from '../src/index.js';
import { mkSnap, mkFile } from './helpers.js';

describe('INSTALL detector', () => {
  it('flags an added postinstall script', () => {
    const pair = {
      old: mkSnap({ name: 'foo', version: '1.0.0' }),
      new: mkSnap({
        name: 'foo',
        version: '1.0.1',
        manifest: { name: 'foo', version: '1.0.1', scripts: { postinstall: 'node do-thing.js' } },
      }),
    };
    const findings = installDetector.run(pair, { direction: 'changed' });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.detector).toBe('install.script-added');
    expect(findings[0]!.severity).toBe('BLOCK');
    expect(validateFinding(findings[0]!)).toBeNull();
  });
  it('flags a changed body', () => {
    const pair = {
      old: mkSnap({ name: 'foo', version: '1.0.0', manifest: { name: 'foo', version: '1.0.0', scripts: { postinstall: 'echo old' } } }),
      new: mkSnap({ name: 'foo', version: '1.0.1', manifest: { name: 'foo', version: '1.0.1', scripts: { postinstall: 'echo new-and-evil' } } }),
    };
    const findings = installDetector.run(pair, { direction: 'changed' });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.detector).toBe('install.script-changed');
  });
  it('emits nothing when scripts are unchanged (diff-framing)', () => {
    const scripts = { postinstall: 'echo same' };
    const pair = {
      old: mkSnap({ name: 'foo', version: '1.0.0', manifest: { name: 'foo', version: '1.0.0', scripts } }),
      new: mkSnap({ name: 'foo', version: '1.0.1', manifest: { name: 'foo', version: '1.0.1', scripts } }),
    };
    expect(installDetector.run(pair, { direction: 'changed' })).toHaveLength(0);
  });
});

describe('META detector', () => {
  it('flags maintainer email change', () => {
    const pair = {
      old: mkSnap({ name: 'foo', version: '1.0.0', manifest: { name: 'foo', version: '1.0.0', maintainers: [{ email: 'a@ex.com' }] } }),
      new: mkSnap({ name: 'foo', version: '1.0.1', manifest: { name: 'foo', version: '1.0.1', maintainers: [{ email: 'attacker@evil.example.invalid' }] } }),
    };
    const findings = maintainerDetector.run(pair, { direction: 'changed' });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('WARN');
    expect(validateFinding(findings[0]!)).toBeNull();
  });
  it('is silent when maintainers unchanged', () => {
    const m = [{ email: 'a@ex.com' }];
    const pair = {
      old: mkSnap({ name: 'foo', version: '1.0.0', manifest: { name: 'foo', version: '1.0.0', maintainers: m } }),
      new: mkSnap({ name: 'foo', version: '1.0.1', manifest: { name: 'foo', version: '1.0.1', maintainers: m } }),
    };
    expect(maintainerDetector.run(pair, { direction: 'changed' })).toHaveLength(0);
  });
});

describe('NET detector', () => {
  it('flags a new URL endpoint added', () => {
    const oldFile = mkFile({ path: 'index.js', urlLiterals: ['https://ok.example.com/api'] });
    const newFile = mkFile({
      path: 'index.js',
      urlLiterals: ['https://ok.example.com/api', 'https://exfil.example.invalid/data'],
    });
    const pair = {
      old: mkSnap({ name: 'chalk', version: '5.3.0', files: [oldFile] }),
      new: mkSnap({ name: 'chalk', version: '5.3.1', files: [newFile] }),
    };
    const findings = netDetector.run(pair, { direction: 'changed' });
    expect(findings.some((f) => f.detector === 'net.new-endpoint' && f.severity === 'BLOCK')).toBe(true);
    for (const f of findings) expect(validateFinding(f)).toBeNull();
  });
  it("is silent when URLs match (diff-framing: 'axios uses the network of course')", () => {
    const same = mkFile({ path: 'i.js', urlLiterals: ['https://ok.example.com/api'] });
    const pair = {
      old: mkSnap({ name: 'axios', version: '1.0.0', files: [same] }),
      new: mkSnap({ name: 'axios', version: '1.0.1', files: [same] }),
    };
    expect(netDetector.run(pair, { direction: 'changed' })).toHaveLength(0);
  });
  it('flags new network module import', () => {
    const oldFile = mkFile({ path: 'i.js', networkModules: [] });
    const newFile = mkFile({ path: 'i.js', networkModules: ['https'] });
    const pair = {
      old: mkSnap({ name: 'foo', version: '1.0.0', files: [oldFile] }),
      new: mkSnap({ name: 'foo', version: '1.0.1', files: [newFile] }),
    };
    const findings = netDetector.run(pair, { direction: 'changed' });
    expect(findings.some((f) => f.detector === 'net.new-module')).toBe(true);
  });
});

describe('EXEC detector', () => {
  it('flags new child_process import', () => {
    const pair = {
      old: mkSnap({ name: 'foo', version: '1.0.0', files: [mkFile({ path: 'i.js' })] }),
      new: mkSnap({ name: 'foo', version: '1.0.1', files: [mkFile({ path: 'i.js', execModules: ['child_process'] })] }),
    };
    const findings = execDetector.run(pair, { direction: 'changed' });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('BLOCK');
    expect(validateFinding(findings[0]!)).toBeNull();
  });
});

describe('FS detector', () => {
  it('flags new write to a hot path (.npmrc)', () => {
    const pair = {
      old: mkSnap({ name: 'foo', version: '1.0.0', files: [mkFile({ path: 'i.js' })] }),
      new: mkSnap({ name: 'foo', version: '1.0.1', files: [mkFile({ path: 'i.js', fsWriteTargets: ['/root/.npmrc'] })] }),
    };
    const findings = fsDetector.run(pair, { direction: 'changed' });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('BLOCK');
  });
  it('ignores writes to project-local paths', () => {
    const pair = {
      old: mkSnap({ name: 'foo', version: '1.0.0', files: [mkFile({ path: 'i.js' })] }),
      new: mkSnap({ name: 'foo', version: '1.0.1', files: [mkFile({ path: 'i.js', fsWriteTargets: ['./cache.json'] })] }),
    };
    expect(fsDetector.run(pair, { direction: 'changed' })).toHaveLength(0);
  });
});

describe('ENV detector', () => {
  it('flags new NPM_TOKEN read', () => {
    const pair = {
      old: mkSnap({ name: 'chalk', version: '5.3.0', files: [mkFile({ path: 'i.js' })] }),
      new: mkSnap({
        name: 'chalk', version: '5.3.1',
        files: [mkFile({
          path: 'i.js',
          envAccesses: [{ line: 3, keys: ['NPM_TOKEN'], snippet: 'process.env.NPM_TOKEN' }],
        })],
      }),
    };
    const findings = envDetector.run(pair, { direction: 'changed' });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('BLOCK');
    expect(findings[0]!.detector).toBe('env.token-harvest');
  });
  it('flags whole-object enumeration', () => {
    const pair = {
      old: mkSnap({ name: 'foo', version: '1.0.0', files: [mkFile({ path: 'i.js' })] }),
      new: mkSnap({
        name: 'foo', version: '1.0.1',
        files: [mkFile({
          path: 'i.js',
          envAccesses: [{ line: 2, keys: null, snippet: 'Object.keys(process.env)' }],
        })],
      }),
    };
    const findings = envDetector.run(pair, { direction: 'changed' });
    expect(findings).toHaveLength(1);
  });
  it('ignores non-sensitive env reads', () => {
    const pair = {
      old: mkSnap({ name: 'foo', version: '1.0.0', files: [mkFile({ path: 'i.js' })] }),
      new: mkSnap({
        name: 'foo', version: '1.0.1',
        files: [mkFile({ path: 'i.js', envAccesses: [{ line: 1, keys: ['NODE_ENV'], snippet: 'process.env.NODE_ENV' }] })],
      }),
    };
    expect(envDetector.run(pair, { direction: 'changed' })).toHaveLength(0);
  });
});

describe('CODE detector', () => {
  it('flags eval added', () => {
    const pair = {
      old: mkSnap({ name: 'foo', version: '1.0.0', files: [mkFile({ path: 'i.js' })] }),
      new: mkSnap({
        name: 'foo', version: '1.0.1',
        files: [mkFile({
          path: 'i.js',
          dynamicCode: [{ line: 5, kind: 'eval', snippet: 'eval("...")' }],
        })],
      }),
    };
    expect(codeDetector.run(pair, { direction: 'changed' })).toHaveLength(1);
  });
});

describe('OBF detector', () => {
  it('flags entropy jump on same-path file', () => {
    const oldF = mkFile({ path: 'i.js', entropy: 4.0, minified: false });
    const newF = mkFile({ path: 'i.js', entropy: 6.5, minified: true });
    const pair = {
      old: mkSnap({ name: 'foo', version: '1.0.0', files: [oldF] }),
      new: mkSnap({ name: 'foo', version: '1.0.1', files: [newF] }),
    };
    const findings = obfDetector.run(pair, { direction: 'changed' });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.category).toBe('OBF');
    expect(findings[0]!.severity).toBe('WARN');
  });
  it('does not fire when entropy is stable', () => {
    const of = mkFile({ path: 'i.js', entropy: 4.5 });
    const nf = mkFile({ path: 'i.js', entropy: 4.5 });
    const pair = {
      old: mkSnap({ name: 'foo', version: '1.0.0', files: [of] }),
      new: mkSnap({ name: 'foo', version: '1.0.1', files: [nf] }),
    };
    expect(obfDetector.run(pair, { direction: 'changed' })).toHaveLength(0);
  });
});

describe('DEPS-manifest detector', () => {
  it('flags a new direct dependency', () => {
    const pair = {
      old: mkSnap({ name: 'foo', version: '1.0.0', manifest: { name: 'foo', version: '1.0.0', dependencies: { a: '^1' } } }),
      new: mkSnap({ name: 'foo', version: '1.0.1', manifest: { name: 'foo', version: '1.0.1', dependencies: { a: '^1', evil: '^0.1' } } }),
    };
    const findings = depsManifestDetector.run(pair, { direction: 'changed' });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('INFO');
  });
});

describe('runAll — escalation + validation', () => {
  it('escalates OBF/WARN to BLOCK when co-occurring with NET in the same package', () => {
    // Build a package with: minified regression (OBF/WARN) + new URL literal (NET/BLOCK).
    const oldFile = mkFile({ path: 'i.js', entropy: 3.0, minified: false, urlLiterals: [] });
    const newFile = mkFile({
      path: 'i.js', entropy: 6.0, minified: true,
      urlLiterals: ['https://exfil.example.invalid/data'],
    });
    const pair = {
      old: mkSnap({ name: 'chalk', version: '5.3.0', files: [oldFile] }),
      new: mkSnap({ name: 'chalk', version: '5.3.1', files: [newFile] }),
    };
    const findings = runAll(pair);
    const obf = findings.find((f) => f.category === 'OBF')!;
    expect(obf.severity).toBe('BLOCK');
    expect(obf.message).toMatch(/escalated/);
  });

  it('validates every finding through validateFinding()', () => {
    const pair = {
      old: mkSnap({ name: 'foo', version: '1.0.0' }),
      new: mkSnap({ name: 'foo', version: '1.0.1', manifest: { name: 'foo', version: '1.0.1', scripts: { postinstall: 'x' } } }),
    };
    const findings = runAll(pair);
    for (const f of findings) expect(validateFinding(f)).toBeNull();
  });

  it('stablesort produces deterministic order', () => {
    const a = runAll({
      old: mkSnap({ name: 'foo', version: '1.0.0' }),
      new: mkSnap({ name: 'foo', version: '1.0.1', manifest: { name: 'foo', version: '1.0.1', scripts: { postinstall: 'x', preinstall: 'y' } } }),
    });
    const b = runAll({
      old: mkSnap({ name: 'foo', version: '1.0.0' }),
      new: mkSnap({ name: 'foo', version: '1.0.1', manifest: { name: 'foo', version: '1.0.1', scripts: { postinstall: 'x', preinstall: 'y' } } }),
    });
    expect(JSON.stringify(a)).toBe(JSON.stringify(b));
    expect(a.length).toBe(2);
  });

  it('registers exactly nine built-in detectors', () => {
    expect(ALL_DETECTORS.length).toBe(9);
  });

  it('stablesort exported', () => {
    expect(typeof stablesort).toBe('function');
  });
});
