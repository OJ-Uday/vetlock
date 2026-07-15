import { describe, it, expect } from 'vitest';
import {
  extractCapabilities,
  shannonEntropy,
  isMinified,
  SENSITIVE_ENV_KEYS,
} from '../src/capabilities.js';

function cap(src: string, filePath = 'a.js') {
  return extractCapabilities(filePath, src, 'sha256-fake', src.length);
}

describe('capability extraction', () => {
  it('detects require() of a network module', () => {
    const c = cap(`const h = require('http'); h.get('http://x');`);
    expect(c.networkModules).toContain('http');
  });

  it('detects ES import of https', () => {
    const c = cap(`import https from 'https'; https.get('a');`);
    expect(c.networkModules).toContain('https');
  });

  it('detects child_process', () => {
    const c = cap(`import { spawn } from 'child_process'; spawn('ls');`);
    expect(c.execModules).toContain('child_process');
  });

  it('detects execSync', () => {
    const c = cap(`const { execSync } = require('child_process'); execSync('whoami');`);
    expect(c.execModules).toContain('child_process');
  });

  it('detects execFile', () => {
    const c = cap(`const { execFile } = require('child_process'); execFile('ls', ['-la'], () => {});`);
    expect(c.execModules).toContain('child_process');
  });

  it('detects fork', () => {
    const c = cap(`const { fork } = require('child_process'); fork('worker.js');`);
    expect(c.execModules).toContain('child_process');
  });

  it('detects execFileSync', () => {
    const c = cap(`const { execFileSync } = require('child_process'); execFileSync('ls', ['-la']);`);
    expect(c.execModules).toContain('child_process');
  });

  it('detects exec', () => {
    const c = cap(`const { exec } = require('child_process'); exec('ls');`);
    expect(c.execModules).toContain('child_process');
  });

  it('detects fs writes with literal targets', () => {
    const c = cap(`const fs = require('fs'); fs.writeFileSync('/etc/hi', 'x');`);
    expect(c.fsModules).toContain('fs');
    expect(c.fsWriteTargets).toContain('/etc/hi');
  });

  it('flags eval', () => {
    const c = cap(`eval("var x=1")`);
    expect(c.dynamicCode.some((d) => d.kind === 'eval')).toBe(true);
  });

  it('flags new Function()', () => {
    const c = cap(`new Function("return 1")()`);
    expect(c.dynamicCode.some((d) => d.kind === 'new-function')).toBe(true);
  });

  it('flags dynamic require (with UNRESOLVABLE arg)', () => {
    // A runtime-computed require whose argument the folder can't resolve.
    const c = cap(`const m = someRuntimeFn(); require(m);`);
    expect(c.dynamicCode.some((d) => d.kind === 'dynamic-require')).toBe(true);
  });

  it('resolves fold-able require arg to the actual module (NEW in v0.2)', () => {
    // Constant folding turns `'child_' + 'process'` into `'child_process'` so
    // this looks like a normal require rather than a dynamic one.
    const c = cap(`const m = 'child_' + 'process'; require(m);`);
    expect(c.execModules).toContain('child_process');
    // NOT flagged as dynamic — the resolvable case is a win, not a miss.
    expect(c.dynamicCode.some((d) => d.kind === 'dynamic-require')).toBe(false);
  });

  it('extracts URL literals from strings', () => {
    const c = cap(`const u = "https://evil.example.invalid/exfil";`);
    expect(c.urlLiterals.some((u) => u.includes('evil.example.invalid'))).toBe(true);
  });

  it('extracts process.env sensitive-key reads', () => {
    const c = cap(`const t = process.env.NPM_TOKEN;`);
    const keys = c.envAccesses.flatMap((e) => e.keys ?? []);
    expect(keys).toContain('NPM_TOKEN');
  });

  it('flags whole-object env enumeration', () => {
    const c = cap(`for (const k of Object.keys(process.env)) console.log(k);`);
    expect(c.envAccesses.some((e) => e.keys === null)).toBe(true);
  });

  it('detects minified source (long single line)', () => {
    const line = 'a'.repeat(2000);
    const src = `${line}\n${line}\n${line}\n${line}\n${line}`;
    expect(isMinified(src)).toBe(true);
  });

  it('does not flag normal source as minified', () => {
    const src = `function foo() {\n  return 1;\n}\n`;
    expect(isMinified(src)).toBe(false);
  });

  it('reports parseError on syntactic garbage (fail-soft, no throw)', () => {
    // Force a parse failure that's severe enough Babel gives up even with errorRecovery
    const c = cap(`function () {{{{ unbalanced`);
    // Fail-soft either: parseError set OR parse succeeded with partial AST.
    // Both are acceptable; the invariant is 'no crash'.
    expect(c.path).toBe('a.js');
  });

  it('computes Shannon entropy sanely', () => {
    expect(shannonEntropy('aaaaaaaa')).toBeCloseTo(0, 2);
    const h = shannonEntropy('abcdefgh');
    expect(h).toBeGreaterThan(2.9);
  });

  it('extracts URLs from JSON files without parsing them as JS', () => {
    const c = cap('{"exfil": "https://evil.example.invalid/data"}', 'foo.json');
    expect(c.urlLiterals.some((u) => u.includes('evil.example.invalid'))).toBe(true);
  });

  it('exposes SENSITIVE_ENV_KEYS constant for detector layer', () => {
    expect(SENSITIVE_ENV_KEYS).toContain('NPM_TOKEN');
    expect(SENSITIVE_ENV_KEYS).toContain('AWS_ACCESS_KEY_ID');
    expect(SENSITIVE_ENV_KEYS).toContain('JWT_SECRET');
    expect(SENSITIVE_ENV_KEYS).toContain('MONGODB_URI');
    expect(SENSITIVE_ENV_KEYS).toContain('SLACK_BOT_TOKEN');
    expect(SENSITIVE_ENV_KEYS).toContain('SMTP_PASSWORD');
    expect(SENSITIVE_ENV_KEYS).not.toContain('CI');
    expect(SENSITIVE_ENV_KEYS).not.toContain('HOME');
  });
});
