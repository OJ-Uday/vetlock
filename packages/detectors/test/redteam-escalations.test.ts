/**
 * REDTEAM D4, D5, S5, S8, L9 FIX: regression tests for the broadened escalation gates.
 *
 * These tests were written BEFORE the fix and must fail against the old code,
 * then pass after. Each describe block maps to one exploit ID.
 */

import { describe, it, expect } from 'vitest';
import { runAll } from '../src/index.js';
import { mkSnap, mkFile } from './helpers.js';

// ---------------------------------------------------------------------------
// L9 — OBF/WARN does not escalate when only EXEC/ENV/FS co-occur (no NET/INSTALL)
// Fix: rule 1 broadened to include EXEC, ENV, FS in the risky set.
// ---------------------------------------------------------------------------
describe('L9 — OBF escalation when co-occurring with EXEC/ENV/FS (no NET/INSTALL)', () => {
  it('escalates OBF/WARN to BLOCK when package has EXEC finding (child_process)', () => {
    // Package that ships OBF (entropy jump) + EXEC (child_process) + no NET/INSTALL
    const pair = {
      old: mkSnap({
        name: 'evil-l9',
        version: '1.0.0',
        files: [mkFile({ path: 'lib/util.min.js', entropy: 2.5, minified: false })],
      }),
      new: mkSnap({
        name: 'evil-l9',
        version: '1.0.1',
        files: [
          mkFile({
            path: 'lib/util.min.js',
            entropy: 6.0,
            minified: true,
            execModules: ['child_process'],
          }),
        ],
      }),
    };
    const findings = runAll(pair);
    const obf = findings.find((f) => f.category === 'OBF');
    expect(obf).toBeDefined();
    expect(obf!.severity).toBe('BLOCK');
    expect(obf!.message).toMatch(/escalated/);
  });

  it('escalates OBF/WARN to BLOCK when package has ENV finding (token harvest)', () => {
    const pair = {
      old: mkSnap({
        name: 'evil-l9-env',
        version: '1.0.0',
        files: [mkFile({ path: 'index.js', entropy: 2.0, minified: false })],
      }),
      new: mkSnap({
        name: 'evil-l9-env',
        version: '1.0.1',
        files: [
          mkFile({
            path: 'index.js',
            entropy: 6.2,
            minified: true,
            envAccesses: [{ line: 3, keys: ['NPM_TOKEN'], snippet: 'process.env.NPM_TOKEN' }],
          }),
        ],
      }),
    };
    const findings = runAll(pair);
    const obf = findings.find((f) => f.category === 'OBF');
    expect(obf).toBeDefined();
    expect(obf!.severity).toBe('BLOCK');
    expect(obf!.message).toMatch(/escalated/);
  });

  it('escalates OBF/WARN to BLOCK when package has FS hotpath-write finding', () => {
    const pair = {
      old: mkSnap({
        name: 'evil-l9-fs',
        version: '1.0.0',
        files: [mkFile({ path: 'lib/a.js', entropy: 2.0, minified: false })],
      }),
      new: mkSnap({
        name: 'evil-l9-fs',
        version: '1.0.1',
        files: [
          mkFile({
            path: 'lib/a.js',
            entropy: 6.5,
            minified: true,
            fsWriteTargets: ['/root/.npmrc'],
          }),
        ],
      }),
    };
    const findings = runAll(pair);
    const obf = findings.find((f) => f.category === 'OBF');
    expect(obf).toBeDefined();
    expect(obf!.severity).toBe('BLOCK');
    expect(obf!.message).toMatch(/escalated/);
  });
});

// ---------------------------------------------------------------------------
// S8 — OBF paired with EXEC BLOCK (child_process + .npmrc read) but no NET/INSTALL
// Fix: same as L9 — rule 1 broadened.
// ---------------------------------------------------------------------------
describe('S8 — OBF escalation when co-occurring with EXEC/FS BLOCK findings', () => {
  it('escalates OBF/WARN to BLOCK when package has both EXEC and FS BLOCK findings', () => {
    // Fixture: entropy jump in lib/util.min.js + new child_process + hotpath fs-write
    const pair = {
      old: mkSnap({
        name: 'evil-s8',
        version: '1.0.0',
        files: [
          mkFile({ path: 'lib/util.min.js', entropy: 2.1, minified: false }),
        ],
      }),
      new: mkSnap({
        name: 'evil-s8',
        version: '1.0.1',
        files: [
          mkFile({
            path: 'lib/util.min.js',
            entropy: 5.8,
            minified: true,
            execModules: ['child_process'],
            fsReadTargets: ['~/.npmrc'],
          }),
        ],
      }),
    };
    const findings = runAll(pair);
    const obf = findings.find((f) => f.category === 'OBF');
    expect(obf).toBeDefined();
    expect(obf!.severity).toBe('BLOCK');
    expect(obf!.message).toMatch(/escalated/);
  });
});

// ---------------------------------------------------------------------------
// D5 — Typosquat + WARN-tier NET only (no BLOCK-tier cap) → stays WARN under old rule
// Fix: rule 2 also escalates when package has 2+ WARN findings across 2+ categories.
// ---------------------------------------------------------------------------
describe('D5 — typosquat escalation on 2+ WARN-tier findings across 2+ categories', () => {
  it('escalates typosquat to BLOCK when co-occurring with a WARN-tier NET finding', () => {
    // "axoiss" is edit-distance-1 from "axios" → typosquat WARN fires.
    // net.new-module (WARN, not BLOCK) also fires (require('https') added).
    // Old rule: no BLOCK-tier NET/INSTALL → no escalation.
    // New rule: 2 WARN findings across 2 distinct categories (DEPS + NET) → escalate.
    const pair = {
      old: null,
      new: mkSnap({
        name: 'axoiss',
        version: '1.0.0',
        files: [
          mkFile({
            path: 'lib/index.js',
            networkModules: ['https'],
          }),
        ],
      }),
    };
    const findings = runAll(pair);
    const typosquat = findings.find((f) => f.detector === 'deps.typosquat-candidate');
    expect(typosquat).toBeDefined();
    expect(typosquat!.severity).toBe('BLOCK');
    expect(typosquat!.message).toMatch(/escalated/);
  });

  it('escalates typosquat to BLOCK when co-occurring with code.dynamic-loading-added WARN', () => {
    // "expresss" is edit-distance-1 from "express".
    // Adds dynamic code (eval) → code.dynamic-loading-added WARN.
    // 2 WARN findings across 2 categories (DEPS + CODE) → escalate.
    const pair = {
      old: null,
      new: mkSnap({
        name: 'expresss',
        version: '1.0.0',
        files: [
          mkFile({
            path: 'index.js',
            dynamicCode: [{ line: 5, kind: 'eval', snippet: 'eval("...")' }],
          }),
        ],
      }),
    };
    const findings = runAll(pair);
    const typosquat = findings.find((f) => f.detector === 'deps.typosquat-candidate');
    expect(typosquat).toBeDefined();
    expect(typosquat!.severity).toBe('BLOCK');
    expect(typosquat!.message).toMatch(/escalated/);
  });

  it('does NOT escalate a typosquat that has ONLY the DEPS warning (no co-occurring signals)', () => {
    // "lodahs" is edit-distance-1 from "lodash" → typosquat WARN fires.
    // No capability signals → only 1 WARN finding → no escalation.
    const pair = {
      old: null,
      new: mkSnap({
        name: 'lodahs',
        version: '1.0.0',
        files: [mkFile({ path: 'index.js' })],
      }),
    };
    const findings = runAll(pair);
    const typosquat = findings.find((f) => f.detector === 'deps.typosquat-candidate');
    expect(typosquat).toBeDefined();
    expect(typosquat!.severity).toBe('WARN');
  });
});

describe('v0.6.0 FP regressions', () => {
  it('does NOT escalate OBF when the only CODE finding is dynamic-import', () => {
    const pair = {
      old: mkSnap({
        name: 'vite-like',
        version: '1.0.0',
        files: [mkFile({ path: 'dist/index.mjs', entropy: 2.8, minified: false })],
      }),
      new: mkSnap({
        name: 'vite-like',
        version: '1.0.1',
        files: [
          mkFile({
            path: 'dist/index.mjs',
            entropy: 6.1,
            minified: true,
            dynamicCode: [{ line: 10, kind: 'dynamic-import', snippet: 'await import(x)' }],
          }),
        ],
      }),
    };
    const findings = runAll(pair);
    const obf = findings.find((f) => f.category === 'OBF');
    const code = findings.find((f) => f.detector === 'code.dynamic-loading-added');
    expect(obf).toBeDefined();
    expect(code).toBeDefined();
    expect(obf!.severity).toBe('WARN');
    expect(obf!.message).not.toMatch(/escalated/);
    expect(code!.severity).toBe('INFO');
  });

  it('still escalates OBF when the co-occurring CODE finding is eval', () => {
    const pair = {
      old: mkSnap({
        name: 'evil-eval',
        version: '1.0.0',
        files: [mkFile({ path: 'dist/index.js', entropy: 2.7, minified: false })],
      }),
      new: mkSnap({
        name: 'evil-eval',
        version: '1.0.1',
        files: [
          mkFile({
            path: 'dist/index.js',
            entropy: 6.2,
            minified: true,
            dynamicCode: [{ line: 4, kind: 'eval', snippet: 'eval(payload)' }],
          }),
        ],
      }),
    };
    const findings = runAll(pair);
    const obf = findings.find((f) => f.category === 'OBF');
    const code = findings.find((f) => f.detector === 'code.dynamic-loading-added');
    expect(obf).toBeDefined();
    expect(code).toBeDefined();
    expect(obf!.severity).toBe('BLOCK');
    expect(obf!.message).toMatch(/escalated/);
    expect(code!.severity).toBe('WARN');
  });

  it('does NOT escalate NET literal + CODE dynamic-import to BLOCK', () => {
    const pair = {
      old: mkSnap({
        name: 'config-only',
        version: '1.0.0',
        files: [mkFile({ path: 'index.js' })],
      }),
      new: mkSnap({
        name: 'config-only',
        version: '1.0.1',
        files: [
          mkFile({
            path: 'index.js',
            urlLiterals: ['https://docs.example.com/faq'],
            urlLiteralContexts: { 'https://docs.example.com/faq': 'literal' },
            dynamicCode: [{ line: 9, kind: 'dynamic-import', snippet: 'await import("./chunk.js")' }],
          }),
        ],
      }),
    };
    const findings = runAll(pair);
    const net = findings.find((f) => f.detector === 'net.new-endpoint');
    const code = findings.find((f) => f.detector === 'code.dynamic-loading-added');
    expect(net).toBeDefined();
    expect(code).toBeDefined();
    expect(net!.severity).toBe('INFO');
    expect(code!.severity).toBe('INFO');
    expect(findings.some((f) => f.severity === 'BLOCK')).toBe(false);
  });

  it('still yields a BLOCK verdict for NET network-arg + ENV attack shapes', () => {
    const pair = {
      old: mkSnap({
        name: 'evil-env',
        version: '1.0.0',
        files: [mkFile({ path: 'index.js' })],
      }),
      new: mkSnap({
        name: 'evil-env',
        version: '1.0.1',
        files: [
          mkFile({
            path: 'index.js',
            urlLiterals: ['https://exfil.attacker.invalid/data'],
            urlLiteralContexts: { 'https://exfil.attacker.invalid/data': 'network-arg' },
            envAccesses: [{ line: 2, keys: ['JWT_SECRET'], snippet: 'process.env.JWT_SECRET' }],
          }),
        ],
      }),
    };
    const findings = runAll(pair);
    const net = findings.find((f) => f.detector === 'net.new-endpoint');
    const env = findings.find((f) => f.detector === 'env.token-harvest');
    expect(net).toBeDefined();
    expect(env).toBeDefined();
    expect(net!.severity).toBe('WARN');
    expect(env!.severity).toBe('BLOCK');
    expect(findings.some((f) => f.severity === 'BLOCK')).toBe(true);
  });

  it('preserves deps.first-version-cluster for first-install secret-exfil shapes', () => {
    const pair = {
      old: null,
      new: mkSnap({
        name: 'aiocpa-like',
        version: '0.1.0',
        files: [
          mkFile({
            path: 'index.js',
            networkModules: ['https'],
            urlLiterals: ['https://harvest.attacker.invalid/wallets'],
            envAccesses: [
              { line: 1, keys: ['MNEMONIC'], snippet: 'process.env.MNEMONIC' },
              { line: 2, keys: ['PRIVATE_KEY'], snippet: 'process.env.PRIVATE_KEY' },
              { line: 3, keys: null, snippet: 'Object.assign({}, process.env)' },
            ],
          }),
        ],
      }),
    };
    const findings = runAll(pair);
    const cluster = findings.find((f) => f.detector === 'deps.first-version-cluster');
    expect(cluster).toBeDefined();
    expect(cluster!.severity).toBe('BLOCK');
    expect(cluster!.category).toBe('DEPS');
  });
});
