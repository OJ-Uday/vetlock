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

// ---------------------------------------------------------------------------
// D4 — Compound rule: exactly 2 findings across 2 categories stays WARN under old rule
// Fix: rule 3 now escalates on (warns.length >= 2 && cats.size >= 2 && security-relevant).
// ---------------------------------------------------------------------------
describe('D4 — compound-suspicion: 2 WARN findings across 2 security-relevant categories', () => {
  it('escalates both findings to BLOCK: net.new-module (NET) + code.dynamic-loading-added (CODE)', () => {
    // Old rule requires warns.length >= 3. New rule: 2+ across 2+ with security-relevant cat.
    const pair = {
      old: mkSnap({
        name: 'evil-d4',
        version: '1.0.0',
        files: [mkFile({ path: 'index.js' })],
      }),
      new: mkSnap({
        name: 'evil-d4',
        version: '1.0.1',
        files: [
          mkFile({
            path: 'index.js',
            networkModules: ['https'],
            dynamicCode: [{ line: 5, kind: 'eval', snippet: 'eval("...")' }],
          }),
        ],
      }),
    };
    const findings = runAll(pair);
    const netFinding = findings.find((f) => f.detector === 'net.new-module');
    const codeFinding = findings.find((f) => f.detector === 'code.dynamic-loading-added');
    expect(netFinding).toBeDefined();
    expect(codeFinding).toBeDefined();
    expect(netFinding!.severity).toBe('BLOCK');
    expect(codeFinding!.severity).toBe('BLOCK');
    expect(netFinding!.message).toMatch(/escalated/);
    expect(codeFinding!.message).toMatch(/escalated/);
  });
});

// ---------------------------------------------------------------------------
// S5 — Compound rule: exactly 4 WARN findings all in NET category stays WARN under old rule
// Fix: rule 3 now escalates on warns.length >= 3 regardless of category count.
// ---------------------------------------------------------------------------
describe('S5 — compound-suspicion: 4 net.new-endpoint WARN findings (single NET category)', () => {
  it('escalates all 4 findings to BLOCK when warns.length >= 3 in single category', () => {
    // 4 separate URL literals each emitting net.new-endpoint WARN.
    // Old rule: cats.size == 1 (only NET) → no escalation.
    // New rule: warns.length >= 3 → escalate regardless of category count.
    const pair = {
      old: mkSnap({
        name: 'evil-s5',
        version: '1.0.0',
        files: [mkFile({ path: 'index.js', urlLiterals: [] })],
      }),
      new: mkSnap({
        name: 'evil-s5',
        version: '1.0.1',
        files: [
          mkFile({
            path: 'index.js',
            // net.new-endpoint fires BLOCK not WARN — so we need to use net.new-module
            // style signals. Actually net.new-endpoint is BLOCK so it won't be in warns.
            // Use obf findings (which are WARN) spread across 4 files to hit warns >= 3.
            // But the fixture spec says 4 net.new-endpoint findings. Let's check: net.new-endpoint
            // fires as BLOCK (detectors.test.ts line 87). So 4 BLOCK findings won't be in warns.
            // The exploit desc says attacker ships "4 net.new-endpoint on 4 URLs" — but if
            // net.new-endpoint is BLOCK they already escalate. The real evasion shape is:
            // 4 obf.entropy-jump WARN across 4 files in a single OBF category.
            // We use obf (4 files) to produce warns.length=4, cats.size=1.
          }),
          mkFile({ path: 'lib/a.min.js', entropy: 6.0, minified: true }),
          mkFile({ path: 'lib/b.min.js', entropy: 6.1, minified: true }),
          mkFile({ path: 'lib/c.min.js', entropy: 6.2, minified: true }),
          mkFile({ path: 'lib/d.min.js', entropy: 6.3, minified: true }),
        ],
      }),
    };
    // "old" needs corresponding files so obf can detect a delta
    const oldPair = {
      old: mkSnap({
        name: 'evil-s5',
        version: '1.0.0',
        files: [
          mkFile({ path: 'index.js' }),
          mkFile({ path: 'lib/a.min.js', entropy: 2.0, minified: false }),
          mkFile({ path: 'lib/b.min.js', entropy: 2.0, minified: false }),
          mkFile({ path: 'lib/c.min.js', entropy: 2.0, minified: false }),
          mkFile({ path: 'lib/d.min.js', entropy: 2.0, minified: false }),
        ],
      }),
      new: mkSnap({
        name: 'evil-s5',
        version: '1.0.1',
        files: [
          mkFile({ path: 'index.js' }),
          mkFile({ path: 'lib/a.min.js', entropy: 6.0, minified: true }),
          mkFile({ path: 'lib/b.min.js', entropy: 6.1, minified: true }),
          mkFile({ path: 'lib/c.min.js', entropy: 6.2, minified: true }),
          mkFile({ path: 'lib/d.min.js', entropy: 6.3, minified: true }),
        ],
      }),
    };
    const findings = runAll(oldPair);
    const obfFindings = findings.filter((f) => f.category === 'OBF');
    // At least 3 OBF findings (one per obfuscated file), all in one category.
    expect(obfFindings.length).toBeGreaterThanOrEqual(3);
    for (const f of obfFindings) {
      expect(f.severity).toBe('BLOCK');
      expect(f.message).toMatch(/escalated/);
    }
  });
});
