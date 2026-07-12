import { describe, it, expect } from 'vitest';
import { validateFinding } from '@vetlock/core';
import { runAll, firstVersionClusterDetector } from '../src/index.js';
import { mkSnap, mkFile } from './helpers.js';

describe('first-version-cluster detector', () => {
  it('fires on an ADDED package with 3+ capability categories', () => {
    const pair = {
      old: null,
      new: mkSnap({
        name: 'evil-first-version',
        version: '1.0.0',
        files: [
          mkFile({
            path: 'index.js',
            networkModules: ['https'],
            execModules: ['child_process'],
            envAccesses: [{ line: 1, keys: ['NPM_TOKEN'], snippet: 'process.env.NPM_TOKEN' }],
          }),
        ],
      }),
    };
    const findings = firstVersionClusterDetector.run(pair, { direction: 'added' });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('BLOCK');
    expect(findings[0]!.category).toBe('DEPS');
    expect(findings[0]!.detector).toBe('deps.first-version-cluster');
    expect(validateFinding(findings[0]!)).toBeNull();
  });

  it('does not fire on an UPGRADED package (pair.old present)', () => {
    const pair = {
      old: mkSnap({
        name: 'foo', version: '1.0.0',
        files: [mkFile({ path: 'index.js', networkModules: ['https'] })],
      }),
      new: mkSnap({
        name: 'foo', version: '1.0.1',
        files: [
          mkFile({
            path: 'index.js',
            networkModules: ['https'],
            execModules: ['child_process'],
            envAccesses: [{ line: 1, keys: ['NPM_TOKEN'], snippet: 'x' }],
          }),
        ],
      }),
    };
    expect(firstVersionClusterDetector.run(pair, { direction: 'changed' })).toHaveLength(0);
  });

  it('does not fire when the package has only 1-2 categories', () => {
    const pair = {
      old: null,
      new: mkSnap({
        name: 'legit-lib', version: '1.0.0',
        files: [mkFile({ path: 'index.js', networkModules: ['https'] })],
      }),
    };
    expect(firstVersionClusterDetector.run(pair, { direction: 'added' })).toHaveLength(0);
  });
});

describe('compound-suspicion escalation (runAll)', () => {
  it('promotes WARN findings to BLOCK when a package has 3+ WARN across 2+ categories', () => {
    // Craft a pair that produces exactly:
    //   - meta.maintainer-change (META, WARN)
    //   - net.new-module (NET, WARN)
    //   - code.dynamic-loading-added (CODE, WARN)
    // All 3 WARN, 3 categories, same package → all should escalate to BLOCK.
    const pair = {
      old: mkSnap({
        name: 'suspect',
        version: '1.0.0',
        manifest: { name: 'suspect', version: '1.0.0', maintainers: [{ email: 'orig@ex.com' }] },
        files: [mkFile({ path: 'i.js' })],
      }),
      new: mkSnap({
        name: 'suspect',
        version: '1.0.1',
        manifest: { name: 'suspect', version: '1.0.1', maintainers: [{ email: 'new@ex.com' }] },
        files: [
          mkFile({
            path: 'i.js',
            networkModules: ['https'],
            dynamicCode: [{ line: 5, kind: 'eval', snippet: 'eval("...")' }],
          }),
        ],
      }),
    };
    const findings = runAll(pair);
    // The 3 originally-WARN findings should now be BLOCK.
    const escalated = findings.filter((f) =>
      ['meta.maintainer-change', 'net.new-module', 'code.dynamic-loading-added'].includes(f.detector),
    );
    expect(escalated.length).toBeGreaterThanOrEqual(3);
    for (const f of escalated) {
      expect(f.severity).toBe('BLOCK');
      expect(f.message).toMatch(/escalated/);
    }
  });

  it('does NOT escalate when only 1 WARN finding (below threshold)', () => {
    // A single WARN finding can never trigger compound-suspicion (needs 2+).
    const pair = {
      old: mkSnap({
        name: 'benign',
        version: '1.0.0',
        manifest: { name: 'benign', version: '1.0.0', maintainers: [{ email: 'orig@ex.com' }] },
        files: [mkFile({ path: 'i.js' })],
      }),
      new: mkSnap({
        name: 'benign',
        version: '1.0.1',
        // Only maintainer-change fires (META/WARN). No capability changes → no NET/CODE/etc.
        manifest: { name: 'benign', version: '1.0.1', maintainers: [{ email: 'new@ex.com' }] },
        files: [mkFile({ path: 'i.js' })],
      }),
    };
    const findings = runAll(pair);
    const stillWarn = findings.filter((f) => f.severity === 'WARN');
    expect(stillWarn.length).toBeGreaterThan(0);
    for (const w of stillWarn) {
      expect(w.message).not.toMatch(/\[escalated: package/);
    }
  });

  it('DOES escalate 3+ WARN findings in the SAME category (single-category saturation — REDTEAM S5, D4)', () => {
    // Under the new rule 3a, warns.length >= 3 is sufficient to escalate regardless
    // of category count. 3 code.dynamic-loading-added findings (all CODE) must escalate
    // because 3 dynamic-eval calls across a diff is compound suspicious even in isolation.
    const pair = {
      old: mkSnap({
        name: 'code-heavy',
        version: '1.0.0',
        files: [mkFile({ path: 'i.js' })],
      }),
      new: mkSnap({
        name: 'code-heavy',
        version: '1.0.1',
        files: [
          mkFile({
            path: 'i.js',
            dynamicCode: [
              { line: 1, kind: 'eval', snippet: 'eval("a")' },
              { line: 2, kind: 'eval', snippet: 'eval("b")' },
              { line: 3, kind: 'eval', snippet: 'eval("c")' },
            ],
          }),
        ],
      }),
    };
    const findings = runAll(pair);
    const codeFindings = findings.filter((f) => f.category === 'CODE');
    // All 3 should now be BLOCK — compound-suspicion escalates on 3+ WARN regardless of category.
    expect(codeFindings.length).toBeGreaterThanOrEqual(3);
    for (const f of codeFindings) {
      expect(f.severity).toBe('BLOCK');
      expect(f.message).toMatch(/escalated/);
    }
  });
});
