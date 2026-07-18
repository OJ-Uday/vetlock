/**
 * SARIF 2.1.0 output — audit §2.5 architectural borrow.
 *
 * These tests confirm the SARIF renderer at
 * packages/core/src/report/sarif.ts produces a document that:
 *   - has all mandatory SARIF top-level fields ($schema, version, runs)
 *   - carries at least tool.driver.name + rules[] + results[].{ruleId, level,
 *     message.text, locations[]}
 *   - maps severity → level correctly (BLOCK→error, WARN→warning, INFO→note)
 *   - emits mitre[] as a rule + result property
 *   - includes riskScore on the run's properties bag
 *
 * We do STRUCTURAL validation (mandatory fields present + shapes) rather than
 * a full JSON-schema pass because the workspace doesn't ship ajv. If ajv is
 * later added as a dev dep the switch to schema-based validation is
 * mechanical — the property paths asserted here are stable.
 */

import { describe, it, expect } from 'vitest';
import { toSarif } from '../src/report/sarif.js';
import type { RunResult } from '../src/engine.js';
import type { Finding } from '../src/finding.js';

function mkFinding(overrides: Partial<Finding> & { severity: Finding['severity'] }): Finding {
  return {
    detector: 'test.detector',
    category: 'META',
    package: 'evil',
    from: null,
    to: '1.0.0',
    direction: 'added',
    confidence: 'high',
    message: 'a message',
    evidence: [{ file: 'index.js', line: 5, snippet: 'const x = 1;' }],
    provenance: [['root', 'evil']],
    mitre: ['T1071.001', 'T1041'],
    ...overrides,
  };
}

function mkResult(findings: Finding[]): RunResult {
  return {
    verdict: 'BLOCK',
    findings,
    rollupByDirect: {},
    changes: [],
    errors: [],
    durationMs: 0,
    riskScore: 7.5,
  };
}

describe('SARIF 2.1.0 output (audit §2.5)', () => {
  it('emits a valid SARIF 2.1.0 top-level shape', () => {
    const sarifText = toSarif(mkResult([mkFinding({ severity: 'BLOCK' })]));
    const sarif = JSON.parse(sarifText);
    expect(sarif.$schema).toContain('sarif-schema-2.1.0');
    expect(sarif.version).toBe('2.1.0');
    expect(Array.isArray(sarif.runs)).toBe(true);
    expect(sarif.runs).toHaveLength(1);
  });

  it('run has a tool.driver with name and rules', () => {
    const sarifText = toSarif(mkResult([mkFinding({ severity: 'BLOCK' })]));
    const run = JSON.parse(sarifText).runs[0];
    expect(run.tool.driver.name).toBe('vetlock');
    expect(run.tool.driver.informationUri).toContain('github.com');
    expect(Array.isArray(run.tool.driver.rules)).toBe(true);
    expect(run.tool.driver.rules.length).toBeGreaterThan(0);
  });

  it('every result has a ruleId + level + message.text + at least one location', () => {
    const sarifText = toSarif(
      mkResult([
        mkFinding({ severity: 'BLOCK' }),
        mkFinding({ severity: 'WARN', detector: 'other', package: 'p2' }),
      ]),
    );
    const results = JSON.parse(sarifText).runs[0].results;
    for (const r of results) {
      expect(typeof r.ruleId).toBe('string');
      expect(typeof r.level).toBe('string');
      expect(typeof r.message.text).toBe('string');
      expect(Array.isArray(r.locations)).toBe(true);
      expect(r.locations.length).toBeGreaterThan(0);
      const loc = r.locations[0];
      expect(loc.physicalLocation.artifactLocation.uri).toBeTruthy();
      expect(loc.physicalLocation.region.startLine).toBeGreaterThan(0);
    }
  });

  it('BLOCK → error, WARN → warning, INFO → note (audit §2.5 level mapping)', () => {
    const sarifText = toSarif(
      mkResult([
        mkFinding({ severity: 'BLOCK', detector: 'b.one' }),
        mkFinding({ severity: 'WARN', detector: 'w.one' }),
        mkFinding({ severity: 'INFO', detector: 'i.one' }),
      ]),
    );
    const results = JSON.parse(sarifText).runs[0].results;
    const byRule = Object.fromEntries(results.map((r: { ruleId: string; level: string }) => [r.ruleId, r.level]));
    expect(byRule['b.one']).toBe('error');
    expect(byRule['w.one']).toBe('warning');
    expect(byRule['i.one']).toBe('note');
  });

  it('mitre techniques appear on rule.properties and result.properties', () => {
    const sarifText = toSarif(mkResult([mkFinding({ severity: 'BLOCK' })]));
    const run = JSON.parse(sarifText).runs[0];
    const rule = run.tool.driver.rules[0];
    expect(rule.properties.mitre).toEqual(['T1071.001', 'T1041']);
    const result = run.results[0];
    expect(result.properties.mitre).toEqual(['T1071.001', 'T1041']);
  });

  it('riskScore is present on the run.properties bag', () => {
    const sarifText = toSarif(mkResult([mkFinding({ severity: 'BLOCK' })]));
    const run = JSON.parse(sarifText).runs[0];
    expect(run.properties.riskScore).toBe(7.5);
    expect(run.properties.verdict).toBe('BLOCK');
  });

  it('rules deduplicate by detector id', () => {
    const sarifText = toSarif(
      mkResult([
        mkFinding({ severity: 'BLOCK', package: 'a' }),
        mkFinding({ severity: 'BLOCK', package: 'b' }),
        mkFinding({ severity: 'WARN', package: 'c' }),
      ]),
    );
    const rules = JSON.parse(sarifText).runs[0].tool.driver.rules;
    expect(rules).toHaveLength(1);
    expect(rules[0].id).toBe('test.detector');
  });

  it('empty findings produces a valid SARIF with empty results/rules', () => {
    const sarifText = toSarif(mkResult([]));
    const sarif = JSON.parse(sarifText);
    expect(sarif.runs[0].results).toEqual([]);
    expect(sarif.runs[0].tool.driver.rules).toEqual([]);
    expect(sarif.runs[0].properties.riskScore).toBe(7.5);
  });

  it('findings without mitre serialize an empty array on properties.mitre', () => {
    const f = mkFinding({ severity: 'WARN' });
    delete (f as { mitre?: readonly string[] }).mitre;
    const sarifText = toSarif(mkResult([f]));
    const result = JSON.parse(sarifText).runs[0].results[0];
    expect(result.properties.mitre).toEqual([]);
  });

  it('message.text includes package and version transition context', () => {
    const sarifText = toSarif(
      mkResult([mkFinding({ severity: 'BLOCK', package: 'chalk', from: '5.3.0', to: '5.3.1', direction: 'changed' })]),
    );
    const msg = JSON.parse(sarifText).runs[0].results[0].message.text;
    expect(msg).toContain('chalk');
    expect(msg).toContain('5.3.0');
    expect(msg).toContain('5.3.1');
  });

  it('respects driverName and driverVersion options', () => {
    const sarifText = toSarif(mkResult([mkFinding({ severity: 'BLOCK' })]), {
      driverName: 'vetlock-experimental',
      driverVersion: '9.9.9',
    });
    const driver = JSON.parse(sarifText).runs[0].tool.driver;
    expect(driver.name).toBe('vetlock-experimental');
    expect(driver.version).toBe('9.9.9');
  });

  it('pretty:false produces a compact single-line JSON', () => {
    const compact = toSarif(mkResult([mkFinding({ severity: 'BLOCK' })]), { pretty: false });
    // Compact form has no newlines (JSON.stringify without a spacer).
    expect(compact.includes('\n')).toBe(false);
    // Still parses back.
    expect(JSON.parse(compact).version).toBe('2.1.0');
  });
});
