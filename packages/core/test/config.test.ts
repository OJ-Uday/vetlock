import { describe, it, expect } from 'vitest';
import type { Finding } from '@vetlock/core';
import { parseConfig, applyConfig, isForcedFailure, ConfigError, DEFAULT_CONFIG } from '../src/config.js';

function fakeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    detector: 'net.new-endpoint',
    category: 'NET',
    package: 'axios',
    from: '1.0.0',
    to: '1.0.1',
    direction: 'changed',
    severity: 'BLOCK',
    confidence: 'high',
    message: 'test finding',
    evidence: [{ file: 'index.js', line: 1, snippet: 'test' }],
    provenance: [],
    ...overrides,
  };
}

describe('parseConfig', () => {
  it('parses a valid config', () => {
    const cfg = parseConfig(JSON.stringify({
      version: 1,
      allowlist: { axios: ['NET'] },
    }));
    expect(cfg.allowlist.axios).toEqual(['NET']);
  });

  it('applies defaults to missing fields', () => {
    const cfg = parseConfig('{}');
    expect(cfg.version).toBe(1);
    expect(cfg.allowlist).toEqual({});
    expect(cfg.failOn).toEqual([]);
  });

  it('rejects unknown top-level fields (strict mode)', () => {
    expect(() =>
      parseConfig(JSON.stringify({ unknown: true })),
    ).toThrow(ConfigError);
  });

  it('rejects invalid severity in override', () => {
    expect(() =>
      parseConfig(JSON.stringify({ severityOverride: { foo: 'MAYBE' } })),
    ).toThrow(ConfigError);
  });

  it('rejects invalid category in allowlist', () => {
    expect(() =>
      parseConfig(JSON.stringify({ allowlist: { pkg: ['MAGIC'] } })),
    ).toThrow(ConfigError);
  });

  it('rejects malformed JSON with a clear message', () => {
    expect(() => parseConfig('{not json}')).toThrow(ConfigError);
  });
});

describe('applyConfig', () => {
  it('downgrades a whitelisted category finding to INFO', () => {
    const cfg = { ...DEFAULT_CONFIG, allowlist: { axios: ['NET'] as const } };
    const out = applyConfig([fakeFinding()], cfg);
    expect(out[0]!.severity).toBe('INFO');
    expect(out[0]!.message).toMatch(/allowlisted/);
  });

  it('applies a per-detector severity override', () => {
    const cfg = { ...DEFAULT_CONFIG, severityOverride: { 'net.new-endpoint': 'WARN' as const } };
    const out = applyConfig([fakeFinding()], cfg);
    expect(out[0]!.severity).toBe('WARN');
  });

  it('drops findings for ignored packages', () => {
    const cfg = { ...DEFAULT_CONFIG, ignorePackages: ['axios'] };
    const out = applyConfig([fakeFinding()], cfg);
    expect(out).toHaveLength(0);
  });

  it('drops findings under ignore-paths-inside', () => {
    const cfg = { ...DEFAULT_CONFIG, ignorePathsInside: { axios: ['test/'] } };
    const out = applyConfig(
      [fakeFinding({ evidence: [{ file: 'test/main.js', line: 1, snippet: '' }] })],
      cfg,
    );
    expect(out).toHaveLength(0);
  });

  it('downgrades maintainer-change when publisher is on trust list', () => {
    const cfg = { ...DEFAULT_CONFIG, trustedPublishers: { axios: ['team@axios.example'] } };
    const finding = fakeFinding({
      detector: 'meta.maintainer-change',
      category: 'META',
      severity: 'WARN',
      evidence: [{ file: 'package.json', line: 1, snippet: 'maintainers: [prev@ex.com] → [team@axios.example]' }],
    });
    const out = applyConfig([finding], cfg);
    expect(out[0]!.severity).toBe('INFO');
    expect(out[0]!.message).toMatch(/trusted/);
  });
});

describe('isForcedFailure', () => {
  it('true when any finding is on the failOn list', () => {
    const cfg = { ...DEFAULT_CONFIG, failOn: ['net.new-endpoint'] };
    expect(isForcedFailure([fakeFinding()], cfg)).toBe(true);
  });

  it('false when no finding is on the failOn list', () => {
    const cfg = { ...DEFAULT_CONFIG, failOn: ['env.token-harvest'] };
    expect(isForcedFailure([fakeFinding()], cfg)).toBe(false);
  });
});
