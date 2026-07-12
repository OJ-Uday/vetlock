/**
 * Regression tests for red-team confirmed exploits D2 and D3.
 *
 * These are locked-in reproductions of specific attacks documented in
 * docs/REDTEAM-2026-07-12.md. If a future refactor loosens the schema or
 * changes .includes/.startsWith semantics, these tests must catch it.
 *
 * @security-critical
 */

import { describe, it, expect } from 'vitest';
import { parseConfig, applyConfig, ConfigError } from '../src/config.js';
import type { Finding } from '../src/finding.js';

const FAKE_FINDING: Finding = {
  detector: 'install.script-added',
  category: 'INSTALL',
  package: 'attacker-pkg',
  from: '1.0.0',
  to: '1.0.1',
  direction: 'changed',
  severity: 'BLOCK',
  confidence: 'high',
  message: 'Lifecycle script postinstall was added.',
  evidence: [{ file: 'package.json', line: 1, snippet: 'postinstall: node evil.js' }],
  provenance: [],
};

describe('REDTEAM D2: ignorePathsInside empty-string bypass', () => {
  it('rejects an ignorePathsInside entry with empty-string prefix', () => {
    // The exact fixture from the report:
    const attackerConfig = JSON.stringify({
      version: 1,
      ignorePathsInside: {
        'legit-pkg-1': ['test/', 'examples/'],
        'legit-pkg-2': ['docs/'],
        'attacker-pkg': [''], // ← the exploit
      },
    });
    expect(() => parseConfig(attackerConfig)).toThrow(ConfigError);
  });

  it('rejects an ignorePathsInside entry with whitespace-only prefix', () => {
    const attackerConfig = JSON.stringify({
      version: 1,
      ignorePathsInside: { foo: ['   '] },
    });
    expect(() => parseConfig(attackerConfig)).toThrow(ConfigError);
  });

  it('rejects prefixes shorter than 3 characters', () => {
    const attackerConfig = JSON.stringify({
      version: 1,
      ignorePathsInside: { foo: ['a'] },
    });
    expect(() => parseConfig(attackerConfig)).toThrow(ConfigError);
  });

  it('accepts a legitimate prefix', () => {
    const cfg = parseConfig(JSON.stringify({
      version: 1,
      ignorePathsInside: { foo: ['test/', 'examples/'] },
    }));
    expect(cfg.ignorePathsInside.foo).toEqual(['test/', 'examples/']);
  });

  it('applyConfig no longer drops findings when an empty-prefix config sneaks through', () => {
    // Even if a malformed config were somehow constructed at runtime,
    // applyConfig must be defensive too.
    // TypeScript won't stop us building this object; check runtime behaviour.
    const config = {
      version: 1,
      allowlist: {},
      severityOverride: {},
      ignorePackages: [],
      ignorePathsInside: { 'attacker-pkg': [''] },
      trustedPublishers: {},
      failOn: [],
    } as const;
    const result = applyConfig([FAKE_FINDING], config);
    // The finding MUST survive — an empty-prefix should not drop anything.
    expect(result).toHaveLength(1);
    expect(result[0]!.severity).toBe('BLOCK');
  });
});

describe('REDTEAM D3: trustedPublishers empty-string downgrade', () => {
  it('rejects a trustedPublishers list containing empty string', () => {
    // Exact fixture from the report:
    const attackerConfig = JSON.stringify({
      version: 1,
      trustedPublishers: { chalk: [''] },
    });
    expect(() => parseConfig(attackerConfig)).toThrow(ConfigError);
  });

  it('rejects a trustedPublishers list containing 1-char string', () => {
    const attackerConfig = JSON.stringify({
      version: 1,
      trustedPublishers: { chalk: ['a'] },
    });
    expect(() => parseConfig(attackerConfig)).toThrow(ConfigError);
  });

  it('accepts a legitimate trustedPublishers entry', () => {
    const cfg = parseConfig(JSON.stringify({
      version: 1,
      trustedPublishers: { chalk: ['sindresorhus@example.com'] },
    }));
    expect(cfg.trustedPublishers.chalk).toEqual(['sindresorhus@example.com']);
  });

  it('applyConfig no longer downgrades BLOCK meta findings on runtime empty-string trust', () => {
    // Same defensive check for runtime-constructed configs
    const finding: Finding = {
      ...FAKE_FINDING,
      detector: 'meta.maintainer-change',
      category: 'META',
      package: 'chalk',
      message: 'Publisher/maintainer set changed between versions.',
      evidence: [{ file: 'package.json', line: 1, snippet: 'maintainers: [random@evil.com]' }],
    };
    const config = {
      version: 1,
      allowlist: {},
      severityOverride: {},
      ignorePackages: [],
      ignorePathsInside: {},
      trustedPublishers: { chalk: [''] },
      failOn: [],
    } as const;
    const result = applyConfig([finding], config);
    // Must NOT be downgraded to INFO — an empty trust anchor is not a trust anchor.
    expect(result).toHaveLength(1);
    expect(result[0]!.severity).toBe('BLOCK');
  });
});

describe('REDTEAM: config schema hardening covers all string-value fields', () => {
  it('rejects failOn entries under 3 chars', () => {
    const bad = JSON.stringify({ version: 1, failOn: [''] });
    expect(() => parseConfig(bad)).toThrow(ConfigError);
  });

  it('rejects severityOverride keys under 3 chars', () => {
    const bad = JSON.stringify({ version: 1, severityOverride: { '': 'INFO' } });
    expect(() => parseConfig(bad)).toThrow(ConfigError);
  });
});
