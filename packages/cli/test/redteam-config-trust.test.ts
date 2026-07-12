/**
 * Regression tests for red-team confirmed exploits S2, C1, C2, and D1.
 *
 * The exploit family: an attacker who mutates package-lock.json in a PR can
 * also add a `.vetlock.json` in the SAME PR that silences every finding
 * against the poisoned lockfile.  The CLI must not trust a config that
 * appeared (or changed) inside the diff under review.
 *
 * These tests exercise the pure `decideConfigApplication()` decision function
 * so the trust boundary can be verified without spawning a git process.
 *
 * @security-critical
 */

import { describe, it, expect } from 'vitest';
import {
  parseConfig,
  applyConfig,
  decideConfigApplication,
  hashConfigText,
  DEFAULT_CONFIG,
  type Finding,
  type VetlockConfig,
} from '@vetlock/core';

/**
 * A BLOCK-tier finding shaped like what the engine emits for the malicious
 * ua-parser-js@0.7.29 (C1), a maintainer-change (C2), or a script-added (S2).
 * The `package` and `detector` fields vary per test; everything else is
 * identical realistic evidence.
 */
function fakeBlock(overrides: Partial<Finding> = {}): Finding {
  return {
    detector: 'install.script-added',
    category: 'INSTALL',
    package: 'attacker-pkg',
    from: null,
    to: '1.0.0',
    direction: 'added',
    severity: 'BLOCK',
    confidence: 'high',
    message: 'Lifecycle script postinstall was added.',
    evidence: [{ file: 'package.json', line: 1, snippet: 'postinstall: node evil.js' }],
    provenance: [],
    ...overrides,
  };
}

describe('REDTEAM S2 / C1 / C2 / D1: don\'t trust .vetlock.json from same diff', () => {
  describe('hashConfigText', () => {
    it('returns null for null input', () => {
      expect(hashConfigText(null)).toBeNull();
    });

    it('returns a stable sha256 hex for the same input', () => {
      const h1 = hashConfigText('{"version":1}');
      const h2 = hashConfigText('{"version":1}');
      expect(h1).not.toBeNull();
      expect(h1).toBe(h2);
      expect(h1).toMatch(/^[0-9a-f]{64}$/);
    });

    it('produces different hashes for different inputs', () => {
      expect(hashConfigText('{"version":1}')).not.toBe(hashConfigText('{"version":1} '));
    });
  });

  describe('S2 — ignorePackages in-diff → REJECT', () => {
    it('rejects a config whose ignorePackages was added in the PR', () => {
      const attackerConfigText = JSON.stringify({
        version: 1,
        ignorePackages: ['attacker-pkg'],
      });
      const parsed = parseConfig(attackerConfigText);

      const decision = decideConfigApplication(parsed, {
        currentText: attackerConfigText,
        baselineText: null, // file absent in baseline — newly added in this PR
      });

      expect(decision.blocked).toBe(true);
      expect(decision.inDiff).toBe(true);
      expect(decision.source).toBe('in-diff');
      expect(decision.findings.length).toBe(1);
      expect(decision.findings[0].detector).toBe('config.in-diff-untrusted');
      expect(decision.findings[0].severity).toBe('BLOCK');

      // Critical assertion — the returned config is safe (default), not the
      // attacker's ignorePackages. Verify by running applyConfig against the
      // returned config: the BLOCK finding must survive.
      const finding = fakeBlock({ package: 'attacker-pkg' });
      const filtered = applyConfig([finding], decision.config);
      expect(filtered.length).toBe(1);
      expect(filtered[0].severity).toBe('BLOCK');
    });

    it('rejects a config whose ignorePackages was mutated relative to baseline', () => {
      const baselineText = JSON.stringify({ version: 1, ignorePackages: [] });
      const attackerText = JSON.stringify({ version: 1, ignorePackages: ['attacker-pkg'] });

      const decision = decideConfigApplication(parseConfig(attackerText), {
        currentText: attackerText,
        baselineText,
      });

      expect(decision.blocked).toBe(true);
      expect(decision.inDiff).toBe(true);
      // The synthetic finding annotates that it CHANGED (not just added).
      expect(decision.findings[0].direction).toBe('changed');
    });
  });

  describe('C1 — allowlist in-diff → REJECT', () => {
    it('rejects a config whose allowlist covers all-categories on an attacker-controlled package', () => {
      const attackerConfigText = JSON.stringify({
        version: 1,
        allowlist: {
          'attacker-pkg': ['NET', 'EXEC', 'ENV', 'FS'],
        },
      });
      const parsed = parseConfig(attackerConfigText);

      const decision = decideConfigApplication(parsed, {
        currentText: attackerConfigText,
        baselineText: null,
      });

      expect(decision.blocked).toBe(true);
      expect(decision.findings[0].severity).toBe('BLOCK');

      // Verify the trust filter neutralized the attacker's allowlist.
      const netFinding = fakeBlock({
        package: 'attacker-pkg',
        detector: 'net.new-endpoint',
        category: 'NET',
        message: 'New network endpoint reached: https://evil.top',
      });
      const filtered = applyConfig([netFinding], decision.config);
      expect(filtered.length).toBe(1);
      expect(filtered[0].severity).toBe('BLOCK'); // not downgraded to INFO
    });

    it('C1 exact fixture: ua-parser-js ignorePackages line dropped GHSA-annotated finding', () => {
      // The exact single-line diff from the exploit report.
      const attackerText = JSON.stringify({
        version: 1,
        ignorePackages: ['ua-parser-js'],
      });
      const decision = decideConfigApplication(parseConfig(attackerText), {
        currentText: attackerText,
        baselineText: null,
      });

      expect(decision.blocked).toBe(true);
      const ghsa = fakeBlock({
        package: 'ua-parser-js',
        detector: 'advisories.known-vulnerable',
        category: 'DEPS',
        message: 'GHSA-fh58-9fw3-vf2v — known-malicious version',
      });
      const filtered = applyConfig([ghsa], decision.config);
      expect(filtered.length).toBe(1);
      expect(filtered[0].severity).toBe('BLOCK');
    });
  });

  describe('C2 — ignorePathsInside in-diff → REJECT', () => {
    it('rejects a config whose ignorePathsInside covers package.json for the attacker package', () => {
      const attackerConfigText = JSON.stringify({
        version: 1,
        ignorePathsInside: {
          chalk: ['package.json', 'test/', 'examples/'],
        },
      });
      const parsed = parseConfig(attackerConfigText);

      const decision = decideConfigApplication(parsed, {
        currentText: attackerConfigText,
        baselineText: null,
      });

      expect(decision.blocked).toBe(true);
      expect(decision.source).toBe('in-diff');

      // Verify a meta.maintainer-change (evidence: package.json) survives.
      const maintainerChange = fakeBlock({
        package: 'chalk',
        detector: 'meta.maintainer-change',
        category: 'META',
        message: 'maintainers: [sindresorhus] → [attacker@example.invalid]',
        evidence: [{ file: 'package.json', line: 1, snippet: 'maintainers: attacker' }],
      });
      const filtered = applyConfig([maintainerChange], decision.config);
      expect(filtered.length).toBe(1);
      expect(filtered[0].severity).toBe('BLOCK');
    });
  });

  describe('D1 — severityOverride in-diff → REJECT', () => {
    it('rejects a config whose severityOverride softens the integrity tripwire', () => {
      const attackerConfigText = JSON.stringify({
        version: 1,
        severityOverride: {
          'install.script-added': 'INFO',
          'integrity.hash-mismatch': 'INFO',
        },
      });
      const parsed = parseConfig(attackerConfigText);

      const decision = decideConfigApplication(parsed, {
        currentText: attackerConfigText,
        baselineText: null,
      });

      expect(decision.blocked).toBe(true);
      expect(decision.findings[0].severity).toBe('BLOCK');
      expect(decision.findings[0].detector).toBe('config.in-diff-untrusted');

      // Even if the always-apply filter caught integrity.hash-mismatch, D1
      // ALSO targets install.script-added — verify it stays BLOCK.
      const scriptFinding = fakeBlock({
        detector: 'install.script-added',
        package: 'foo',
      });
      const filtered = applyConfig([scriptFinding], decision.config);
      expect(filtered.length).toBe(1);
      expect(filtered[0].severity).toBe('BLOCK');
    });
  });

  describe('positive control — same config in baseline is APPLIED', () => {
    it('applies a config whose text matches the baseline exactly', () => {
      const configText = JSON.stringify({
        version: 1,
        ignorePackages: ['known-good-internal-pkg'],
      });
      const parsed = parseConfig(configText);

      const decision = decideConfigApplication(parsed, {
        currentText: configText,
        baselineText: configText, // identical
      });

      expect(decision.blocked).toBe(false);
      expect(decision.inDiff).toBe(false);
      expect(decision.source).toBe('baseline');
      expect(decision.findings.length).toBe(0);
      expect(decision.config.ignorePackages).toEqual(['known-good-internal-pkg']);

      // Sanity: applying the config to a finding on that internal package
      // drops it — because the config IS trusted.
      const finding = fakeBlock({ package: 'known-good-internal-pkg' });
      const filtered = applyConfig([finding], decision.config);
      expect(filtered.length).toBe(0);
    });

    it('returns DEFAULT_CONFIG when the file is absent altogether', () => {
      const decision = decideConfigApplication(null, {
        currentText: null,
        baselineText: null,
      });

      expect(decision.blocked).toBe(false);
      expect(decision.inDiff).toBe(false);
      expect(decision.source).toBe('default');
      expect(decision.findings.length).toBe(0);
      expect(decision.config).toEqual(DEFAULT_CONFIG);
    });
  });

  describe('--config-allow-in-diff (strict=false) — WARN + APPLY', () => {
    it('emits a WARN synthetic finding but applies the config when strict=false', () => {
      const attackerConfigText = JSON.stringify({
        version: 1,
        ignorePackages: ['attacker-pkg'],
      });
      const parsed = parseConfig(attackerConfigText);

      const decision = decideConfigApplication(
        parsed,
        { currentText: attackerConfigText, baselineText: null },
        false, // strict = false: operator explicitly opts in
      );

      expect(decision.blocked).toBe(false);
      expect(decision.inDiff).toBe(true);
      expect(decision.source).toBe('in-diff');
      expect(decision.findings.length).toBe(1);
      expect(decision.findings[0].severity).toBe('WARN');
      expect(decision.config.ignorePackages).toContain('attacker-pkg');
    });
  });

  describe('always-apply detectors — baseline severityOverride cannot silence integrity.hash-mismatch', () => {
    // Verifies the ALWAYS_APPLY_DETECTORS set (already implemented in
    // config.ts) — an in-baseline (trusted) config that softens the integrity
    // tripwire still fails to silence it. This closes the specific D1 hole
    // that survives even after the trust boundary lets a config through.
    it('integrity.hash-mismatch stays BLOCK even with a baseline severityOverride to INFO', () => {
      const baselineConfigText = JSON.stringify({
        version: 1,
        severityOverride: {
          'integrity.hash-mismatch': 'INFO',
        },
      });
      const parsed = parseConfig(baselineConfigText);

      // Fully baseline — no diff, no synthetic finding, config applies normally.
      const decision = decideConfigApplication(parsed, {
        currentText: baselineConfigText,
        baselineText: baselineConfigText,
      });
      expect(decision.blocked).toBe(false);

      const integrityFinding = fakeBlock({
        detector: 'integrity.hash-mismatch',
        category: 'INTEG',
        package: 'foo',
        message: 'foo@1.2.3 integrity changed on republish (tarball swap)',
        evidence: [{ file: 'package.json', line: 1, snippet: 'sha512-old vs sha512-new' }],
      });
      const filtered = applyConfig([integrityFinding], decision.config);
      expect(filtered.length).toBe(1);
      expect(filtered[0].severity).toBe('BLOCK');
      // Verify it did NOT get overridden to INFO.
      expect(filtered[0].severity).not.toBe('INFO');
    });

    it('analysis.failed stays at native severity even with baseline severityOverride', () => {
      const baselineConfigText = JSON.stringify({
        version: 1,
        severityOverride: {
          'analysis.failed': 'INFO',
        },
      });
      const parsed = parseConfig(baselineConfigText);
      const decision = decideConfigApplication(parsed, {
        currentText: baselineConfigText,
        baselineText: baselineConfigText,
      });

      const analysisFail = fakeBlock({
        detector: 'analysis.failed',
        category: 'META',
        package: 'foo',
        severity: 'BLOCK',
        message: 'Analyzer crashed on foo@1.2.3',
        evidence: [{ file: 'package.json', line: 1, snippet: 'analyzer error' }],
      });
      const filtered = applyConfig([analysisFail], decision.config);
      expect(filtered.length).toBe(1);
      expect(filtered[0].severity).toBe('BLOCK');
    });
  });
});
