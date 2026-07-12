/**
 * GHSA correlation + publisher trust store tests.
 *
 * These cover:
 *   - Version-range matching against known advisories
 *   - The trust store's takeover-detection logic (trusted → unknown = BLOCK)
 *   - The trust store's non-regressive downgrade (trusted → trusted = INFO)
 */

import { describe, it, expect } from 'vitest';
import { advisoriesForVersion } from '../src/advisories.js';
import { BUILTIN_TRUST_STORE, isTrustedPublisher, effectiveTrustList } from '../src/publishers.js';
import { maintainerDetector } from '../src/meta.js';
import { runAll } from '../src/index.js';
import { mkSnap } from './helpers.js';

describe('GHSA advisory correlation', () => {
  it('matches ua-parser-js@0.7.29 against its takeover advisory', () => {
    const a = advisoriesForVersion('ua-parser-js', '0.7.29');
    expect(a.length).toBeGreaterThanOrEqual(1);
    expect(a[0]!.ghsa).toBe('GHSA-fh58-9fw3-vf2v');
    expect(a[0]!.severity).toBe('critical');
  });

  it('matches @solana/web3.js@1.95.5 against its wallet-drainer advisory', () => {
    const a = advisoriesForVersion('@solana/web3.js', '1.95.5');
    expect(a).toHaveLength(1);
    expect(a[0]!.summary).toMatch(/wallet-drainer/);
  });

  it('does NOT match ua-parser-js@0.7.28 (safe version)', () => {
    expect(advisoriesForVersion('ua-parser-js', '0.7.28')).toHaveLength(0);
  });

  it('does NOT match arbitrary packages', () => {
    expect(advisoriesForVersion('my-benign-lib', '1.0.0')).toHaveLength(0);
  });

  it('handles bad version strings without throwing', () => {
    expect(() => advisoriesForVersion('ua-parser-js', 'not-a-version')).not.toThrow();
  });

  it('runAll annotates findings when a matching advisory exists', () => {
    const pair = {
      old: mkSnap({
        name: 'ua-parser-js',
        version: '0.7.28',
        manifest: { name: 'ua-parser-js', version: '0.7.28', scripts: {} },
      }),
      new: mkSnap({
        name: 'ua-parser-js',
        version: '0.7.29',
        manifest: {
          name: 'ua-parser-js',
          version: '0.7.29',
          scripts: { preinstall: 'node evil.js' },
        },
      }),
    };
    const findings = runAll(pair);
    const withGhsa = findings.filter((f) => f.message.includes('GHSA:'));
    expect(withGhsa.length).toBeGreaterThan(0);
    expect(withGhsa[0]!.message).toMatch(/GHSA-fh58-9fw3-vf2v/);
  });
});

describe('publisher trust store', () => {
  it('BUILTIN_TRUST_STORE contains well-known Chalk maintainers', () => {
    expect(BUILTIN_TRUST_STORE['chalk']).toContain('sindresorhus');
  });

  it('isTrustedPublisher matches substring within evidence text', () => {
    expect(isTrustedPublisher('by sindresorhus <sindresorhus@gmail.com>', ['sindresorhus'])).toBe(true);
    expect(isTrustedPublisher('publisher: attacker@evil.example.invalid', ['sindresorhus'])).toBe(false);
  });

  it('effectiveTrustList composes builtin + user config', () => {
    const list = effectiveTrustList('chalk', { chalk: ['my-team'] });
    expect(list).toContain('sindresorhus'); // built-in
    expect(list).toContain('my-team');       // user-added
  });

  it('meta detector BLOCKS when trusted publisher replaced by unknown', () => {
    const pair = {
      old: mkSnap({
        name: 'chalk',
        version: '5.3.0',
        manifest: {
          name: 'chalk',
          version: '5.3.0',
          maintainers: [{ email: 'sindresorhus@gmail.com' }],
        },
      }),
      new: mkSnap({
        name: 'chalk',
        version: '5.3.1',
        manifest: {
          name: 'chalk',
          version: '5.3.1',
          maintainers: [{ email: 'attacker@evil.example.invalid' }],
        },
      }),
    };
    const findings = maintainerDetector.run(pair, { direction: 'changed' });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('BLOCK');
    expect(findings[0]!.message).toMatch(/takeover pattern/);
  });

  it('meta detector INFOs on rotation within trusted publishers', () => {
    // Real npm maintainer records use emails; the S3 fix requires email-shaped
    // input for the trust check. Bare-username manifests are not what npm
    // actually publishes.
    const pair = {
      old: mkSnap({
        name: 'chalk',
        version: '5.3.0',
        manifest: {
          name: 'chalk',
          version: '5.3.0',
          maintainers: [{ email: 'sindresorhus@example.com' }],
        },
      }),
      new: mkSnap({
        name: 'chalk',
        version: '5.3.1',
        manifest: {
          name: 'chalk',
          version: '5.3.1',
          maintainers: [{ email: 'qix-@example.com' }],
        },
      }),
    };
    const findings = maintainerDetector.run(pair, { direction: 'changed' });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('INFO');
    expect(findings[0]!.message).toMatch(/rotation within trusted/);
  });

  it('meta detector WARNs on unknown → unknown change (no trust store data)', () => {
    const pair = {
      old: mkSnap({
        name: 'obscure-lib',
        version: '1.0.0',
        manifest: {
          name: 'obscure-lib',
          version: '1.0.0',
          maintainers: [{ email: 'a@ex.com' }],
        },
      }),
      new: mkSnap({
        name: 'obscure-lib',
        version: '1.0.1',
        manifest: {
          name: 'obscure-lib',
          version: '1.0.1',
          maintainers: [{ email: 'b@ex.com' }],
        },
      }),
    };
    const findings = maintainerDetector.run(pair, { direction: 'changed' });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('WARN');
  });
});
