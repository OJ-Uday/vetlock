import { describe, it, expect } from 'vitest';
import { validateFinding } from '@vetlock/core';
import { metaDisposableDomainDetector, disposableDomainOf } from '../src/meta-disposable-domain.js';
import { mkSnap } from './helpers.js';

describe('meta.disposable-author-domain (port from guarddog:metadata/deceptive_author.py)', () => {
  it('POS: fires on maintainer email using mailinator.com', () => {
    const pair = {
      old: null,
      new: mkSnap({
        name: 'sketchy-pkg',
        version: '1.0.0',
        manifest: {
          name: 'sketchy-pkg',
          version: '1.0.0',
          maintainers: [{ name: 'alice', email: 'alice@mailinator.com' }],
        },
      }),
    };
    const findings = metaDisposableDomainDetector.run(pair, { direction: 'added' });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.detector).toBe('meta.disposable-author-domain');
    expect(findings[0]!.category).toBe('META');
    expect(findings[0]!.severity).toBe('WARN');
    expect(findings[0]!.confidence).toBe('medium');
    expect(findings[0]!.message).toMatch(/mailinator\.com/);
    expect(validateFinding(findings[0]!)).toBeNull();
  });

  it('POS: fires on author string with disposable domain', () => {
    const pair = {
      old: null,
      new: mkSnap({
        name: 'sketchy-pkg',
        version: '1.0.0',
        manifest: {
          name: 'sketchy-pkg',
          version: '1.0.0',
          // npm authors are commonly serialised as "Name <email>"
          author: 'Alice <alice@guerrillamail.com>',
        } as never,
      }),
    };
    const findings = metaDisposableDomainDetector.run(pair, { direction: 'added' });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.message).toMatch(/guerrillamail\.com/);
    expect(validateFinding(findings[0]!)).toBeNull();
  });

  it('POS: subdomain matches — sub.mailinator.com hits mailinator.com', () => {
    const pair = {
      old: null,
      new: mkSnap({
        name: 'sketchy-pkg',
        version: '1.0.0',
        manifest: {
          name: 'sketchy-pkg',
          version: '1.0.0',
          maintainers: [{ email: 'a@sub.mailinator.com' }],
        },
      }),
    };
    const findings = metaDisposableDomainDetector.run(pair, { direction: 'added' });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.message).toMatch(/mailinator\.com/);
  });

  it('NEG: does not fire for a legitimate corporate email domain', () => {
    const pair = {
      old: null,
      new: mkSnap({
        name: 'legit-pkg',
        version: '1.0.0',
        manifest: {
          name: 'legit-pkg',
          version: '1.0.0',
          maintainers: [{ email: 'developer@example.com' }],
          _npmUser: { name: 'developer', email: 'developer@example.com' },
        },
      }),
    };
    const findings = metaDisposableDomainDetector.run(pair, { direction: 'added' });
    expect(findings).toEqual([]);
  });

  it('NEG: does not fire when the disposable-domain email was already there in pair.old (diff-safe)', () => {
    const oldManifest = {
      name: 'stable-pkg',
      version: '1.0.0',
      maintainers: [{ email: 'alice@mailinator.com' }],
    };
    const newManifest = {
      name: 'stable-pkg',
      version: '1.0.1',
      maintainers: [{ email: 'alice@mailinator.com' }],
    };
    const pair = {
      old: mkSnap({ name: 'stable-pkg', version: '1.0.0', manifest: oldManifest }),
      new: mkSnap({ name: 'stable-pkg', version: '1.0.1', manifest: newManifest }),
    };
    const findings = metaDisposableDomainDetector.run(pair, { direction: 'changed' });
    expect(findings).toEqual([]);
  });

  it('DIFF: fires when the disposable-domain email is added between versions', () => {
    const pair = {
      old: mkSnap({
        name: 'compromised-pkg',
        version: '1.0.0',
        manifest: {
          name: 'compromised-pkg',
          version: '1.0.0',
          maintainers: [{ email: 'og@example.com' }],
        },
      }),
      new: mkSnap({
        name: 'compromised-pkg',
        version: '1.0.1',
        manifest: {
          name: 'compromised-pkg',
          version: '1.0.1',
          maintainers: [
            { email: 'og@example.com' },
            { email: 'attacker@yopmail.com' },
          ],
        },
      }),
    };
    const findings = metaDisposableDomainDetector.run(pair, { direction: 'changed' });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.direction).toBe('changed');
    expect(findings[0]!.message).toMatch(/yopmail\.com/);
    expect(findings[0]!.message).not.toMatch(/og@example\.com/); // old email not flagged
  });

  it('helper: disposableDomainOf recognizes known disposable domains and rejects unknowns', () => {
    expect(disposableDomainOf('a@mailinator.com')).toBe('mailinator.com');
    expect(disposableDomainOf('b@yopmail.com')).toBe('yopmail.com');
    expect(disposableDomainOf('c@example.com')).toBeNull();
    expect(disposableDomainOf('no-at-sign')).toBeNull();
    expect(disposableDomainOf('')).toBeNull();
    expect(disposableDomainOf(undefined)).toBeNull();
  });
});
