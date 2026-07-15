/**
 * META disposable-author-domain — bundled list domain-exact-match.
 *
 * Test contract:
 *  - Author email on the disposable-domain snapshot list → fires.
 *  - Author email at a legit provider (gmail.com, google.com) → does NOT fire.
 *  - Only newly-appeared emails fire on upgrades (long-standing disposable
 *    email is a doc problem, not a diff signal).
 *  - Newly-added packages with any disposable email → BLOCK.
 *  - Upgrades that added a disposable email → WARN.
 *
 * Ports from guarddog:deceptive_author, per §4 row 7.
 */

import { describe, it, expect } from 'vitest';
import {
  disposableAuthorDomainDetector,
  isDisposableEmail,
} from '../src/meta-disposable-author-domain.js';
import { mkSnap } from './helpers.js';
import type { PackageManifest } from '@vetlock/core';

function withMaintainers(name: string, version: string, emails: string[]): PackageManifest {
  return {
    name,
    version,
    maintainers: emails.map((email) => ({ email })),
  };
}

describe('meta.disposable-author-domain — domain-list lookup', () => {
  it('identifies disposable-domain emails', () => {
    expect(isDisposableEmail('bob@maildrop.cc')).toBe(true);
    expect(isDisposableEmail('alice@10minutemail.com')).toBe(true);
    expect(isDisposableEmail('spammer@yopmail.com')).toBe(true);
    expect(isDisposableEmail('test@guerrillamail.com')).toBe(true);
  });

  it('does NOT flag legitimate providers', () => {
    expect(isDisposableEmail('me@gmail.com')).toBe(false);
    expect(isDisposableEmail('me@outlook.com')).toBe(false);
    expect(isDisposableEmail('me@company.com')).toBe(false);
    expect(isDisposableEmail('me@users.noreply.github.com')).toBe(false);
  });

  it('handles case-insensitively', () => {
    expect(isDisposableEmail('BOB@MAILDROP.CC')).toBe(true);
    expect(isDisposableEmail('Bob@Maildrop.cc')).toBe(true);
  });

  it('handles bogus inputs gracefully', () => {
    expect(isDisposableEmail('')).toBe(false);
    expect(isDisposableEmail('noatsign')).toBe(false);
    expect(isDisposableEmail('trailing@')).toBe(false);
  });

  it('emits BLOCK-tier finding on newly-added package with disposable email', () => {
    const pair = {
      old: null,
      new: mkSnap({
        name: 'my-package',
        version: '1.0.0',
        manifest: withMaintainers('my-package', '1.0.0', ['bob@maildrop.cc']),
      }),
    };
    const findings = disposableAuthorDomainDetector.run(pair, { direction: 'added' });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.detector).toBe('meta.disposable-author-domain');
    expect(findings[0]!.severity).toBe('BLOCK');
    expect(findings[0]!.confidence).toBe('high');
    expect(findings[0]!.message).toMatch(/bob@maildrop\.cc/);
  });

  it('emits WARN-tier finding on upgrade when disposable email is NEW', () => {
    const pair = {
      old: mkSnap({
        name: 'my-package',
        version: '1.0.0',
        manifest: withMaintainers('my-package', '1.0.0', ['alice@company.com']),
      }),
      new: mkSnap({
        name: 'my-package',
        version: '1.0.1',
        manifest: withMaintainers('my-package', '1.0.1', ['alice@company.com', 'bob@yopmail.com']),
      }),
    };
    const findings = disposableAuthorDomainDetector.run(pair, { direction: 'changed' });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('WARN');
    expect(findings[0]!.message).toMatch(/yopmail/);
  });

  it('does NOT fire on upgrades when the disposable email was already present', () => {
    const pair = {
      old: mkSnap({
        name: 'my-package',
        version: '1.0.0',
        manifest: withMaintainers('my-package', '1.0.0', ['bob@maildrop.cc']),
      }),
      new: mkSnap({
        name: 'my-package',
        version: '1.0.1',
        manifest: withMaintainers('my-package', '1.0.1', ['bob@maildrop.cc']),
      }),
    };
    // Disposable email was already there — nothing NEW in the diff.
    expect(disposableAuthorDomainDetector.run(pair, { direction: 'changed' })).toHaveLength(0);
  });

  it('does NOT fire when all emails are legit', () => {
    const pair = {
      old: null,
      new: mkSnap({
        name: 'my-package',
        version: '1.0.0',
        manifest: withMaintainers('my-package', '1.0.0', ['dev@company.com', 'ops@company.io']),
      }),
    };
    expect(disposableAuthorDomainDetector.run(pair, { direction: 'added' })).toHaveLength(0);
  });

  it('picks up author.string field', () => {
    const pair = {
      old: null,
      new: mkSnap({
        name: 'my-package',
        version: '1.0.0',
        manifest: {
          name: 'my-package',
          version: '1.0.0',
          author: 'Attacker Name <attacker@sharklasers.com>',
        },
      }),
    };
    const findings = disposableAuthorDomainDetector.run(pair, { direction: 'added' });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.message).toMatch(/sharklasers/);
  });

  it('picks up author.object field', () => {
    const pair = {
      old: null,
      new: mkSnap({
        name: 'my-package',
        version: '1.0.0',
        manifest: {
          name: 'my-package',
          version: '1.0.0',
          author: { name: 'Attacker', email: 'attacker@throwam.com' },
        },
      }),
    };
    const findings = disposableAuthorDomainDetector.run(pair, { direction: 'added' });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.message).toMatch(/throwam/);
  });

  it('picks up _npmUser field', () => {
    const pair = {
      old: null,
      new: mkSnap({
        name: 'my-package',
        version: '1.0.0',
        manifest: {
          name: 'my-package',
          version: '1.0.0',
          _npmUser: { name: 'Attacker', email: 'attacker@guerrillamail.com' },
        },
      }),
    };
    const findings = disposableAuthorDomainDetector.run(pair, { direction: 'added' });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.message).toMatch(/guerrillamail/);
  });
});
