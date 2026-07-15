/**
 * META disposable-author-domain — package's author/maintainer email domain
 * is on the bundled disposable-email-domain snapshot.
 *
 * Port from guarddog:deceptive_author — audit §4 row 7.
 *
 * Attacker shape: publish a malicious package under a throwaway maildrop.cc /
 * 10minutemail.com / yopmail.com identity — nothing tying the release back to
 * a real developer. The domain-list check is a fast, offline, snapshot-based
 * signal that pairs well with the existing meta.maintainer-change detector.
 *
 * Only fires on ADDED packages OR on newly-appeared emails within an existing
 * package's maintainer set — an established package whose maintainer moved
 * their email to a disposable provider is a distinct-and-existing signal
 * (meta.maintainer-change already surfaces the transition; this detector
 * qualifies WHY the new address is suspect).
 *
 * NEVER-EXECUTE (ADR 0005): reads only the package manifest fields already
 * parsed by the core analyzer. No new I/O, no runtime fetches for the domain
 * list — the snapshot is bundled JSON.
 */

import type { Detector, Finding, PackageManifest, SnapshotPair, Severity } from '@vetlock/core';
import { getDisposableDomains } from './data/disposable-domains-loader.js';

function collectEmails(manifest: PackageManifest): string[] {
  const set = new Set<string>();
  if (Array.isArray(manifest.maintainers)) {
    for (const m of manifest.maintainers) {
      if (m && typeof m === 'object' && typeof m.email === 'string') set.add(m.email.toLowerCase());
    }
  }
  if (manifest._npmUser && typeof manifest._npmUser === 'object' && typeof manifest._npmUser.email === 'string') {
    set.add(manifest._npmUser.email.toLowerCase());
  }
  // package.json `author` may be a string ("Name <mail@x>") or {name, email}.
  const author = (manifest as Record<string, unknown>).author;
  if (typeof author === 'string') {
    const m = author.match(/<([^>]+@[^>]+)>/);
    if (m) set.add(m[1].toLowerCase());
  } else if (author && typeof author === 'object' && 'email' in author && typeof (author as { email?: unknown }).email === 'string') {
    set.add(((author as { email: string }).email).toLowerCase());
  }
  return [...set].sort();
}

function domainOf(email: string): string | null {
  const at = email.lastIndexOf('@');
  if (at < 0 || at === email.length - 1) return null;
  return email.slice(at + 1).toLowerCase();
}

/** For test surface. */
export function isDisposableEmail(email: string): boolean {
  const domain = domainOf(email);
  if (!domain) return false;
  return getDisposableDomains().has(domain);
}

export const disposableAuthorDomainDetector: Detector = {
  id: 'meta-disposable-author-domain',
  category: 'META',
  run(pair: SnapshotPair): Finding[] {
    if (!pair.new) return [];
    const newEmails = collectEmails(pair.new.manifest);
    if (newEmails.length === 0) return [];
    // For upgrades: only flag emails NEW in this version — an existing package
    // with a long-standing disposable-email maintainer is a documentation
    // problem, not a diff-tier signal. This preserves the "new pattern in
    // pair.new that wasn't in pair.old" discipline.
    const isAdd = pair.old === null;
    const oldEmails = pair.old ? new Set(collectEmails(pair.old.manifest)) : new Set<string>();
    const flagged = newEmails.filter((e) => {
      if (!isAdd && oldEmails.has(e)) return false;
      return isDisposableEmail(e);
    });
    if (flagged.length === 0) return [];
    // ADDED packages with a disposable-domain maintainer are BLOCK-tier —
    // an entirely new dependency vouched for only by a throwaway email is
    // the exact shape we want to stop.
    // UPGRADED packages: WARN — an existing package that gained a disposable
    // email is unusual but not disqualifying; runAll compound-suspicion
    // escalates it when other signals co-occur.
    const severity: Severity = isAdd ? 'BLOCK' : 'WARN';
    const confidence: 'high' | 'medium' = isAdd ? 'high' : 'medium';
    return [
      {
        detector: 'meta.disposable-author-domain',
        category: 'META',
        package: pair.new.name,
        from: pair.old?.version ?? null,
        to: pair.new.version,
        direction: isAdd ? 'added' : 'changed',
        severity,
        confidence,
        message:
          `Author/maintainer email address(es) resolve to a disposable-email-provider domain: ${flagged.join(', ')}. ` +
          'Ported from guarddog:deceptive_author.',
        evidence: [
          {
            file: 'package.json',
            line: 1,
            snippet: `disposable-domain email(s): ${flagged.join(', ')}`.slice(0, 240),
          },
        ],
        provenance: [],
      },
    ];
  },
};
