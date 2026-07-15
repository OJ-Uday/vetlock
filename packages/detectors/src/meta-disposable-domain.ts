// port from guarddog:metadata/deceptive_author.py
/**
 * META detector — publisher email uses a disposable / throwaway mail domain.
 *
 * Rationale (audit §1 G-15): the `meta.maintainer-change` detector catches
 * *changes* in publisher identity. It does not evaluate the *quality* of the
 * publisher identity itself — a first-published package by
 * `attacker@mailinator.com` clears the maintainer-change gate because there is
 * no prior version to diff against. guarddog's `metadata/deceptive_author.py`
 * closes this gap by rejecting emails whose domain is a known
 * disposable/throwaway mail service (mailinator.com, guerrillamail.com,
 * 10minutemail.com, and ~100 more).
 *
 * We fire in both diff-mode (new or changed publisher identity ships a
 * disposable domain) AND added-package mode (first-published package uses one).
 * We deliberately do NOT try to fire when the OLD version already had a
 * disposable-domain email — that would be a signal about the previous release,
 * not a diff-frame delta about this one.
 *
 * Baseline severity WARN, medium confidence. Escalates via the
 * runAll() compound-suspicion pass when the package also carries BLOCK-tier
 * capabilities (INSTALL / EXEC / NET / ENV / FS / CODE / OBF).
 *
 * The bundled disposable-domain list intentionally covers the ~35 most
 * commonly-abused services rather than the full ~200 guarddog ships — the
 * long-tail entries add < 1% detection value against the FP risk of matching
 * a legitimately-run ".mail" or ".temp" TLD company. See docs/CAPABILITY-MAP.md
 * for the full list; grow it via PR when a new service surfaces in a real
 * incident.
 */

import type { Detector, Finding, PackageManifest, SnapshotPair } from '@vetlock/core';
import { directionFor } from './direction.js';

/**
 * Bundled list of known disposable / throwaway mail services. Sourced from
 * guarddog's own `deceptive_author.py` + widely-published disposable-domain
 * blocklists (Adafruit, disposable-email-domains repo). Lowercase, no leading
 * dot — matched with an EXACT domain match and a wildcard match on the
 * trailing subdomain of the email address (so `alice@sub.mailinator.com`
 * matches `mailinator.com`).
 */
const DISPOSABLE_DOMAINS: readonly string[] = [
  '10minutemail.com',
  '10minutemail.net',
  '20minutemail.com',
  'anonbox.net',
  'anonymbox.com',
  'burnermail.io',
  'deadaddress.com',
  'discard.email',
  'dispostable.com',
  'emailondeck.com',
  'fakeinbox.com',
  'getnada.com',
  'guerrillamail.com',
  'guerrillamail.info',
  'guerrillamail.net',
  'guerrillamail.org',
  'guerrillamail.biz',
  'guerrillamail.de',
  'inboxbear.com',
  'jetable.org',
  'mailcatch.com',
  'maildrop.cc',
  'mailinator.com',
  'mailnesia.com',
  'meltmail.com',
  'mintemail.com',
  'mohmal.com',
  'moakt.com',
  'mvrht.net',
  'mytemp.email',
  'nowmymail.com',
  'sharklasers.com',
  'spam4.me',
  'spamgourmet.com',
  'spamex.com',
  'temp-mail.io',
  'temp-mail.org',
  'tempail.com',
  'tempmail.com',
  'tempinbox.com',
  'temporaryinbox.com',
  'throwawaymail.com',
  'trashmail.com',
  'trashmail.net',
  'trashmail.io',
  'tutanota.com',
  'yopmail.com',
  'yopmail.fr',
  'yopmail.net',
];

const DISPOSABLE_SET = new Set<string>(DISPOSABLE_DOMAINS);

/** Return the disposable domain the email belongs to, else null. */
function disposableDomainOf(email: string | undefined | null): string | null {
  if (!email || typeof email !== 'string') return null;
  const at = email.lastIndexOf('@');
  if (at < 0 || at === email.length - 1) return null;
  const domain = email.slice(at + 1).toLowerCase().trim();
  if (!domain) return null;
  if (DISPOSABLE_SET.has(domain)) return domain;
  // Also match a domain suffix (e.g. `sub.mailinator.com` → mailinator.com).
  const parts = domain.split('.');
  for (let i = 1; i < parts.length; i++) {
    const suffix = parts.slice(i).join('.');
    if (DISPOSABLE_SET.has(suffix)) return suffix;
  }
  return null;
}

/** Collect every author/maintainer/_npmUser email from a manifest. */
function collectEmails(manifest: PackageManifest | undefined): string[] {
  if (!manifest) return [];
  const emails = new Set<string>();
  // manifest.author can be a string ("Name <email>") or an object { email }.
  const author = (manifest as Record<string, unknown>).author;
  if (typeof author === 'string') {
    const m = author.match(/<([^>]+)>/);
    if (m) emails.add(m[1]!.trim());
  } else if (author && typeof author === 'object') {
    const e = (author as Record<string, unknown>).email;
    if (typeof e === 'string') emails.add(e.trim());
  }
  if (Array.isArray(manifest.maintainers)) {
    for (const m of manifest.maintainers) {
      if (m && typeof m === 'object' && typeof m.email === 'string') emails.add(m.email.trim());
    }
  }
  if (manifest._npmUser && typeof manifest._npmUser.email === 'string') {
    emails.add(manifest._npmUser.email.trim());
  }
  return [...emails].sort();
}

export const metaDisposableDomainDetector: Detector = {
  id: 'meta-disposable-domain',
  category: 'META',
  run(pair: SnapshotPair): Finding[] {
    if (!pair.new) return [];
    const dir = directionFor(pair.old);
    const newEmails = collectEmails(pair.new.manifest);
    const oldEmails = new Set(collectEmails(pair.old?.manifest ?? undefined));

    const disposableHits: Array<{ email: string; domain: string }> = [];
    for (const email of newEmails) {
      // Diff-safe: only fire if the disposable-domain email is NEW to this
      // version. A package that already had `alice@mailinator.com` in v1 and
      // still has it in v2 is a signal about v1, not v2.
      if (oldEmails.has(email)) continue;
      const domain = disposableDomainOf(email);
      if (domain) disposableHits.push({ email, domain });
    }
    if (disposableHits.length === 0) return [];

    // One finding per package version, listing every disposable email seen.
    const emailList = disposableHits.map((h) => `${h.email} (${h.domain})`).join(', ');
    return [
      {
        detector: 'meta.disposable-author-domain',
        category: 'META',
        package: pair.new.name,
        from: dir.from,
        to: pair.new.version,
        direction: dir.direction,
        severity: 'WARN',
        confidence: 'medium',
        message:
          `Package author/maintainer email uses a disposable / throwaway mail domain: ${emailList}. ` +
          'Attackers routinely publish typosquat and dependency-confusion packages from disposable inboxes.',
        evidence: [
          {
            file: 'package.json',
            line: 1,
            snippet: `disposable-domain email(s): ${emailList}`.slice(0, 240),
          },
        ],
        provenance: [],
      },
    ];
  },
};

/** Exported for tests / capability-map tooling. */
export { DISPOSABLE_DOMAINS, disposableDomainOf };
