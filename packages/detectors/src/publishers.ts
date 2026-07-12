/**
 * Publisher trust store — known-good publisher emails/orgs per popular package.
 *
 * Used by the meta.maintainer-change detector to distinguish:
 *   - "New maintainer email; still on the trust list"           → INFO
 *   - "New maintainer email; not on trust list"                  → WARN
 *   - "Existing maintainer replaced by unknown"                  → BLOCK
 *
 * Data source: manually curated from npm's public maintainer records for the
 * top-download packages. This list DOES NOT try to be exhaustive — it covers
 * the packages most commonly used as vehicles for T1 takeover attacks. A
 * comprehensive live-fetched trust store is on the roadmap; users can extend
 * this via .vetlock.json `trustedPublishers` in the meantime.
 *
 * Format: `{ [packageName]: [ ...trustedEmailsOrOrgs ] }`.
 *
 * Names in the value list may be:
 *   - Full email addresses      ('sindresorhus@gmail.com')
 *   - Domain-suffix wildcards   ('@github.com', '@microsoft.com')
 *   - Publisher usernames       ('sindresorhus', 'isaacs')
 *
 * The matcher checks each substring, so 'sindresorhus@gmail.com' matches when
 * the finding evidence contains that email OR just the username.
 */

export const BUILTIN_TRUST_STORE: Readonly<Record<string, readonly string[]>> = {
  // Prolific individual maintainers — these accounts publish 100s of packages
  // and are natural high-value takeover targets. Any of these emails/handles
  // rotating out to an unknown is BLOCK-tier signal.
  'chalk': ['sindresorhus', 'qix-'],
  'ansi-styles': ['sindresorhus', 'qix-'],
  'strip-ansi': ['sindresorhus'],
  'ora': ['sindresorhus'],
  'debug': ['tjholowaychuk', 'dougwilson', 'qix-'],
  'ms': ['tjholowaychuk', 'dougwilson'],
  'express': ['dougwilson', 'blakeembrey'],
  'body-parser': ['dougwilson'],

  // npm-team-published
  'npm': ['@npmjs.com'],
  'semver': ['isaacs', '@npmjs.com'],
  'pacote': ['isaacs', '@npmjs.com'],

  // GitHub org
  '@actions/core': ['@github.com'],
  '@actions/github': ['@github.com'],
  '@github/hub': ['@github.com'],

  // Microsoft org
  '@microsoft/tsdoc': ['@microsoft.com'],
  '@microsoft/api-extractor': ['@microsoft.com'],
  'typescript': ['@microsoft.com'],
  '@types/node': ['definitelytyped'],
  '@types/react': ['definitelytyped'],

  // Google / Angular
  '@angular/core': ['@google.com', '@angular.io'],
  '@angular/common': ['@google.com', '@angular.io'],

  // Meta / React
  'react': ['@fb.com', '@meta.com'],
  'react-dom': ['@fb.com', '@meta.com'],
  'react-native': ['@fb.com', '@meta.com'],

  // Vercel / Next
  'next': ['@vercel.com', '@zeit.co'],

  // Vite / Vue
  'vite': ['yyx990803'],
  'vue': ['yyx990803'],
  'vue-router': ['yyx990803'],

  // Webpack
  'webpack': ['sokra', '@webpack.js.org'],

  // Solana
  '@solana/web3.js': ['@solana.com', '@solana-labs.com'],

  // Popular utility maintainers historically targeted
  'lodash': ['jdalton'],
  'moment': ['@momentjs.com'],
  'axios': ['@axios-http.com'],
  'jest': ['@facebook.com', '@meta.com'],

  // Sindresorhus's smaller-but-numerous published packages (a takeover on any
  // of these could pivot to bigger targets); we only enumerate the highest-
  // download ones here — extend via config.
  'is-plain-obj': ['sindresorhus'],
  'p-limit': ['sindresorhus'],
  'p-queue': ['sindresorhus'],
  'p-map': ['sindresorhus'],
};

/**
 * Match one email address against a trust-store entry list.
 *
 * REDTEAM S3 FIX: the old implementation did `evidenceText.toLowerCase().includes(t.toLowerCase())`
 * — a substring match. `attacker@github.com.evil.example` contains `@github.com`
 * as a substring and was treated as trusted. Same problem let
 * `sindresorhus-fake@evil.example` slip through because it contains `sindresorhus`.
 *
 * Corrected matching rules — an email `local@domain` matches a trust anchor `t`
 * iff ONE of these EXACT-STRUCTURE conditions holds:
 *
 *   1. `t` starts with `@` (domain-anchor): `domain` must EQUAL `t.slice(1)` OR
 *      `domain` must END WITH `.${t.slice(1)}` (subdomain-suffix).
 *      Example: `@github.com` matches `octocat@github.com` and `octocat@app.github.com`
 *      but NOT `octocat@github.com.evil.example`.
 *
 *   2. `t` contains an `@` (full-email-anchor): case-insensitive exact equality
 *      of the whole email.
 *      Example: `foo@bar.com` matches ONLY `foo@bar.com`.
 *
 *   3. `t` is a bare username: case-insensitive exact equality against `local`,
 *      the part before `@`.
 *      Example: `sindresorhus` matches `sindresorhus@example.com` — but not
 *      `sindresorhus-fake@example.com` (local ≠ 'sindresorhus').
 *
 * Only these three forms are meaningful in the trust store. Everything else
 * returns false.
 *
 * Callers pass the evidence-snippet string from a meta.maintainer-change
 * finding, which is shaped like `maintainers: [a@b.c] → [d@e.f, g@h.i]`. We
 * extract every plausible email from it (via regex — no fancy parsing) and
 * test each independently against the trust list. The finding is considered
 * "trusted" iff EVERY email on the NEW side is trusted (the previous "any
 * match" behaviour meant an unknown attacker joining an existing trusted
 * team looked trusted — that was also wrong).
 */

const EMAIL_RE = /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g;

/**
 * Test whether an evidence snippet from a maintainer-change finding indicates
 * a fully-trusted new-maintainer set. Returns true only when EVERY email
 * found in the snippet matches AT LEAST ONE trust anchor by the exact rules
 * above. If the snippet has an arrow `→` (which meta.ts uses), only emails
 * on the RIGHT side of the arrow are checked (the "new" side).
 */
export function isTrustedPublisher(
  evidenceText: string,
  trustList: readonly string[],
): boolean {
  if (trustList.length === 0) return false;

  // Prefer just the "new" side of a maintainer-change snippet when present.
  // meta.ts writes: `maintainers: [oldA, oldB] → [newA, newB]`
  const arrowIdx = evidenceText.lastIndexOf('→');
  const target = arrowIdx >= 0 ? evidenceText.slice(arrowIdx + 1) : evidenceText;

  const emails = target.match(EMAIL_RE) ?? [];
  if (emails.length === 0) return false;

  for (const email of emails) {
    if (!matchesAnyAnchor(email, trustList)) return false;
  }
  return true;
}

function matchesAnyAnchor(email: string, trustList: readonly string[]): boolean {
  const lcEmail = email.toLowerCase();
  const atIdx = lcEmail.indexOf('@');
  if (atIdx < 1 || atIdx === lcEmail.length - 1) return false; // malformed
  const local = lcEmail.slice(0, atIdx);
  const domain = lcEmail.slice(atIdx + 1);

  for (const anchor of trustList) {
    if (anchor.length < 3) continue; // defense-in-depth against config bypass
    const t = anchor.toLowerCase();

    if (t.startsWith('@')) {
      // domain-anchor: EXACT-match domain OR subdomain-suffix.
      const trustedDomain = t.slice(1);
      if (domain === trustedDomain) return true;
      if (domain.endsWith('.' + trustedDomain)) return true;
      continue;
    }

    if (t.includes('@')) {
      // full-email anchor: exact equality only.
      if (t === lcEmail) return true;
      continue;
    }

    // bare-username anchor: exact equality against local part.
    if (t === local) return true;
  }
  return false;
}

/**
 * Combine the built-in trust store with the user's config-provided one.
 * User-provided entries EXTEND the built-in list (never override) — this
 * prevents an attacker from removing trust anchors via a config file.
 */
export function effectiveTrustList(
  packageName: string,
  userConfig: Record<string, readonly string[]> | undefined,
): readonly string[] {
  const builtin = BUILTIN_TRUST_STORE[packageName] ?? [];
  const user = userConfig?.[packageName] ?? [];
  return [...builtin, ...user];
}
