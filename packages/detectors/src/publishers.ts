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
 * Match a publisher-string (email, username, or evidence snippet) against a
 * trust-store entry list. Substring match — the evidence snippet from a
 * maintainer-change finding usually contains BOTH the email and the human-
 * readable name.
 */
export function isTrustedPublisher(
  evidenceText: string,
  trustList: readonly string[],
): boolean {
  const lc = evidenceText.toLowerCase();
  for (const t of trustList) {
    if (lc.includes(t.toLowerCase())) return true;
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
