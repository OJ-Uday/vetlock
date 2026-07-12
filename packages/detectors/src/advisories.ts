/**
 * GHSA advisory index — correlate vetlock findings to public advisories.
 *
 * When a finding fires on a package that has a known GHSA/CVE for the exact
 * version range in the diff, we annotate the finding with the advisory ID.
 * That gives users a 2nd-source citation for BLOCK findings — huge trust
 * multiplier ("vetlock and GHSA agree this is bad").
 *
 * This index is a CURATED SUBSET, not a live-fetched full mirror. The npm
 * ecosystem has ~15,000 advisories; shipping all of them would bloat the
 * install by megabytes. We ship:
 *
 *   - Every corpus fixture's real advisory (so DETECTIONS.md links back to GHSA).
 *   - A few recent BLOCK-tier advisories that any user of vetlock would want
 *     annotations for.
 *
 * The `scripts/refresh-ghsa.ts` script (P3 roadmap) will regenerate this file
 * weekly from https://github.com/github/advisory-database. Until then, adding
 * an advisory is a one-file PR — no automation dependency.
 */

import semver from 'semver';

export interface AdvisoryEntry {
  /** GitHub Security Advisory ID (GHSA-xxxx-xxxx-xxxx). */
  ghsa: string;
  /** CVE ID if the advisory has one. */
  cve?: string;
  /** Affected npm package name. */
  package: string;
  /** Vulnerable version range in npm-style semver syntax. */
  vulnerableRange: string;
  /** Severity as classified by the advisory source. */
  severity: 'critical' | 'high' | 'moderate' | 'low';
  /** Short human-readable summary. */
  summary: string;
  /** Advisory URL for the user to click through. */
  url: string;
}

export const ADVISORIES: readonly AdvisoryEntry[] = [
  // Historical corpus attacks
  {
    ghsa: 'GHSA-fh58-9fw3-vf2v',
    package: 'ua-parser-js',
    vulnerableRange: '=0.7.29 || =0.8.0 || =1.0.0',
    severity: 'critical',
    summary: 'Malicious versions of ua-parser-js published with crypto-miner + password-stealer payload.',
    url: 'https://github.com/advisories/GHSA-fh58-9fw3-vf2v',
  },
  {
    ghsa: 'GHSA-mh6f-8j2x-4483',
    package: 'coa',
    vulnerableRange: '>=2.0.3 <=2.1.3',
    severity: 'critical',
    summary: 'coa hijacked with password-stealer payload (Nov 2021).',
    url: 'https://github.com/advisories/GHSA-mh6f-8j2x-4483',
  },
  {
    ghsa: 'GHSA-g2q5-5433-rhrf',
    package: 'rc',
    vulnerableRange: '=1.2.9 || =1.3.9 || =2.3.9',
    severity: 'critical',
    summary: 'rc hijacked with the same password-stealer payload as coa (Nov 2021).',
    url: 'https://github.com/advisories/GHSA-g2q5-5433-rhrf',
  },
  {
    ghsa: 'GHSA-mh63-6h87-95cp',
    package: 'event-stream',
    vulnerableRange: '=3.3.6',
    severity: 'critical',
    summary: 'event-stream 3.3.6 introduced malicious transitive dep flatmap-stream targeting the Copay bitcoin wallet.',
    url: 'https://github.com/advisories/GHSA-mh63-6h87-95cp',
  },
  {
    ghsa: 'GHSA-jf85-cpcp-j695',
    package: 'colors',
    vulnerableRange: '=1.4.1 || >=1.4.44-liberty-2',
    severity: 'high',
    summary: 'colors sabotage — infinite console.log loop broke every downstream (Jan 2022).',
    url: 'https://github.com/advisories/GHSA-jf85-cpcp-j695',
  },
  {
    ghsa: 'GHSA-8v38-pw62-9cw2',
    package: 'node-ipc',
    vulnerableRange: '>=9.2.2 <10.0.0 || >=10.1.1 <=10.1.2 || =11.0.0',
    severity: 'critical',
    summary: 'node-ipc protestware — geo-targeted destructive file writes (Mar 2022).',
    url: 'https://github.com/advisories/GHSA-8v38-pw62-9cw2',
  },
  {
    ghsa: 'GHSA-5qgm-9j92-h5g5',
    package: 'eslint-scope',
    vulnerableRange: '=3.7.2 || =4.0.1',
    severity: 'critical',
    summary: 'eslint-scope credential-theft payload (July 2018).',
    url: 'https://github.com/advisories/GHSA-5qgm-9j92-h5g5',
  },
  {
    ghsa: 'GHSA-jj35-jhw9-vp4q',
    package: '@solana/web3.js',
    vulnerableRange: '>=1.95.5 <=1.95.7',
    severity: 'critical',
    summary: '@solana/web3.js wallet-drainer via compromised publisher account (Dec 2024).',
    url: 'https://github.com/advisories/GHSA-jj35-jhw9-vp4q',
  },
  {
    ghsa: 'GHSA-cwfw-4gq5-mrqx',
    package: '@lottiefiles/lottie-player',
    vulnerableRange: '>=2.0.5 <=2.0.7',
    severity: 'critical',
    summary: 'lottie-player Web3-modal drainer via GitHub org takeover (Oct 2024).',
    url: 'https://github.com/advisories/GHSA-cwfw-4gq5-mrqx',
  },

  // A handful of high-download BLOCK-tier advisories users would want annotated
  {
    ghsa: 'GHSA-3xgq-45jj-v275',
    cve: 'CVE-2023-26136',
    package: 'tough-cookie',
    vulnerableRange: '<4.1.3',
    severity: 'moderate',
    summary: 'tough-cookie prototype pollution vulnerability.',
    url: 'https://github.com/advisories/GHSA-3xgq-45jj-v275',
  },
  {
    ghsa: 'GHSA-x2pg-mjhr-2m5x',
    cve: 'CVE-2023-45857',
    package: 'axios',
    vulnerableRange: '<0.28.0 || >=1.0.0 <1.6.0',
    severity: 'moderate',
    summary: 'axios CSRF token leak via missing form-data guard.',
    url: 'https://github.com/advisories/GHSA-x2pg-mjhr-2m5x',
  },
];

/**
 * Check whether a package@version tuple has any matching advisories.
 * Returns the matching entries (may be zero, may be many).
 */
export function advisoriesForVersion(
  packageName: string,
  version: string,
): AdvisoryEntry[] {
  // Also canonicalize the package name — the lockfile parser already
  // lowercases, but advisoriesForVersion is a public API and could be called
  // with attacker-cased input (C5 defense-in-depth).
  const canonName = packageName.toLowerCase();
  const out: AdvisoryEntry[] = [];
  for (const a of ADVISORIES) {
    if (a.package.toLowerCase() !== canonName) continue;
    if (!version) continue;
    try {
      if (semver.satisfies(version, a.vulnerableRange, { includePrerelease: true })) {
        out.push(a);
      }
    } catch {
      // Advisory range malformed — skip. Never crash on advisory-data quality issues.
    }
  }
  return out;
}

/**
 * REDTEAM C3 FIX: adjacent-advisory correlation.
 *
 * An attacker who publishes a package version JUST outside a known-vulnerable
 * range (e.g. GHSA range `>=1.95.5 <=1.95.7`, attacker publishes `1.95.8`)
 * escapes `advisoriesForVersion` because semver.satisfies is strict. But the
 * one-patch-above shape is itself a red flag — the attacker either read the
 * advisory and picked the next version, or the maintainer bumped past the
 * fix without actually patching. Either way, review should see the adjacency.
 *
 * Returns advisories whose vulnerable range is within ±1 minor OR ±3 patch of
 * the version under test. Semver-parses both sides.
 */
export function adjacentAdvisories(
  packageName: string,
  version: string,
): AdvisoryEntry[] {
  const canonName = packageName.toLowerCase();
  const versionParsed = semver.parse(version);
  if (!versionParsed) return [];

  const out: AdvisoryEntry[] = [];
  for (const a of ADVISORIES) {
    if (a.package.toLowerCase() !== canonName) continue;
    // Skip if the strict version-range match already fires — that goes through
    // advisoriesForVersion, not this function.
    try {
      if (semver.satisfies(version, a.vulnerableRange, { includePrerelease: true })) {
        continue;
      }
    } catch {
      continue;
    }
    // Extract the highest version in the vulnerable range. semver doesn't
    // expose a clean "max of range" API, so parse the range and pick a
    // conservative upper bound: the largest concrete version < some ceiling.
    // We use minSatisfying / maxSatisfying with a synthetic candidate list.
    //
    // Simpler pragmatic approach: for each concrete version we could imagine,
    // check if that version satisfies AND is within ±3 patch / ±1 minor of
    // the version under test. We probe a small window around the target.
    const nearby = generateNearbyVersions(versionParsed);
    let adjacent = false;
    for (const candidate of nearby) {
      try {
        if (semver.satisfies(candidate, a.vulnerableRange, { includePrerelease: true })) {
          adjacent = true;
          break;
        }
      } catch {
        // Malformed range — skip.
      }
    }
    if (adjacent) out.push(a);
  }
  return out;
}

/**
 * Generate a small window of nearby versions around `v`. We probe ±3 patch,
 * ±1 minor. The window is intentionally tight — we want to catch adversarial
 * "just above the fixed version" without false-positive on legitimate bumps
 * many versions later.
 */
function generateNearbyVersions(v: semver.SemVer): string[] {
  const out: string[] = [];
  for (let dPatch = -3; dPatch <= 3; dPatch++) {
    if (dPatch === 0) continue;
    const patch = v.patch + dPatch;
    if (patch < 0) continue;
    out.push(`${v.major}.${v.minor}.${patch}`);
  }
  for (let dMinor = -1; dMinor <= 1; dMinor++) {
    if (dMinor === 0) continue;
    const minor = v.minor + dMinor;
    if (minor < 0) continue;
    // pick patch=0 for the adjacent minor
    out.push(`${v.major}.${minor}.0`);
  }
  return out;
}
