/**
 * .vetlock.json config file — user-configurable behavior.
 *
 * Schema-validated via `zod`. Any invalid config yields a clear pointer to the
 * offending path; better than a silent partial-parse.
 *
 * Fields:
 *   allowlist         Per-package capability allowlist. Findings in ALLOWED
 *                     categories on named packages are downgraded to INFO.
 *                     e.g. { "axios": ["NET"] } — expected axios capabilities.
 *   severityOverride  Per-detector severity override.
 *                     e.g. { "install.script-added": "WARN" } to soften.
 *   ignorePackages    Packages to skip entirely. Use for known-good internal
 *                     packages that trip false positives.
 *   ignorePathsInside Per-package: glob-like path prefixes inside the package
 *                     that should NOT be analyzed. e.g. { "foo": ["test/", "examples/"] }
 *   trustedPublishers Per-package: emails/names allowed as publisher.
 *                     meta.maintainer-change is INFO instead of WARN when
 *                     the new maintainer is on this list.
 *   failOn            Detector IDs that force exit code 2 even at WARN level.
 */

import { z } from 'zod';
import type {
  DetectorCategory,
  Finding,
  Severity,
} from './finding.js';

const CategorySchema = z.enum([
  'NET', 'EXEC', 'FS', 'ENV', 'CODE', 'OBF', 'INSTALL', 'META', 'DEPS', 'INTEG',
]);
const SeveritySchema = z.enum(['BLOCK', 'WARN', 'INFO']);

/**
 * Empty-string / wildcard-degeneration guard for config string values.
 *
 * The red-team pass found D2 and D3: an attacker who can add a `.vetlock.json`
 * to a malicious PR (see task #1: don't-trust-in-diff-config, separate fix)
 * could set `ignorePathsInside: { "attacker-pkg": [""] }` and every
 * `file.startsWith("")` returns true, dropping every finding. Same for
 * `trustedPublishers: { "chalk": [""] }` where `evidence.includes("")` is
 * unconditionally true.
 *
 * Defense: reject empty strings, whitespace-only strings, and single-char
 * pathological inputs at schema time. Any legitimate publisher/path prefix is
 * at least 3 characters (`.js`, `foo`, `sindresorhus`); anything shorter is
 * either a mistake or an attack.
 *
 * This is a security decision, not a UX decision. See docs/SECURITY-DECISIONS.md:
 * when config-supplied strings feed into `.includes()` or `.startsWith()`
 * predicates, they MUST have a minimum length.
 */
const NON_EMPTY_STRING = z
  .string()
  .min(3, 'must be at least 3 characters (empty or short strings cause `.includes()`/`.startsWith()` to match everything)')
  .refine((s) => s.trim().length >= 3, 'must not be whitespace-only');

/** Package names — allow shorter (real npm names go down to 1 char in edge cases). */
const PACKAGE_NAME_STRING = z.string().min(1);

export const ConfigSchema = z.object({
  version: z.literal(1).default(1),
  allowlist: z.record(PACKAGE_NAME_STRING, z.array(CategorySchema)).default({}),
  severityOverride: z.record(NON_EMPTY_STRING, SeveritySchema).default({}),
  ignorePackages: z.array(PACKAGE_NAME_STRING).default([]),
  // The values here feed .startsWith() — empty string would match every path.
  ignorePathsInside: z.record(PACKAGE_NAME_STRING, z.array(NON_EMPTY_STRING)).default({}),
  // The values here feed .includes() — empty string would match every evidence.
  trustedPublishers: z.record(PACKAGE_NAME_STRING, z.array(NON_EMPTY_STRING)).default({}),
  failOn: z.array(NON_EMPTY_STRING).default([]),
}).strict();

export type VetlockConfig = z.infer<typeof ConfigSchema>;

export const DEFAULT_CONFIG: VetlockConfig = {
  version: 1,
  allowlist: {},
  severityOverride: {},
  ignorePackages: [],
  ignorePathsInside: {},
  trustedPublishers: {},
  failOn: [],
};

export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ConfigError';
  }
}

/** Parse config JSON text; throws ConfigError on validation failure. */
export function parseConfig(json: string): VetlockConfig {
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch (e) {
    throw new ConfigError(`.vetlock.json is not valid JSON: ${(e as Error).message}`);
  }
  const result = ConfigSchema.safeParse(parsed);
  if (!result.success) {
    const issues = result.error.issues
      .map((i) => `  - ${i.path.join('.')}: ${i.message}`)
      .join('\n');
    throw new ConfigError(`.vetlock.json failed validation:\n${issues}`);
  }
  return result.data;
}

/**
 * Apply the config to a list of findings — downgrade allowlisted-category
 * findings on named packages, apply per-detector severity overrides, drop
 * findings for ignored packages, and re-check trusted publishers.
 *
 * Defensive: even if a malformed config bypasses the zod schema (e.g. by
 * being constructed programmatically), we filter out empty-string prefixes
 * and trust anchors at each `.startsWith` / `.includes` predicate. This is
 * a second layer of the D2/D3 fix — schema is the first layer.
 *
 * REDTEAM D1 FIX: findings whose detector is in ALWAYS_APPLY_DETECTORS are
 * exempt from ignorePackages/ignorePathsInside, severityOverride, and
 * allowlist downgrading — applyConfig cannot drop or soften them.
 */
export function applyConfig(findings: Finding[], config: VetlockConfig): Finding[] {
  // Strip severityOverride entries that target always-apply detectors (D1 fix).
  const safeConfig = filterConfigOverrides(config);

  return findings
    // Drop findings for ignored packages
    .filter((f) => ALWAYS_APPLY_DETECTORS.has(f.detector) || !safeConfig.ignorePackages.includes(f.package))
    // Drop findings whose evidence-file falls under an ignore-path-inside.
    // Empty/whitespace prefixes are ignored here (D2 defense-in-depth).
    .filter((f) => {
      if (ALWAYS_APPLY_DETECTORS.has(f.detector)) return true;
      const ignore = safeConfig.ignorePathsInside[f.package];
      if (!ignore || ignore.length === 0) return true;
      const first = f.evidence[0];
      if (!first) return true;
      const safePrefixes = ignore.filter((p) => p != null && p.trim().length >= 3);
      if (safePrefixes.length === 0) return true;
      return !safePrefixes.some((prefix) => first.file.startsWith(prefix));
    })
    // Downgrade allowlisted-category findings on named packages to INFO.
    // ALWAYS_APPLY_DETECTORS findings are exempt.
    .map((f) => {
      if (ALWAYS_APPLY_DETECTORS.has(f.detector)) return f;
      const allowed = safeConfig.allowlist[f.package];
      if (allowed && allowed.includes(f.category as DetectorCategory)) {
        return {
          ...f,
          severity: 'INFO' as Severity,
          message: `${f.message} [allowlisted: ${f.category} is expected for ${f.package}]`,
        };
      }
      return f;
    })
    // Apply per-detector severity overrides (already stripped for always-apply).
    .map((f) => {
      const override = safeConfig.severityOverride[f.detector];
      if (override) return { ...f, severity: override };
      return f;
    })
    // Meta: if maintainer-change lists trusted publishers, downgrade.
    // Empty/whitespace trust anchors are ignored (D3 defense-in-depth).
    .map((f) => {
      if (f.detector !== 'meta.maintainer-change') return f;
      const trusted = safeConfig.trustedPublishers[f.package];
      if (!trusted || trusted.length === 0) return f;
      const safeAnchors = trusted.filter((t) => t != null && t.trim().length >= 3);
      if (safeAnchors.length === 0) return f;
      const evidence = f.evidence[0]?.snippet ?? '';
      if (safeAnchors.some((t) => evidence.includes(t))) {
        return {
          ...f,
          severity: 'INFO' as Severity,
          message: `${f.message} [trusted: publisher on trust list]`,
        };
      }
      return f;
    });
}

// REDTEAM S2/C1/C2/D1 FIX: detectors in this set are always applied at their
// native severity — config cannot silence or downgrade them.
// - integrity.hash-mismatch: T5 unconditional-BLOCK invariant; D1 showed that
//   severityOverride can otherwise neuter the tripwire.
// - analysis.failed: when an engine error makes a package unanalyzable the
//   caller should see a BLOCK, not a silenced INFO.
export const ALWAYS_APPLY_DETECTORS: ReadonlySet<string> = new Set([
  'integrity.hash-mismatch',
  'analysis.failed',
]);

/**
 * Return a copy of `config` with any severityOverride entries targeting
 * ALWAYS_APPLY_DETECTORS stripped out.
 *
 * Concretely: this function only removes detector ids from severityOverride.
 * applyConfig itself enforces the matching ALWAYS_APPLY exemptions for
 * ignorePackages, ignorePathsInside, and allowlist handling.
 *
 * Called by applyConfig — callers do NOT need to call this separately.
 */
export function filterConfigOverrides(config: VetlockConfig): VetlockConfig {
  const safeOverride: Record<string, Severity> = {};
  for (const [det, sev] of Object.entries(config.severityOverride)) {
    if (!ALWAYS_APPLY_DETECTORS.has(det)) {
      safeOverride[det] = sev;
    }
  }
  return { ...config, severityOverride: safeOverride };
}

/** Which detectors were force-failed by config? Used by exit-code logic. */
export function isForcedFailure(findings: Finding[], config: VetlockConfig): boolean {
  const failOnSet = new Set(config.failOn);
  return findings.some((f) => failOnSet.has(f.detector));
}
