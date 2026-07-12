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

export const ConfigSchema = z.object({
  version: z.literal(1).default(1),
  allowlist: z.record(z.string(), z.array(CategorySchema)).default({}),
  severityOverride: z.record(z.string(), SeveritySchema).default({}),
  ignorePackages: z.array(z.string()).default([]),
  ignorePathsInside: z.record(z.string(), z.array(z.string())).default({}),
  trustedPublishers: z.record(z.string(), z.array(z.string())).default({}),
  failOn: z.array(z.string()).default([]),
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
 */
export function applyConfig(findings: Finding[], config: VetlockConfig): Finding[] {
  return findings
    // Drop findings for ignored packages
    .filter((f) => !config.ignorePackages.includes(f.package))
    // Drop findings whose evidence-file falls under an ignore-path-inside
    .filter((f) => {
      const ignore = config.ignorePathsInside[f.package];
      if (!ignore || ignore.length === 0) return true;
      const first = f.evidence[0];
      if (!first) return true;
      return !ignore.some((prefix) => first.file.startsWith(prefix));
    })
    // Downgrade allowlisted-category findings on named packages to INFO
    .map((f) => {
      const allowed = config.allowlist[f.package];
      if (allowed && allowed.includes(f.category as DetectorCategory)) {
        return {
          ...f,
          severity: 'INFO' as Severity,
          message: `${f.message} [allowlisted: ${f.category} is expected for ${f.package}]`,
        };
      }
      return f;
    })
    // Apply per-detector severity overrides
    .map((f) => {
      const override = config.severityOverride[f.detector];
      if (override) return { ...f, severity: override };
      return f;
    })
    // Meta: if maintainer-change lists trusted publishers, downgrade
    .map((f) => {
      if (f.detector !== 'meta.maintainer-change') return f;
      const trusted = config.trustedPublishers[f.package];
      if (!trusted || trusted.length === 0) return f;
      const evidence = f.evidence[0]?.snippet ?? '';
      // A permissive check: if the evidence names any trusted publisher, downgrade
      if (trusted.some((t) => evidence.includes(t))) {
        return {
          ...f,
          severity: 'INFO' as Severity,
          message: `${f.message} [trusted: publisher on trust list]`,
        };
      }
      return f;
    });
}

/** Which detectors were force-failed by config? Used by exit-code logic. */
export function isForcedFailure(findings: Finding[], config: VetlockConfig): boolean {
  const failOnSet = new Set(config.failOn);
  return findings.some((f) => failOnSet.has(f.detector));
}
