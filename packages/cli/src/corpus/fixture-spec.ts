/**
 * Corpus DSL — one FixtureSpec describes an attack scenario:
 *
 *   - clean:  package.json + files for the OLD (benign) version
 *   - malicious:  package.json + files for the NEW (attacker) version
 *   - expectations: which detector ids MUST fire, which MUST NOT, and
 *     the overall verdict.
 *
 * The corpus builder consumes a directory of these specs, produces
 * lockfile.before.json + lockfile.after.json + tarballs. The replay test
 * runs each fixture through vetlock and asserts the expectations.
 *
 * DEFANGED invariant: every URL literal in a fixture MUST resolve to an
 * unreachable RFC-2606 reserved domain (.invalid / .example / .test) or
 * loopback. corpus-defanged.test.ts greps every fixture for banned live-endpoint
 * patterns.
 */

export interface FixtureSpec {
  /** Slug (used as dirname): 'event-stream-2018', 'ua-parser-2021', … */
  id: string;
  /** Human-readable title for docs. */
  title: string;
  /** Year the attack occurred. */
  year: number;
  /** Threat class(es): 'T1 maintainer takeover', 'T2 transitive injection', etc. */
  threatClass: string;
  /** One-paragraph attack summary. */
  summary: string;
  /**
   * Provenance: 'PUBLISHED' (fixture built from the actual bytes, if we could
   * archive them before unpublish), 'RECONSTRUCTED' (built from postmortem
   * descriptions — this is the honest default and covers most entries).
   */
  provenance: 'PUBLISHED' | 'RECONSTRUCTED';
  /** Attack topology: 'direct' if the attack is in a direct dep of the app,
   *  'transitive' if the app depends on X which depends on the poisoned Y. */
  topology: 'direct' | 'transitive';
  /** The pre-attack (clean) state. */
  clean: PackageDefinition;
  /** The post-attack (malicious) state. */
  malicious: PackageDefinition;
  /**
   * If topology is 'transitive', these give the intermediate package that
   * (unwittingly) pulled the malicious dep in. Only 'clean' — a legitimate
   * package linking to the malicious package below it.
   */
  transitiveParent?: PackageDefinition;
  /** Expected findings from the run. */
  expect: Expectations;
}

/**
 * One package version's material: manifest fields + source files. Anything
 * omitted defaults sensibly.
 */
export interface PackageDefinition {
  name: string;
  version: string;
  manifest: Record<string, unknown>;
  files: Record<string, string>;
}

export interface Expectations {
  /**
   * Every detector id in this list MUST appear at least once in the findings.
   * Format: 'install.script-added', 'env.token-harvest', 'net.new-endpoint', etc.
   */
  mustFire: string[];
  /**
   * Every detector id in this list MUST NOT appear (used to lock in that we
   * don't over-flag benign parts of an attack).
   */
  mustNotFire?: string[];
  /** Overall verdict — usually 'BLOCK', 'WARN' for some cases, 'CLEAN' for the
   *  hard-miss cases where we honestly admit vetlock can't catch this. */
  verdict: 'BLOCK' | 'WARN' | 'INFO' | 'CLEAN';
  /**
   * Optional stricter check: exact per-package-per-detector counts. Used for
   * cases where we want to lock the shape of the finding set precisely.
   */
  minCategories?: string[]; // e.g. ['INSTALL', 'ENV', 'NET']
  /**
   * If the attack is genuinely hard to catch (e.g. logic bomb in a package
   * that already had FS write capability), set this to a truthy description.
   * The catch/miss table renders this row as "PARTIAL / MISS" honestly.
   */
  known_limitation?: string;
}
