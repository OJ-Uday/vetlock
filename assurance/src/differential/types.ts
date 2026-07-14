/**
 * Differential-scanner types (packet §2.2 modality 3, §4 differential ledger metric).
 *
 * A `DifferentialScanner` runs a public vuln scanner (npm audit, osv-scanner, …) against
 * the SAME lockfile inputs vetlock sees. Findings the competitor catches that vetlock
 * doesn't are DELTAS. Every delta MUST be classified — packet rule: honest ledger, no
 * silent hits.
 *
 * The classification is deliberately blunt-instrument:
 *   - real-gap: competitor caught something vetlock missed AND it's in vetlock's scope
 *     (behavioral, not advisory-DB). File a coverage bug.
 *   - intentional-non-goal: competitor caught an advisory-DB CVE; vetlock is a behavioral
 *     analyzer, not a CVE lookup service. Documented as out-of-scope.
 *   - advisory-only: pure CVE lookup; same as above but for the ledger's second bucket.
 *     Some packet-users may treat this identically to intentional-non-goal; the split
 *     exists so the ledger can distinguish "we chose not to do this" from "this scanner
 *     is doing pure CVE work regardless of scope".
 *   - noise: false positive from the competitor. Documented but not actioned.
 */

export interface DifferentialScanner {
  readonly id: string;
  readonly name: string;
  /** Test whether the scanner is available on this host. Skips gracefully if not. */
  isAvailable(): Promise<boolean>;
  /** Run the scanner against a lockfile path. Returns normalized findings. */
  scan(lockfilePath: string): Promise<ScannerFinding[]>;
}

export interface ScannerFinding {
  readonly scanner: string; // scanner id
  readonly package: string;
  readonly severity: 'LOW' | 'MODERATE' | 'HIGH' | 'CRITICAL' | 'INFO';
  readonly cve?: string; // CVE-YYYY-NNNNN if present
  readonly title: string;
  readonly rawMessage: string;
}

export type DeltaClass =
  | 'real-gap' // competitor caught something vetlock missed AND it's in vetlock's scope
  | 'intentional-non-goal' // competitor caught an advisory-DB CVE; vetlock is behavioral, not advisory
  | 'advisory-only' // pure CVE lookup; not vetlock's scope
  | 'noise'; // false positive from competitor

export interface Delta {
  readonly finding: ScannerFinding;
  readonly class: DeltaClass;
  readonly rationale: string;
}

/** Serialized form of the ledger persisted to `assurance/report/differential-ledger.json`.
 *  Stable field order and stable formatting (2-space JSON) so `git diff` is meaningful. */
export interface LedgerFile {
  readonly version: 1;
  readonly generatedIso: string | null;
  readonly deltas: readonly Delta[];
  readonly pending: readonly ScannerFinding[];
}
