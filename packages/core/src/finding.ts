/**
 * Universal finding schema — every detector emits values shaped like this.
 * Evidence is MANDATORY (non-empty); the schema validator enforces it.
 * Direction 'removed' never exceeds INFO (diff-framing invariant).
 */

export type Severity = 'BLOCK' | 'WARN' | 'INFO';
export type Confidence = 'high' | 'medium' | 'low';
export type Direction = 'added' | 'changed' | 'removed';

export type DetectorCategory =
  | 'NET'
  | 'EXEC'
  | 'FS'
  | 'ENV'
  | 'CODE'
  | 'OBF'
  | 'INSTALL'
  | 'META'
  | 'DEPS'
  | 'INTEG';

export interface Evidence {
  /** Path relative to package root (e.g. 'lib/util.js'). */
  file: string;
  /** 1-based line number. */
  line: number;
  /** Trimmed source snippet, ≤ 240 chars. */
  snippet: string;
}

export interface Finding {
  /** Stable dotted id, e.g. 'net.new-endpoint', 'install.script-added'. */
  detector: string;
  category: DetectorCategory;
  package: string;
  /** null when direction === 'added'. */
  from: string | null;
  /** null when direction === 'removed'. */
  to: string | null;
  direction: Direction;
  severity: Severity;
  confidence: Confidence;
  message: string;
  evidence: Evidence[];
  /** Up to 3 shortest paths root → node; overflow rendered as "+N more". */
  provenance: string[][];
}

/**
 * A frozen, parseable summary of one package version — the unit of caching.
 * Detectors read pairs of these; they never read tarballs directly.
 */
export interface PackageSnapshot {
  name: string;
  version: string;
  /** sha512 integrity string from lockfile ('sha512-…'). */
  integrity: string;
  /** Contents of package.json, verbatim. */
  manifest: PackageManifest;
  /**
   * Per-file capability extract. Files that failed to parse appear here with
   * parseError set — never dropped silently.
   */
  files: FileCapabilities[];
  /**
   * Native binary artifacts shipped in the tarball: `.node`, `.so`, `.dylib`,
   * `.dll`, `.exe`, `.wasm`, bare `.bin`. Populated by the analyzer; the
   * bin.new-native-artifact detector reads this.
   */
  nativeArtifacts: NativeArtifact[];
  /** Cache-format version; increment on breaking taxonomy changes. */
  formatVersion: number;
  /** When this snapshot was built (ISO). */
  builtAt: string;
}

export interface NativeArtifact {
  path: string;
  bytes: number;
  sha256: string;
  kind: 'node' | 'so' | 'dylib' | 'dll' | 'exe' | 'wasm' | 'bin';
}

export interface PackageManifest {
  name?: string;
  version?: string;
  main?: string;
  bin?: string | Record<string, string>;
  scripts?: Record<string, string>;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  maintainers?: Array<{ name?: string; email?: string }>;
  _npmUser?: { name?: string; email?: string };
  /** All other fields preserved for META detector. */
  [key: string]: unknown;
}

export interface FileCapabilities {
  path: string;
  bytes: number;
  /** sha256 of the file bytes (identify duplicates across snapshots). */
  sha256: string;
  parseError?: string;
  /** Shannon entropy of the file contents (0-8 bits/byte). */
  entropy: number;
  /** True iff we're confident this file is minified. */
  minified: boolean;
  /** Every network module import/require detected. */
  networkModules: string[];
  /** Every process/exec module detected. */
  execModules: string[];
  /** Every fs module detected. */
  fsModules: string[];
  /** Distinct string literals reaching URL/domain shape. */
  urlLiterals: string[];
  /**
   * URLs recovered from base64/hex decoding of long high-entropy string
   * literals. These are structurally suspect: real code rarely encodes URLs.
   */
  encodedUrls: EncodedUrl[];
  /** process.env access sites (whole-object enumeration or specific keys). */
  envAccesses: EnvAccess[];
  /** Dynamic code sinks (eval, new Function, vm, dynamic require). */
  dynamicCode: DynamicCodeSite[];
  /** File paths reached via literal-string args to fs writes. */
  fsWriteTargets: string[];
  /** File paths reached via literal-string args to fs reads (secret files). */
  fsReadTargets: string[];
  /** Very long string literals with high entropy — obfuscation candidates. */
  suspiciousLiterals: SuspiciousLiteral[];
}

export interface EncodedUrl {
  /** The URL that was recovered from the encoding. */
  url: string;
  /** Which encoding this was decoded from. */
  encoding: 'base64' | 'hex';
  line: number;
  /** The literal we decoded (truncated to 60 chars). */
  encodedPreview: string;
}

export interface EnvAccess {
  line: number;
  /** null == whole-object enumeration; else specific key(s). */
  keys: string[] | null;
  snippet: string;
}

export interface DynamicCodeSite {
  line: number;
  kind: 'eval' | 'new-function' | 'vm' | 'dynamic-require' | 'dynamic-import';
  snippet: string;
}

export interface SuspiciousLiteral {
  line: number;
  length: number;
  entropy: number;
  preview: string; // first 40 chars
}

export interface SnapshotPair {
  /** null iff direction === 'added' (new node has no prior snapshot). */
  old: PackageSnapshot | null;
  /** null iff direction === 'removed'. */
  new: PackageSnapshot | null;
}

export interface DetectorContext {
  /**
   * Called by detectors that need to know the direction they're running in
   * (added vs changed vs removed). Computed once per pair.
   */
  direction: Direction;
}

export interface Detector {
  id: string;
  category: DetectorCategory;
  run(pair: SnapshotPair, ctx: DetectorContext): Finding[];
}

/**
 * Validate a Finding against the schema invariants.
 * Returns null if valid; otherwise a human-readable error.
 */
export function validateFinding(f: Finding): string | null {
  if (!f.detector) return 'missing detector id';
  if (!f.category) return 'missing category';
  if (!f.package) return 'missing package';
  if (!f.evidence || f.evidence.length === 0) {
    return 'evidence array is mandatory and must be non-empty';
  }
  for (const e of f.evidence) {
    if (!e.file || typeof e.line !== 'number' || !e.snippet) {
      return `invalid evidence entry: ${JSON.stringify(e)}`;
    }
  }
  if (f.direction === 'added' && f.from !== null) {
    return "direction 'added' requires from === null";
  }
  if (f.direction === 'removed') {
    if (f.to !== null) return "direction 'removed' requires to === null";
    // Diff-framing: removals never exceed INFO.
    if (f.severity !== 'INFO') {
      return "direction 'removed' cannot exceed INFO severity (diff-framing invariant)";
    }
  }
  return null;
}
