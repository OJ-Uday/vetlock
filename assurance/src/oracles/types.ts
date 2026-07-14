/**
 * Types shared by the runner (ADR-0003) and the oracle set.
 *
 * These value shapes cross the worker_thread boundary via `structuredClone`, so they must be
 * plain data: no functions, no `Error` instances, no cyclic refs. Errors are represented via
 * `SerializedError`. Findings are a plain JSON value.
 */

/** A single detector finding. Kept intentionally minimal — the engine's real shape is richer,
 *  but the harness only depends on this subset for its oracles. Extending is safe. */
export interface Finding {
  /** Capability class — one of the CAPABILITY-MAP class ids (STARTUP §3.5).
   *  Examples: 'code-execution', 'net-egress', 'fs-write', 'env/secret-read'. */
  readonly capabilityClass: string;
  /** Detector-defined severity. The runner never interprets this; the oracles only compare. */
  readonly severity: 'INFO' | 'FLAG' | 'BLOCK';
  /** Human-readable reason. Not compared by identity-invariance normalization. */
  readonly reason: string;
  /** Optional source location for the finding. Compared under normalization. */
  readonly location?: {
    readonly file: string;
    readonly line?: number;
    readonly column?: number;
  };
  /** Free-form structured extras from the detector. Compared under normalization when present. */
  readonly meta?: Readonly<Record<string, unknown>>;
}

export type Findings = readonly Finding[];

/** Serialized shape of an Error crossing a worker boundary. */
export interface SerializedError {
  readonly name: string;
  readonly message: string;
  readonly stack?: string;
  /** Any structured payload from the engine's error taxonomy (e.g., detector id). */
  readonly cause?: unknown;
}

/** Bounds enforced by the runner (ADR-0003). */
export interface Bounds {
  /** Hard wall-clock cap. Timer fires at this; worker is terminated. */
  readonly wallMs: number;
  /** Hard heap cap for the worker. Passed as `resourceLimits.maxOldGenerationSizeMb`. */
  readonly heapMb: number;
  /** Seed for any RNG used by input generators. Echoed in the outcome and the report. */
  readonly seed: number;
}

/** The runner's discriminated result. Every engine invocation resolves to exactly one of these. */
export type RunOutcome =
  | {
      readonly kind: 'ok';
      readonly findings: Findings;
      readonly wallMs: number;
      readonly peakRssBytes: number;
      readonly seed: number;
    }
  | {
      readonly kind: 'timeout';
      readonly wallMs: number;
      readonly seed: number;
    }
  | {
      readonly kind: 'oom';
      readonly peakRssBytes: number;
      readonly seed: number;
    }
  | {
      readonly kind: 'crash';
      readonly error: SerializedError;
      readonly wallMs: number;
      readonly seed: number;
    }
  | {
      readonly kind: 'fail-safe';
      /** The engine returned a BLOCK finding with reason `analysis-failed` (or equivalent).
       *  This is the *good* path when a detector errors internally; see ADR-0003 fail-safe convention. */
      readonly reason: string;
      readonly findings: Findings;
      readonly wallMs: number;
      readonly seed: number;
    };

/** Every oracle returns this. Failures carry a reason a human can act on. */
export interface OracleResult {
  readonly oracle: string;
  readonly pass: boolean;
  /** Present on failure; describes what went wrong in words the report will render. */
  readonly reason?: string;
  /** Present on failure; the outcome(s) that failed the oracle. Pair oracles include both. */
  readonly evidence?: Readonly<Record<string, unknown>>;
}
