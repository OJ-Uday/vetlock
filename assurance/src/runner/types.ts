/**
 * Runner types (ADR-0003).
 *
 * A Scenario is a structured-clone-safe descriptor of what the worker should do.
 * P0 defines a set of built-in synthetic scenarios (hang / crash / oom / normal / fail-safe)
 * used exclusively by the runner's self-tests. P1 introduces the `engine` scenario, which
 * dynamically imports @vetlock/core and calls its public analyze entrypoint.
 *
 * Keeping the scenario as data (not a function) is deliberate: functions don't structured-
 * clone across the worker boundary; data does. The worker script switches on `kind`.
 */

/** Synthetic scenarios for runner self-tests only. Never used against the engine. */
export type SyntheticScenario =
  | {
      readonly kind: 'synthetic:normal';
      /** How many milliseconds of pretend work to do before returning. Small (< 100ms). */
      readonly workMs?: number;
      /** Findings to return in the ok outcome. */
      readonly findings?: readonly {
        readonly capabilityClass: string;
        readonly severity: 'INFO' | 'FLAG' | 'BLOCK';
        readonly reason: string;
      }[];
    }
  | {
      readonly kind: 'synthetic:hang';
      /** Busy-loop OR await-a-never-resolving-promise. Either must be caught by the wallMs bound. */
      readonly mode?: 'busy-loop' | 'await-forever';
    }
  | {
      readonly kind: 'synthetic:crash';
      readonly errorName?: string;
      readonly errorMessage?: string;
    }
  | {
      readonly kind: 'synthetic:oom';
      /** Growth strategy for allocating past the heap cap. */
      readonly mode?: 'grow-array' | 'grow-string' | 'grow-buffer';
    }
  | {
      readonly kind: 'synthetic:fail-safe';
      readonly reason?: string;
      readonly capabilityClass?: string;
    };

/**
 * Engine scenario (P1 introduces the actual wiring). The worker will `import()` the module
 * at `enginePath` and call `entry(input)`. Kept in the union so the runner API is stable
 * from P0 forward.
 */
export interface EngineScenario {
  readonly kind: 'engine';
  /** ESM specifier or absolute path the worker will `import()`. */
  readonly enginePath: string;
  /** Name of the export to call. */
  readonly entry: string;
  /** Argument to pass to the entry — must be structured-clone-safe. */
  readonly input: unknown;
}

export type Scenario = SyntheticScenario | EngineScenario;

/** The public interface an engine analyze function must satisfy. Documented here for P1. */
export interface AnalyzeFn {
  (input: unknown, ctl: RunControl): Promise<{
    findings: ReadonlyArray<{
      capabilityClass: string;
      severity: 'INFO' | 'FLAG' | 'BLOCK';
      reason: string;
      location?: { file: string; line?: number; column?: number };
      meta?: Record<string, unknown>;
    }>;
    /** Optional signal from the engine that it hit its own give-up path. */
    failSafe?: { reason: string };
  }>;
}

/** Passed to the engine's analyze function. Present shape is minimal for P0. */
export interface RunControl {
  /** Deadline (Date.now()-style ms) after which the engine should abort. Advisory; the runner
   *  will hard-terminate the worker at the same instant regardless. */
  readonly deadlineMs: number;
  /** The seed the runner is using. Engines that want deterministic sub-behavior can read this. */
  readonly seed: number;
}
