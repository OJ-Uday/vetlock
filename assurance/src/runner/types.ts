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
 * Engine scenarios (P1 wires the actual @vetlock/core surface). Variants match the engine's
 * natural entrypoints, plus room to grow.
 *
 *   parseLockfileText   — pure text-in, DetectionResult-out. No detectors, no fetch, no
 *                         filesystem. Ideal target for parser-DoS / ReDoS / malformed-
 *                         lockfile robustness generators (packet §5 P1 first move).
 *   runDiff             — full-flow: two lockfile texts + a detector strategy. The detector
 *                         closure can't cross the worker boundary, so the caller picks a
 *                         symbolic `detectorMode` and the worker constructs the closure
 *                         locally. Wave 4-R now supports 'all' — dynamic-imports
 *                         @vetlock/detectors and wires runAll(pair) as runDetectors. 'none'
 *                         (no-op) remains for parser-DoS / ReDoS probes. 'parse-only'
 *                         (config-driven subset that skips fetch-dependent detectors) is
 *                         reserved as a future addition.
 *   extractCapabilities — text-in, FileCapabilities-out (per-file AST scan). Wave 3-O
 *                         addition. Unblocks Wave 1B-J's metamorphic tests, which need a
 *                         way to hand hostile-but-defanged source text to the engine's
 *                         AST scanner and inspect the emitted capability set.
 *   analyzeTarball      — tarball-path-in, PackageSnapshot-out (full pipeline: extract +
 *                         per-file scan + manifest read). Wave 3-O addition. Unblocks the
 *                         archive test vectors (Wave 3-M) which need to feed adversarial
 *                         tarballs (path-traversal, symlinks, size-bombs) through the real
 *                         extractor + analyzer end-to-end.
 *
 * All variants share `enginePath` so the worker can resolve them from a bare specifier
 * ('@vetlock/core') or an absolute path (useful when testing a specific dist tree).
 */
export type EngineScenario =
  | {
      readonly kind: 'engine:parseLockfileText';
      /** ESM specifier or absolute path the worker will `import()`. */
      readonly enginePath: string;
      /** Lockfile content to parse. */
      readonly text: string;
      /** Filename hint used by the engine's parser dispatcher (e.g. 'pnpm-lock.yaml'). */
      readonly filename?: string;
    }
  | {
      readonly kind: 'engine:runDiff';
      readonly enginePath: string;
      readonly oldLockfileText: string;
      readonly newLockfileText: string;
      readonly oldLockfilePath?: string;
      readonly newLockfilePath?: string;
      /**
       * Which detector closure the worker constructs.
       *   'none' — no-op detector closure; used for parser-DoS / ReDoS / graph-DoS
       *            robustness probes where detector output is irrelevant.
       *   'all'  — dynamic-imports @vetlock/detectors and wires runAll(pair) as the
       *            engine's runDetectors callback. This is what evasion-catch-rate +
       *            enumerated-coverage metrics need: real findings from real detectors.
       *   'parse-only' — reserved TODO. Would run a filtered subset that skips
       *            fetch-dependent detectors while still exercising the manifest/deps
       *            detectors that don't need tarball bodies. Not wired in Wave 4-R;
       *            add here + in both runEngine handlers when a caller needs it.
       */
      readonly detectorMode: 'none' | 'all';
      /** Fetch is disabled by default (this is an assurance harness — nothing hits the network).
       *  When true, the worker installs a fetchOverride that resolves to a benign empty tarball
       *  for every request; caller-supplied fetch is not accepted (structured-clone problem). */
      readonly disableFetch?: boolean;
    }
  | {
      readonly kind: 'engine:extractCapabilities';
      /** ESM specifier or absolute path the worker will `import()`. */
      readonly enginePath: string;
      /** Repo-relative path label shown in emitted findings (never opened on disk). */
      readonly relPath: string;
      /** Source text handed to the AST scanner. */
      readonly text: string;
      /** Optional sha256 of the bytes — passed through to extractCapabilities verbatim. */
      readonly sha256?: string;
      /** Optional byte count — defaults to text.length when omitted. */
      readonly bytes?: number;
    }
  | {
      readonly kind: 'engine:analyzeTarball';
      /** ESM specifier or absolute path the worker will `import()`. */
      readonly enginePath: string;
      /** Absolute path to a tarball on disk. The engine extracts + scans it in-process. */
      readonly tarballPath: string;
    };

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
