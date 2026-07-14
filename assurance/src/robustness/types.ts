/**
 * Robustness generator types.
 *
 * A generator is a PURE FUNCTION from a seed (and optional params) to a lockfile-shaped
 * input the engine's parseLockfileText will accept as a candidate. Purity + seed = every
 * failure replays byte-identically.
 *
 * Each generator declares:
 *   - kind: unique identifier for the report (e.g. "deep-nested-yaml")
 *   - filename: the filename hint the parser should use ("pnpm-lock.yaml" for YAML, etc.)
 *   - lockfileFormat: one of the four kinds the engine dispatches to
 *
 * Generators DO NOT know about the runner or oracles — they just produce inputs. The
 * robustness driver (in tests) wires them through the runner and asserts the oracle set.
 */

export type LockfileFormat = 'npm' | 'pnpm' | 'yarn-classic' | 'yarn-berry';

export interface LockfileInput {
  readonly text: string;
  readonly filename: string;
  readonly format: LockfileFormat;
}

/** A single generator run. */
export interface RobustnessGenerator<P = void> {
  /** Stable id; used in the ASSURANCE.md and in test names. */
  readonly id: string;
  /** One-line description; renders in the report. */
  readonly description: string;
  /** Which lockfile format this generator targets. */
  readonly format: LockfileFormat;
  /** Produce an input. Same (seed, params) always yield the same output. */
  generate(seed: number, params?: P): LockfileInput;
}
