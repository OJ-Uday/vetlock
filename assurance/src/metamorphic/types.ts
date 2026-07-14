/**
 * Metamorphic pair types (packet §2.2, §5 P3).
 *
 * A "metamorphic pair" is two source strings that MUST behave identically at runtime:
 * same imports, same effects, same escapes. If the analyzer produces different
 * capability findings on `a` and `b`, its decision surface is inconsistent — a
 * completeness gap the map should close.
 *
 * A `PairGenerator` is a PURE function from a numeric seed to a `MetamorphicPair`.
 * Same seed → byte-identical pair. This is the invariant that lets a failing pair be
 * pinned as a corpus regression and replayed forever.
 *
 * Generators DO NOT know about the runner, the oracles, or the engine — they only
 * produce inputs. The invariance driver wires them through `oracleIdentityInvariant`.
 */

/** A single semantically-identical program pair. */
export interface MetamorphicPair {
  /** Stable id, unique within a family. Used in reports and test names. */
  readonly id: string;
  /** Family this pair belongs to (e.g. 'statement-reorder'). */
  readonly family: string;
  /** Program A source. Valid JS. */
  readonly a: string;
  /** Program B source. Valid JS. Semantically identical to A. */
  readonly b: string;
  /** One-line rationale for the pair — what capability edge case it targets. */
  readonly description: string;
}

/** A pair generator. */
export interface PairGenerator {
  /** Family id — the shared category (e.g. 'alpha-rename'). */
  readonly family: string;
  /** One-line description of what this family tests. */
  readonly description: string;
  /** Produce a pair. Same seed always yields byte-identical output. */
  generate(seed: number): MetamorphicPair;
}
