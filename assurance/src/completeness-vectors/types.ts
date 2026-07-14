/**
 * Completeness vector transform types (packet §2.2, §5 P3).
 *
 * A "completeness vector" is a **semantics-preserving code-normalization transform**.
 * Applied to a source string that references a known capability class (e.g.
 * `child_process.exec("echo foo")` — code-execution class), the transform yields a
 * *syntactically different but semantically identical* source string. If the
 * scanner catches the original but misses the transform, the scanner's coverage of
 * that class has a gap — a spelling of the capability the map thinks it covers
 * but doesn't.
 *
 * A `CompletenessTransform` is a PURE function of `(source, seed)`:
 *   - Same `(source, seed)` → byte-identical output every time.
 *   - No I/O, no globals, no hidden state — the whole point is deterministic replay
 *     of any completeness gap the corpus pins.
 *
 * Transforms DO NOT know about the runner, the engine, or the defang guard. They
 * simply transform code. The completeness driver (test surface) wires them through
 * `oracleFindingSurvives(beforeOutcome, afterOutcome, targetClass)`.
 *
 * The three families this file supports:
 *
 *   - `sink-family-widening`   — widen a call within a capability family to a
 *     documented sibling API (`exec` → `execFile`; `http.request` → `https.request`).
 *     If the scanner detects only the "canonical" sink and not its siblings, the
 *     class is incomplete.
 *
 *   - `string-normalization`   — convert a string literal into an equivalent
 *     syntactic form (concat / template / `String.fromCharCode`). A capable scanner
 *     constant-folds; a weak one only matches the literal shape.
 *
 *   - `code-location`          — move the payload to a different location in the
 *     package layout without changing its semantics (nest a file; move code into a
 *     `postinstall` script body). If the scanner only looks at `index.js`, the
 *     class is location-incomplete.
 */

/** Family taxonomy — kept as a string-union so downstream reporting is exhaustive. */
export type CompletenessFamily =
  | 'sink-family-widening'
  | 'string-normalization'
  | 'code-location';

/** A single completeness transform. */
export interface CompletenessTransform {
  /** Stable id, unique within a family (e.g. `exec-to-execFile`). Used in reports and test names. */
  readonly id: string;
  /** Family the transform belongs to. */
  readonly family: CompletenessFamily;
  /** Capability class this transform preserves (e.g. `code-execution`, `net-egress`). */
  readonly targetClass: string;
  /** One-line rationale — what completeness edge case the transform tests. */
  readonly description: string;
  /**
   * Transform `source` to a semantically-equivalent variant. PURE — same
   * `(source, seed)` always yields byte-identical output. Deterministic replay is
   * the whole invariant that lets any gap pin as a corpus regression.
   *
   * If the transform's target pattern is not present in `source`, the transform is
   * a no-op and returns `source` unchanged. Callers can detect this with a strict
   * equality check (see the "non-triviality" test).
   */
  transform(source: string, seed: number): string;
}
