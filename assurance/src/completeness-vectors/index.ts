/**
 * @vetlock/assurance completeness-vector transforms (packet §2.2, §5 P3).
 *
 * A completeness vector is a semantics-preserving code-normalization transform. If
 * the scanner catches an input but MISSES its transform, the scanner has a
 * completeness gap — a spelling of the same capability class it thinks it covers.
 *
 * Three families ship in this wave:
 *
 *   • sink-family-widening — widen a call to a documented sibling API (`exec` →
 *     `execFile`, `http.request` → `https.request`). Class-preserving.
 *
 *   • string-normalization — convert a capability-relevant string literal into an
 *     equivalent syntactic form (concat / template / `String.fromCharCode`).
 *     Constant-fold equivalent.
 *
 *   • code-location — move the payload to a different location in the package
 *     layout (postinstall lifecycle script; nested file under `lib/`). Content
 *     unchanged; only where the scanner has to look changes.
 *
 * Every transform is pure: same `(source, seed)` → byte-identical output. The
 * `allTransforms` array is the canonical enumeration and drives the completeness
 * assertions in the test surface.
 */

export type { CompletenessFamily, CompletenessTransform } from './types.js';

export {
  execToExecFile,
  execToSpawn,
  httpRequestToHttpsRequest,
} from './sink-family-widening.js';

export {
  literalToConcat,
  literalToTemplate,
  literalToCharCodeRebuild,
} from './string-normalization.js';

export {
  intoLifecycleScript,
  intoNestedFile,
  NESTED_FILE_MARKER_PREFIX,
} from './code-location.js';

import type { CompletenessTransform } from './types.js';
import {
  execToExecFile,
  execToSpawn,
  httpRequestToHttpsRequest,
} from './sink-family-widening.js';
import {
  literalToConcat,
  literalToTemplate,
  literalToCharCodeRebuild,
} from './string-normalization.js';
import {
  intoLifecycleScript,
  intoNestedFile,
} from './code-location.js';

/**
 * Canonical enumeration of transforms. Stable order — the report and the test
 * matrix iterate in this exact sequence, so any re-ordering is a visible diff.
 * Grouped by family for readability.
 */
export const allTransforms: readonly CompletenessTransform[] = [
  // sink-family-widening
  execToExecFile,
  execToSpawn,
  httpRequestToHttpsRequest,
  // string-normalization
  literalToConcat,
  literalToTemplate,
  literalToCharCodeRebuild,
  // code-location
  intoLifecycleScript,
  intoNestedFile,
];
