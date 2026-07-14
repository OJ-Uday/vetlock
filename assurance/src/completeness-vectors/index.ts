/**
 * @vetlock/assurance completeness-vector transforms (packet §2.2, §5 P3).
 *
 * A completeness vector is a semantics-preserving code-normalization transform. If
 * the scanner catches an input but MISSES its transform, the scanner has a
 * completeness gap — a spelling of the same capability class it thinks it covers.
 *
 * Three families ship:
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
 * assertions in the test surface AND the `enumeratedCoverage` metric via
 * metrics/collector.ts (which reads `targetClass` per transform).
 */

export type { CompletenessFamily, CompletenessTransform } from './types.js';

// Wave 1B-G — original 8 transforms
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

// Wave 6-X — big-three coverage (fs-write, secret-read, obfuscation-decode)
export {
  writeFileToWriteFileSync,
  writeFileToCreateWriteStream,
} from './fs-write-widening.js';

export {
  envToProcessEnv,
  envToDestructure,
} from './secret-read-widening.js';

export {
  base64DecodeToAtob,
  hexDecodeToParseInt,
} from './obfuscation-normalization.js';

// Wave 6-Y — smaller-class coverage
export { preinstallToPostinstall } from './persistence-relocation.js';
export { webcryptoToNode } from './crypto-mine-normalization.js';
export { execClipboardCall } from './clipboard-normalization.js';
export { psListToChildProcess } from './process-enum-widening.js';
export { sha256Reimplement } from './integrity-normalization.js';
export { namedAliasToNodeModulesPath } from './dep-graph-alias.js';

// Wave 7-HH — fill P2 completeness coverage to 100% (STARTUP v0.7.0 grew the
// CAPABILITY-MAP with PyPI + hosted-API sinks; these transforms take coverage
// from 52.6% → 100% by intentionally targeting each remaining enumerated class).
export { readFileToReadFileSync } from './fs-read-widening.js';
export { atobToBufferFrom } from './obfuscation-decode-canonical.js';
export { envToBracketedComputed } from './env-secret-read-canonical.js';
export { advisoryVersionShift } from './advisory-version-shift.js';
export { pyExecToEvalCompile } from './python-code-exec-widening.js';
export { pyOsEnvironToGetenv } from './python-env-access-widening.js';
export { pyUrllibToRequests } from './python-net-egress-widening.js';
export {
  pySetupPyToPyproject,
  PY_NESTED_FILE_MARKER_PREFIX,
} from './python-install-hook-relocation.js';
export { pyHyphenToUnderscoreName } from './python-supply-chain-normalization.js';

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
import {
  writeFileToWriteFileSync,
  writeFileToCreateWriteStream,
} from './fs-write-widening.js';
import {
  envToProcessEnv,
  envToDestructure,
} from './secret-read-widening.js';
import {
  base64DecodeToAtob,
  hexDecodeToParseInt,
} from './obfuscation-normalization.js';
import { preinstallToPostinstall } from './persistence-relocation.js';
import { webcryptoToNode } from './crypto-mine-normalization.js';
import { execClipboardCall } from './clipboard-normalization.js';
import { psListToChildProcess } from './process-enum-widening.js';
import { sha256Reimplement } from './integrity-normalization.js';
import { namedAliasToNodeModulesPath } from './dep-graph-alias.js';
import { readFileToReadFileSync } from './fs-read-widening.js';
import { atobToBufferFrom } from './obfuscation-decode-canonical.js';
import { envToBracketedComputed } from './env-secret-read-canonical.js';
import { advisoryVersionShift } from './advisory-version-shift.js';
import { pyExecToEvalCompile } from './python-code-exec-widening.js';
import { pyOsEnvironToGetenv } from './python-env-access-widening.js';
import { pyUrllibToRequests } from './python-net-egress-widening.js';
import { pySetupPyToPyproject } from './python-install-hook-relocation.js';
import { pyHyphenToUnderscoreName } from './python-supply-chain-normalization.js';

/**
 * Canonical enumeration of transforms. Stable order — the report and the test
 * matrix iterate in this exact sequence, so any re-ordering is a visible diff.
 * Grouped by family for readability, then by class within family.
 */
export const allTransforms: readonly CompletenessTransform[] = [
  // sink-family-widening (Wave 1B-G + Wave 6-X + Wave 6-Y + Wave 7-HH)
  execToExecFile,                    // code-execution
  execToSpawn,                       // code-execution
  httpRequestToHttpsRequest,         // net-egress
  writeFileToWriteFileSync,          // fs-write
  writeFileToCreateWriteStream,      // fs-write
  envToProcessEnv,                   // secret-read
  envToDestructure,                  // secret-read
  psListToChildProcess,              // process-enumeration
  readFileToReadFileSync,            // fs-read              (Wave 7-HH)
  atobToBufferFrom,                  // obfuscation/decode   (Wave 7-HH)
  envToBracketedComputed,            // env/secret-read      (Wave 7-HH)
  advisoryVersionShift,              // advisory-known-vuln  (Wave 7-HH)
  pyExecToEvalCompile,               // python-code-exec     (Wave 7-HH)
  pyOsEnvironToGetenv,               // python-env-access    (Wave 7-HH)
  pyUrllibToRequests,                // python-net-egress    (Wave 7-HH)
  // string-normalization (Wave 1B-G + Wave 6-X + Wave 6-Y + Wave 7-HH)
  literalToConcat,                   // code-execution
  literalToTemplate,                 // code-execution
  literalToCharCodeRebuild,          // code-execution
  base64DecodeToAtob,                // obfuscation-decode
  hexDecodeToParseInt,               // obfuscation-decode
  webcryptoToNode,                   // crypto-mine
  execClipboardCall,                 // clipboard
  sha256Reimplement,                 // integrity
  pyHyphenToUnderscoreName,          // python-supply-chain  (Wave 7-HH)
  // code-location (Wave 1B-G + Wave 6-Y + Wave 7-HH)
  intoLifecycleScript,               // code-execution
  intoNestedFile,                    // code-execution
  preinstallToPostinstall,           // persistence
  namedAliasToNodeModulesPath,       // dep-graph-anomaly
  pySetupPyToPyproject,              // python-install-hook  (Wave 7-HH)
];
