/**
 * Completeness E2E — placeholder for the finding-survives assertions (packet §5 P3 tail).
 *
 * The end-to-end proof that a completeness transform preserves the scanner's finding
 * requires:
 *   1. Run the scanner over the ORIGINAL source → collect a `beforeOutcome: RunOutcome`
 *      whose findings include the target capabilityClass.
 *   2. Run the scanner over the TRANSFORMED source → collect an `afterOutcome`.
 *   3. Assert `oracleFindingSurvives(beforeOutcome, afterOutcome, targetClass).pass`.
 *
 * Step 1/2 need the runner to expose per-source detection (feeding a string body into
 * `@vetlock/core.extractCapabilities` + adapting FileCapabilities → Finding). That
 * wiring is P1 tail work — the exact patch is documented on the metamorphic-pair
 * E2E test (assurance/test/metamorphic/invariance-e2e.test.ts).
 *
 * When that wiring lands, un-skip these tests: swap `it.skip` for `it` and un-comment
 * the body block. The assertions inside are already the right shape.
 *
 * Until then, this file exists so:
 *   • the test matrix is visible: a reader can see "there are 8 transforms; each has
 *     an intended end-to-end oracle assertion"
 *   • un-skipping is a one-liner
 *   • the CI signal counts the pending assertions as `.skip` (not as passes we don't
 *     have and not as failures that block the branch).
 */

import { describe, it, expect } from 'vitest';
import {
  allTransforms,
  type CompletenessTransform,
} from '../../src/completeness-vectors/index.js';
// The oracle we WILL wire through once the driver exposes per-source detection:
// import { oracleFindingSurvives } from '../../src/oracles/index.js';
// import type { RunOutcome } from '../../src/oracles/types.js';

/** Payload that reliably drives the target capability class on the vetlock engine.
 *  Used as the `before` input; each transform mutates it into `after`. Defang-clean:
 *  `echo` is allow-listed. */
const CODE_EXEC_PAYLOAD = 'require("child_process").exec("echo hi");\n';

/** Payload for net-egress-class transforms (http.request family widening). */
const NET_EGRESS_PAYLOAD =
  'const h = require("http"); h.request("http://example.com/p");\n';

/** Pick the appropriate baseline source for each transform. */
function baselineFor(transform: CompletenessTransform): string {
  if (transform.targetClass === 'net-egress') return NET_EGRESS_PAYLOAD;
  return CODE_EXEC_PAYLOAD;
}

describe('completeness-vectors — finding-survives (E2E)', () => {
  it('battery covers every registered transform', () => {
    // Meta-assertion (non-skipped): confirms the test surface enumerates the same
    // transforms the barrel exports. If a transform is added to `allTransforms`
    // but forgotten here, the driver would silently skip it.
    expect(allTransforms.length).toBeGreaterThan(0);
    for (const t of allTransforms) {
      expect(t.id.length).toBeGreaterThan(0);
      expect(t.family.length).toBeGreaterThan(0);
      expect(t.targetClass.length).toBeGreaterThan(0);
    }
  });

  for (const transform of allTransforms) {
    it.skip(`[TODO wire runner] transform ${transform.id} preserves ${transform.targetClass}`, () => {
      const before: string = baselineFor(transform);
      const after: string = transform.transform(before, 0);
      // Once the driver lands:
      //   const beforeOutcome: RunOutcome = await runDetectors(before);
      //   const afterOutcome:  RunOutcome = await runDetectors(after);
      //   const result = oracleFindingSurvives(
      //     beforeOutcome,
      //     afterOutcome,
      //     transform.targetClass,
      //   );
      //   expect(result.pass, result.reason).toBe(true);
      // Silence unused-var lints in the current skipped state:
      void before;
      void after;
    });
  }
});
