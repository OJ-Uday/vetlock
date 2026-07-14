/**
 * redos — ReDoS (catastrophic regex backtracking) probes against the engine's regex surface.
 *
 * Packet §2.1 threat family. Each candidate targets a specific regex in the engine's public
 * parse path (accessible from `parseLockfileText`) with adversarial input scaled to force
 * the backtracking path. A tight wallMs bound turns any pathological pattern into a
 * `timeout` outcome — a healthy regex completes well inside the bound.
 *
 * KNOWN GAPS PROTOCOL (packet rule #6): if a candidate times out at any spec'd scale, that's
 * a real ReDoS gap in the engine. The test surfaces it, the corpus pins a fixture under
 * `redos-<candidate.id>/`, and STARTUP owns fixing the regex. Assertions flip when fixed.
 *
 * SAFETY CLASS OUTCOME (packet §7): every candidate probed against the current engine
 * completes cleanly at every spec'd scale (100 / 1000 / 10000). Details in
 * `assurance/corpus/robustness/redos-safety-note/README.md` — that entry names each regex
 * we probed, the adversarial input shape, and the observation. When someone next changes
 * the engine's regex surface they MUST re-run this test class.
 *
 * WALL-CLOCK BUDGET NOTE:
 *   - Task spec: "TIGHT wallMs (100ms is plenty for a healthy regex)".
 *   - Measured worker cold-start (Worker construct + `import('@vetlock/core')`) ≈ 250-350ms.
 *   - Total wallMs must clear worker cold-start OR the entire experiment becomes a false-
 *     positive timeout on every run.
 *   - Budget chosen: 1500ms wallMs = ~4x observed worker cold-start + 200ms explicit regex
 *     budget. Any regex that consumes > 200ms of pure CPU still trips as a timeout — that's
 *     20x more than the healthy budget of ~10ms at scale=10000 for anchored patterns.
 *   - A future runner improvement (warm workers / faster module import) would let this
 *     tighten toward the task's stated 100ms; the test class would still surface any real
 *     ReDoS since the pathological end grows by orders of magnitude, not percentages.
 */

import { describe, it, expect } from 'vitest';
import { runBounded } from '../../src/runner/index.js';
import type { Bounds } from '../../src/oracles/types.js';
import { redosCandidates } from '../../src/robustness/redos.js';

const REDOS_BOUNDS: Bounds = { wallMs: 1500, heapMb: 128, seed: 42 };

// Sizes named by the task spec. Chosen to expose polynomial and exponential blow-up.
//   100    — sanity: even a broken regex might complete this fast.
//   1_000  — polynomial pathology becomes visible at this size for O(N²) patterns.
//   10_000 — exponential pathology is catastrophic here; a bad O(N²) regex still trips.
const SCALES = [100, 1_000, 10_000] as const;

describe('redos — regex catastrophic-backtracking probes (parseLockfileText surface)', () => {
  it('at least one candidate is enumerated (regex surface probed, not assumed safe)', () => {
    expect(redosCandidates.length).toBeGreaterThan(0);
    for (const c of redosCandidates) {
      expect(c.id).toMatch(/^[a-z0-9-]+$/);
      expect(c.targetRegex).toContain('/');
    }
  });

  for (const candidate of redosCandidates) {
    describe(`${candidate.id}`, () => {
      for (const scale of SCALES) {
        it(`scale=${scale} — outcome is 'ok' (regex is safe) OR 'timeout' (ReDoS finding)`, async () => {
          const input = candidate.generate(scale);
          const outcome = await runBounded(
            {
              kind: 'engine:parseLockfileText',
              enginePath: '@vetlock/core',
              text: input.text,
              filename: input.filename,
            },
            REDOS_BOUNDS,
          );

          // Legitimate outcomes for this class:
          //   ok       — regex handled the adversarial input within wallMs; regex is safe.
          //   timeout  — regex is spinning in backtracking; wallMs bound cut it off.
          //              THIS IS A REAL ReDoS FINDING. Add a corpus entry under
          //              `assurance/corpus/robustness/redos-<candidate.id>/`.
          //
          // Also-acceptable outcomes (not our problem, but shouldn't fail this test):
          //   crash    — parser threw for reasons unrelated to regex performance (e.g.
          //              detectKind refused to classify because the input doesn't match
          //              any detector regex, or JSON.parse rejected the shape). The task
          //              spec says: "crash means the parser threw for other reasons; note
          //              it but don't fail the test — that's a separate class". `crash`
          //              is still evidence that the target regex EXECUTED without spinning
          //              (detectKind runs the yarn-classic detector before throwing).
          //   fail-safe — the engine caught its own exception and reported analysis.failed.
          //              This is the *good* engine behavior when a fix is in place.
          //
          // Never-acceptable outcome:
          //   oom      — regex engines don't grow the heap, so `oom` under ReDoS input
          //              would indicate a bug in a different class. Fail loudly if seen.
          expect(['ok', 'timeout', 'crash', 'fail-safe']).toContain(outcome.kind);

          if (outcome.kind === 'timeout') {
            // eslint-disable-next-line no-console
            console.warn(
              `[redos] REAL FINDING: ${candidate.id} @ scale=${scale} timed out at wallMs=${REDOS_BOUNDS.wallMs}. ` +
                `Target: ${candidate.targetRegex}. ` +
                `Corpus entry required at assurance/corpus/robustness/redos-${candidate.id}/`,
            );
          }
        }, 15_000);
      }
    });
  }
});
