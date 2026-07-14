/**
 * Mock CAPABILITY-MAP for the agent panel driver.
 *
 * Wave 1B-H owns the production CAPABILITY-MAP as `packages/detectors/src/capability-map.json`
 * plus a generator that emits `docs/CAPABILITY-MAP.md` (ADR 0011 completeness doctrine).
 * When that lands, `loadCapabilityMap()` will read that JSON and adapt the shape. Until
 * then, the panel is self-contained on a small hardcoded slice of the same shape so this
 * wave can ship independently.
 *
 * The mock slice covers the four capability classes P0 already knows about — the ones the
 * assurance harness's own type surface enumerates in `oracles/types.ts` and
 * `runner/engine-adapter.ts`. Each entry gives the panel one concrete sink to name in its
 * hypotheses.
 */

import type { CapabilityMap } from './types.js';

/**
 * The hardcoded slice. Order is stable — the panel iterates it in order, so tests can
 * assert positional invariants (e.g. "the first entry produced N hypotheses").
 */
const MOCK_MAP: CapabilityMap = {
  entries: [
    {
      class: 'code-execution',
      sinkId: 'child_process.exec',
      kind: 'sink',
      description:
        'Direct shell invocation via child_process.exec / execSync. First-order code exec.',
    },
    {
      class: 'net-egress',
      sinkId: 'http.request',
      kind: 'sink',
      description:
        'Outbound HTTP via node:http / node:https / global fetch — arbitrary destination.',
    },
    {
      class: 'fs-write',
      sinkId: 'fs.writeFile',
      kind: 'sink',
      description:
        'Filesystem write via node:fs writeFile / writeFileSync / createWriteStream.',
    },
    {
      class: 'env/secret-read',
      sinkId: 'process.env',
      kind: 'sink',
      description:
        'Environment variable / secret-file reads (process.env, dotenv, ~/.aws/credentials).',
    },
  ],
};

/**
 * Load the CAPABILITY-MAP. Currently returns the mock; the swap to the real 1B-H JSON is
 * a follow-up (see file docstring). Keeping the function name matches the packet spec so
 * callers don't have to change.
 */
export function loadCapabilityMap(): CapabilityMap {
  return MOCK_MAP;
}
