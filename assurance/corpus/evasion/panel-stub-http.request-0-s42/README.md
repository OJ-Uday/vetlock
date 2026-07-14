# panel-stub-http.request-0-s42 — identifier-split-and-concat evasion of net-egress

**Class:** net-egress (STARTUP enumerates via `packages/detectors/src/capability-map.json` — sinks: `http`, `https`, `net`, `dns`, `fetch`, `websocket`, `url-literal`, `encoded-url`).
**Technique:** identifier-split-and-concat (from `agent-panel/stub-agent.ts`).
**Target sink:** `http.request`.

## Discovery

Found by the adversarial-agent panel's stub agent, seed=42, run 2026-07-14 (see
`assurance/report/panel-report.json` — hypothesis id `stub-http.request-0-s42`).
All 12 stub-panel hypotheses evaded (outcome kind `ok`, findings `[]`) because they
targeted classes/sinks the panel's own hypothesis generator names but no detector-wired
`engine:extractCapabilities` test currently covers with a matching fixture.

## Why blocking matters

Splitting `'req' + 'uest'` (or `'ht' + 'tp.request'`) hides the exact identifier from
static string-match scanners while keeping the runtime call site executable. A malicious
package uses this technique to reach a C2 endpoint or an arbitrary URL without tripping
naive net-egress detectors. The completeness gate must treat identifier-split as an
in-scope evasion for the net-egress class.

## Rationale (from the stub agent)

> Split the sink identifier across two string literals concatenated at runtime. Static
> string-match detectors miss the split token.

## Reproduction

```ts
import { stubAgent } from '@vetlock/assurance/agent-panel';
import { runBounded } from '@vetlock/assurance/runner';

const hypotheses = await stubAgent.propose({ seed: 42, capabilityMap: /* … */ });
const h = hypotheses.find((h) => h.id === 'stub-http.request-0-s42')!;

const outcome = await runBounded(
  {
    kind: 'engine:extractCapabilities',
    text: h.generatedFixture,
    relPath: 'pnpm-lock.yaml',
  },
  { wallMs: 5_000, heapMb: 128, seed: 42 },
);
// Current (2026-07-14): outcome.kind === 'ok', findings === []  →  EVADED.
// Target after wiring: findings includes { capabilityClass: 'net-egress' }.
```

## Fixture (defang-clean pnpm-lock.yaml fragment)

```yaml
lockfileVersion: '6.0'
settings:
  autoInstallPeers: true
packages:
  /evade-net-egress@0.1.0:
    resolution:
      integrity: sha512-AAAA
      tarball: https://packages.invalid/evade-net-egress/-/evade-net-egress-0.1.0.tgz
    description: 'proposes to evade http.request by splitting the identifier'
```

## Status

- **Found:** 2026-07-14 (panel run seed=42, stub agent)
- **Filed as:** OPEN — waiting for detector wiring OR closer completeness-vector coverage.
- **Blocking on:** the engine's net-egress detectors gaining coverage for split-token
  identifier patterns in pnpm-lock.yaml `description` fields and inline `.js` payloads.
- **Superseded by:** (empty)
