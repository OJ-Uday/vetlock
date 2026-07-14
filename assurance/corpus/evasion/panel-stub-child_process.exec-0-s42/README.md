# panel-stub-child_process.exec-0-s42 — identifier-split-and-concat evasion of code-execution

**Class:** code-execution (STARTUP enumerates via `packages/detectors/src/capability-map.json` — sinks: `child_process`, `worker_threads`, `vm`, `inspector`, `async_hooks`, `eval`, `new Function`, `dynamic-require`, `dynamic-import`, `native-node-artifact`, `wasm-instantiate`).
**Technique:** identifier-split-and-concat (from `agent-panel/stub-agent.ts`).
**Target sink:** `child_process.exec`.

## Discovery

Found by the adversarial-agent panel's stub agent, seed=42, run 2026-07-14 (see
`assurance/report/panel-report.json` — hypothesis id `stub-child_process.exec-0-s42`).
All 12 stub-panel hypotheses evaded (outcome kind `ok`, findings `[]`) because they
targeted classes/sinks the panel's own hypothesis generator names but no detector-wired
`engine:extractCapabilities` test currently covers with a matching fixture.

## Why blocking matters

Splitting an identifier across two string literals concatenated at runtime — e.g.
`'ex' + 'ec'` — is a textbook evasion against static string-match detectors. A malicious
package uses it to hide `child_process.exec` from grep-shaped scanners while keeping the
call site executable at runtime. If vetlock's completeness gate declares code-execution
covered while the identifier-split variant slips through, we've mislabeled the coverage —
which is worse than admitting a gap.

## Rationale (from the stub agent)

> Split the sink identifier across two string literals concatenated at runtime. Static
> string-match detectors miss the split token.

## Reproduction

```ts
import { stubAgent } from '@vetlock/assurance/agent-panel';
import { runBounded } from '@vetlock/assurance/runner';

// Regenerate the hypothesis from the deterministic stub agent:
const hypotheses = await stubAgent.propose({ seed: 42, capabilityMap: /* mock or STARTUP */ });
const h = hypotheses.find((h) => h.id === 'stub-child_process.exec-0-s42')!;

// Feed the defanged fixture through the runner:
const outcome = await runBounded(
  {
    kind: 'engine:extractCapabilities',
    text: h.generatedFixture,
    relPath: 'pnpm-lock.yaml',
  },
  { wallMs: 5_000, heapMb: 128, seed: 42 },
);
// Current (2026-07-14): outcome.kind === 'ok', findings === []  →  EVADED.
// Target after wiring: findings includes { capabilityClass: 'code-execution' }.
```

## Fixture (defang-clean pnpm-lock.yaml fragment, from the stub hypothesis)

```yaml
lockfileVersion: '6.0'
settings:
  autoInstallPeers: true
packages:
  /evade-code-execution@0.1.0:
    resolution:
      integrity: sha512-AAAA
      tarball: https://packages.invalid/evade-code-execution/-/evade-code-execution-0.1.0.tgz
    description: 'proposes to evade child_process.exec by splitting the identifier'
```

## Status

- **Found:** 2026-07-14 (panel run seed=42, stub agent)
- **Filed as:** OPEN — waiting for detector wiring OR closer completeness-vector coverage.
- **Blocking on:** the engine gaining an `engine:extractCapabilities` code path that
  parses pnpm-lock.yaml `description` fields for split-identifier evasion patterns.
- **Superseded by:** (empty)
