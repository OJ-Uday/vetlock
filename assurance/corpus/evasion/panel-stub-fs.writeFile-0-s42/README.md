# panel-stub-fs.writeFile-0-s42 — identifier-split-and-concat evasion of fs-write

**Class:** fs-write (STARTUP enumerates via `packages/detectors/src/capability-map.json` — sinks: `fs-write-hotpath`).
**Technique:** identifier-split-and-concat (from `agent-panel/stub-agent.ts`).
**Target sink:** `fs.writeFile`.

## Discovery

Found by the adversarial-agent panel's stub agent, seed=42, run 2026-07-14 (see
`assurance/report/panel-report.json` — hypothesis id `stub-fs.writeFile-0-s42`).
All 12 stub-panel hypotheses evaded (outcome kind `ok`, findings `[]`) because they
targeted classes/sinks the panel's own hypothesis generator names but no detector-wired
`engine:extractCapabilities` test currently covers with a matching fixture.

## Why blocking matters

Splitting `'write' + 'File'` at runtime hides the fs-write sink from static
identifier-match scanners. A malicious package uses this technique to drop a persistence
payload to disk (e.g. `~/.bashrc`, `~/.aws/credentials`) without tripping a naive
fs-write detector. The completeness gate must treat identifier-split as an in-scope
evasion for the fs-write class.

## Rationale (from the stub agent)

> Split the sink identifier across two string literals concatenated at runtime. Static
> string-match detectors miss the split token.

## Reproduction

```ts
import { stubAgent } from '@vetlock/assurance/agent-panel';
import { runBounded } from '@vetlock/assurance/runner';

const hypotheses = await stubAgent.propose({ seed: 42, capabilityMap: /* … */ });
const h = hypotheses.find((h) => h.id === 'stub-fs.writeFile-0-s42')!;

const outcome = await runBounded(
  {
    kind: 'engine:extractCapabilities',
    text: h.generatedFixture,
    relPath: 'pnpm-lock.yaml',
  },
  { wallMs: 5_000, heapMb: 128, seed: 42 },
);
// Current (2026-07-14): outcome.kind === 'ok', findings === []  →  EVADED.
// Target after wiring: findings includes { capabilityClass: 'fs-write' }.
```

## Fixture (defang-clean pnpm-lock.yaml fragment)

```yaml
lockfileVersion: '6.0'
settings:
  autoInstallPeers: true
packages:
  /evade-fs-write@0.1.0:
    resolution:
      integrity: sha512-AAAA
      tarball: https://packages.invalid/evade-fs-write/-/evade-fs-write-0.1.0.tgz
    description: 'proposes to evade fs.writeFile by splitting the identifier'
```

## Status

- **Found:** 2026-07-14 (panel run seed=42, stub agent)
- **Filed as:** OPEN — waiting for detector wiring OR closer completeness-vector coverage.
- **Blocking on:** the engine's fs-write detectors gaining coverage for split-token
  identifier patterns in pnpm-lock.yaml `description` fields and inline `.js` payloads.
- **Superseded by:** (empty)
