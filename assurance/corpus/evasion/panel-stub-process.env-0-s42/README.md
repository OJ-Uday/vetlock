# panel-stub-process.env-0-s42 — identifier-split-and-concat evasion of env/secret-read

**Class:** env/secret-read (STARTUP enumerates this as `secret-read` in `packages/detectors/src/capability-map.json` — sinks: `process-env-token`, `process-env-enumerate`, `process-env-destructure`, `process-env-reflect`, `secret-file-read`).
**Technique:** identifier-split-and-concat (from `agent-panel/stub-agent.ts`).
**Target sink:** `process.env`.

## Discovery

Found by the adversarial-agent panel's stub agent, seed=42, run 2026-07-14 (see
`assurance/report/panel-report.json` — hypothesis id `stub-process.env-0-s42`).
All 12 stub-panel hypotheses evaded (outcome kind `ok`, findings `[]`) because they
targeted classes/sinks the panel's own hypothesis generator names but no detector-wired
`engine:extractCapabilities` test currently covers with a matching fixture.

## Why blocking matters

Splitting `'pro' + 'cess.env'` or `'e' + 'nv'` at runtime hides the secret-read sink
from static identifier-match scanners. A malicious package uses this to enumerate
credential-shaped environment variables (`AWS_*`, `GITHUB_TOKEN`, `NPM_TOKEN`) without
tripping a naive detector. The completeness gate must treat identifier-split as an
in-scope evasion for the env/secret-read class — the harm of missing this is that a
compromised package can exfiltrate CI/CD secrets while presenting as "no secret-read
finding".

## Rationale (from the stub agent)

> Split the sink identifier across two string literals concatenated at runtime. Static
> string-match detectors miss the split token.

## Reproduction

```ts
import { stubAgent } from '@vetlock/assurance/agent-panel';
import { runBounded } from '@vetlock/assurance/runner';

const hypotheses = await stubAgent.propose({ seed: 42, capabilityMap: /* … */ });
const h = hypotheses.find((h) => h.id === 'stub-process.env-0-s42')!;

const outcome = await runBounded(
  {
    kind: 'engine:extractCapabilities',
    text: h.generatedFixture,
    relPath: 'pnpm-lock.yaml',
  },
  { wallMs: 5_000, heapMb: 128, seed: 42 },
);
// Current (2026-07-14): outcome.kind === 'ok', findings === []  →  EVADED.
// Target after wiring: findings includes { capabilityClass: 'env/secret-read' }
// (or STARTUP's split-form 'secret-read').
```

## Fixture (defang-clean pnpm-lock.yaml fragment)

```yaml
lockfileVersion: '6.0'
settings:
  autoInstallPeers: true
packages:
  /evade-env/secret-read@0.1.0:
    resolution:
      integrity: sha512-AAAA
      tarball: https://packages.invalid/evade-env/secret-read/-/evade-env/secret-read-0.1.0.tgz
    description: 'proposes to evade process.env by splitting the identifier'
```

## Status

- **Found:** 2026-07-14 (panel run seed=42, stub agent)
- **Filed as:** OPEN — waiting for detector wiring OR closer completeness-vector coverage.
- **Blocking on:** the engine's secret-read detectors gaining coverage for split-token
  identifier patterns (`process` + `.env`, `env` + `.HOME`, `process.env` + `.AWS_*`).
- **Superseded by:** (empty)
