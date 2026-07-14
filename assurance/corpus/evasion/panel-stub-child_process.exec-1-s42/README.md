# panel-stub-child_process.exec-1-s42 — nested-manifest-relocation evasion of code-execution

**Class:** code-execution (STARTUP enumerates via `packages/detectors/src/capability-map.json` — sinks: `child_process`, `worker_threads`, `vm`, `inspector`, `async_hooks`, `eval`, `new Function`, `dynamic-require`, `dynamic-import`, `native-node-artifact`, `wasm-instantiate`).
**Technique:** nested-manifest-relocation (from `agent-panel/stub-agent.ts`).
**Target sink:** `child_process.exec` (moved into a nested `scripts` field).

## Discovery

Found by the adversarial-agent panel's stub agent, seed=42, run 2026-07-14 (see
`assurance/report/panel-report.json` — hypothesis id `stub-child_process.exec-1-s42`).
All 12 stub-panel hypotheses evaded (outcome kind `ok`, findings `[]`) because they
targeted classes/sinks the panel's own hypothesis generator names but no detector-wired
`engine:extractCapabilities` test currently covers with a matching fixture.

## Why blocking matters

npm/pnpm lifecycle hooks (`preinstall`, `install`, `postinstall`, and shell aliases
underneath) execute arbitrary commands at install time — that's equivalent to
`child_process.exec` from the attacker's perspective, but a scanner that walks only the
main entry file (`index.js`) never sees it. A malicious package hides its exec by
declaring the payload as a nested-manifest script hook the walker skips. The completeness
gate must treat nested-manifest relocation as an in-scope evasion for code-execution.

## Rationale (from the stub agent)

> Move the sink invocation from index.js into a nested package.json 'scripts' entry the
> walker misses. Detector visits main entry but skips deep scripts.

## Reproduction

```ts
import { stubAgent } from '@vetlock/assurance/agent-panel';
import { runBounded } from '@vetlock/assurance/runner';

const hypotheses = await stubAgent.propose({ seed: 42, capabilityMap: /* … */ });
const h = hypotheses.find((h) => h.id === 'stub-child_process.exec-1-s42')!;

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

## Fixture (defang-clean pnpm-lock.yaml fragment)

```yaml
lockfileVersion: '6.0'
settings:
  autoInstallPeers: true
packages:
  /nested-code-execution@0.2.0:
    resolution:
      integrity: sha512-BBBB
      tarball: https://packages.test/nested-code-execution/-/nested-code-execution-0.2.0.tgz
    peerDependencies:
      inert-marker: '*'
    description: 'moves child_process.exec into a nested script hook — echo hello only'
```

## Status

- **Found:** 2026-07-14 (panel run seed=42, stub agent)
- **Filed as:** OPEN — waiting for detector wiring OR closer completeness-vector coverage.
- **Blocking on:** the engine walking package.json `scripts` and nested-manifest entries
  as first-class code-execution surfaces (mirrors STARTUP's `install-hook` entry-point family).
- **Superseded by:** (empty)
