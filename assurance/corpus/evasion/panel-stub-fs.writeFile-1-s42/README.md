# panel-stub-fs.writeFile-1-s42 — nested-manifest-relocation evasion of fs-write

**Class:** fs-write (STARTUP enumerates via `packages/detectors/src/capability-map.json` — sinks: `fs-write-hotpath`).
**Technique:** nested-manifest-relocation (from `agent-panel/stub-agent.ts`).
**Target sink:** `fs.writeFile` (moved into a nested `scripts` field).

## Discovery

Found by the adversarial-agent panel's stub agent, seed=42, run 2026-07-14 (see
`assurance/report/panel-report.json` — hypothesis id `stub-fs.writeFile-1-s42`).
All 12 stub-panel hypotheses evaded (outcome kind `ok`, findings `[]`) because they
targeted classes/sinks the panel's own hypothesis generator names but no detector-wired
`engine:extractCapabilities` test currently covers with a matching fixture.

## Why blocking matters

A `postinstall` hook that runs `[NODE_E_INVOCATION]` calling `require("fs").writeFileSync(...)`
writes files at install time — a first-class fs-write capability that the scanner never
sees if it only walks `.js` entry files. Nested-manifest relocation of the fs sink into a script hook is
the same evasion pattern used by real supply-chain attacks (e.g. ua-parser-2021 dropped
a miner via postinstall). The completeness gate must treat script-hook fs-write as
in-scope for the fs-write class.

## Rationale (from the stub agent)

> Move the sink invocation from index.js into a nested package.json 'scripts' entry the
> walker misses. Detector visits main entry but skips deep scripts.

## Reproduction

```ts
import { stubAgent } from '@vetlock/assurance/agent-panel';
import { runBounded } from '@vetlock/assurance/runner';

const hypotheses = await stubAgent.propose({ seed: 42, capabilityMap: /* … */ });
const h = hypotheses.find((h) => h.id === 'stub-fs.writeFile-1-s42')!;

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
  /nested-fs-write@0.2.0:
    resolution:
      integrity: sha512-BBBB
      tarball: https://packages.test/nested-fs-write/-/nested-fs-write-0.2.0.tgz
    peerDependencies:
      inert-marker: '*'
    description: 'moves fs.writeFile into a nested script hook — echo hello only'
```

## Status

- **Found:** 2026-07-14 (panel run seed=42, stub agent)
- **Filed as:** OPEN — waiting for detector wiring OR closer completeness-vector coverage.
- **Blocking on:** the engine walking package.json `scripts` for fs-write patterns
  (`> file`, `tee`, `[NODE_E_INVOCATION]` with `writeFile*`, `dd`, etc.).
- **Superseded by:** (empty)
