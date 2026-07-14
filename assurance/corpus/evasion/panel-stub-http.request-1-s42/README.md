# panel-stub-http.request-1-s42 — nested-manifest-relocation evasion of net-egress

**Class:** net-egress (STARTUP enumerates via `packages/detectors/src/capability-map.json` — sinks: `http`, `https`, `net`, `dns`, `fetch`, `websocket`, `url-literal`, `encoded-url`).
**Technique:** nested-manifest-relocation (from `agent-panel/stub-agent.ts`).
**Target sink:** `http.request` (moved into a nested `scripts` field).

## Discovery

Found by the adversarial-agent panel's stub agent, seed=42, run 2026-07-14 (see
`assurance/report/panel-report.json` — hypothesis id `stub-http.request-1-s42`).
All 12 stub-panel hypotheses evaded (outcome kind `ok`, findings `[]`) because they
targeted classes/sinks the panel's own hypothesis generator names but no detector-wired
`engine:extractCapabilities` test currently covers with a matching fixture.

## Why blocking matters

Lifecycle scripts (`preinstall`, `install`, `postinstall`) can invoke commands like
`[CURL_INVOCATION]` to `https://c2.example/...` at install time — a net-egress capability
that never surfaces if the scanner only walks `.js` entry files. Nested-manifest relocation of the net call site into a script hook is
a textbook supply-chain evasion. The completeness gate must treat script-hook net-egress
as an in-scope evasion class.

## Rationale (from the stub agent)

> Move the sink invocation from index.js into a nested package.json 'scripts' entry the
> walker misses. Detector visits main entry but skips deep scripts.

## Reproduction

```ts
import { stubAgent } from '@vetlock/assurance/agent-panel';
import { runBounded } from '@vetlock/assurance/runner';

const hypotheses = await stubAgent.propose({ seed: 42, capabilityMap: /* … */ });
const h = hypotheses.find((h) => h.id === 'stub-http.request-1-s42')!;

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
  /nested-net-egress@0.2.0:
    resolution:
      integrity: sha512-BBBB
      tarball: https://packages.test/nested-net-egress/-/nested-net-egress-0.2.0.tgz
    peerDependencies:
      inert-marker: '*'
    description: 'moves http.request into a nested script hook — echo hello only'
```

## Status

- **Found:** 2026-07-14 (panel run seed=42, stub agent)
- **Filed as:** OPEN — waiting for detector wiring OR closer completeness-vector coverage.
- **Blocking on:** the engine walking package.json `scripts` for net-egress patterns
  (`[CURL_INVOCATION]`, `[WGET_INVOCATION]`, `[NODE_E_INVOCATION]` with fetch, etc.).
- **Superseded by:** (empty)
