# panel-stub-child_process.exec-2-s42 — unicode-homoglyph evasion of code-execution

**Class:** code-execution (STARTUP enumerates via `packages/detectors/src/capability-map.json` — sinks: `child_process`, `worker_threads`, `vm`, `inspector`, `async_hooks`, `eval`, `new Function`, `dynamic-require`, `dynamic-import`, `native-node-artifact`, `wasm-instantiate`).
**Technique:** unicode-homoglyph (from `agent-panel/stub-agent.ts`).
**Target sink:** `child_process.exec` (with mixed-script character substitution).

## Discovery

Found by the adversarial-agent panel's stub agent, seed=42, run 2026-07-14 (see
`assurance/report/panel-report.json` — hypothesis id `stub-child_process.exec-2-s42`).
All 12 stub-panel hypotheses evaded (outcome kind `ok`, findings `[]`) because they
targeted classes/sinks the panel's own hypothesis generator names but no detector-wired
`engine:extractCapabilities` test currently covers with a matching fixture.

## Why blocking matters

Homoglyph substitution — replacing ASCII characters in an identifier with visually
identical Unicode from a different script (Cyrillic `о` U+043E for Latin `o` U+006F is
the canonical example) — defeats naive exact-match detectors. The rendered code looks
identical to a reviewer AND to a grep pattern that lists only the ASCII sink names, but
JavaScript treats the mixed-script identifier as a distinct symbol at some layers (as
identifier text) and identical at others (property access via a homoglyphed string).
For a completeness-doctrine engine, "we scan for `child_process.exec` verbatim" is
insufficient — any bijective character substitution over the sink identifier is an
evasion class we must enumerate.

## Rationale (from the stub agent)

> Replace ASCII characters in the sink identifier with visually identical unicode
> homoglyphs. Detector's exact-match table doesn't include the mixed-script variant.

## Reproduction

```ts
import { stubAgent } from '@vetlock/assurance/agent-panel';
import { runBounded } from '@vetlock/assurance/runner';

const hypotheses = await stubAgent.propose({ seed: 42, capabilityMap: /* … */ });
const h = hypotheses.find((h) => h.id === 'stub-child_process.exec-2-s42')!;

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
  /homoglyph-code-execution@0.3.0:
    resolution:
      integrity: sha512-CCCC
      tarball: https://packages.example/homoglyph-code-execution/-/homoglyph-code-execution-0.3.0.tgz
    description: 'homoglyph on child_process.exec — cyrillic o replaces latin o in the identifier'
```

## Status

- **Found:** 2026-07-14 (panel run seed=42, stub agent)
- **Filed as:** OPEN — waiting for detector wiring OR closer completeness-vector coverage.
- **Blocking on:** the engine gaining a Unicode-normalization pass over sink-identifier
  matches (NFKC + confusable-script folding per the Unicode Security Mechanisms report).
- **Superseded by:** (empty)
