# panel-stub-process.env-2-s42 — unicode-homoglyph evasion of env/secret-read

**Class:** env/secret-read (STARTUP enumerates this as `secret-read` in `packages/detectors/src/capability-map.json` — sinks: `process-env-token`, `process-env-enumerate`, `process-env-destructure`, `process-env-reflect`, `secret-file-read`).
**Technique:** unicode-homoglyph (from `agent-panel/stub-agent.ts`).
**Target sink:** `process.env` (with mixed-script character substitution).

## Discovery

Found by the adversarial-agent panel's stub agent, seed=42, run 2026-07-14 (see
`assurance/report/panel-report.json` — hypothesis id `stub-process.env-2-s42`).
All 12 stub-panel hypotheses evaded (outcome kind `ok`, findings `[]`) because they
targeted classes/sinks the panel's own hypothesis generator names but no detector-wired
`engine:extractCapabilities` test currently covers with a matching fixture.

## Why blocking matters

Homoglyph attacks on env-read identifiers hide `process.env` accesses from grep-shaped
scanners. Even more insidiously: JavaScript property access via a homoglyphed string
(`process["ẹnv"]` with a dotted-below `e`) can be constructed on hosts where the runtime
tolerates the lookup, defeating any exact-match `.env` scanner. The completeness gate
must fold confusable scripts before matching sink identifiers — otherwise a homoglyphed
env-enumerate that dumps `AWS_*` to disk passes as "no secret-read finding".

## Rationale (from the stub agent)

> Replace ASCII characters in the sink identifier with visually identical unicode
> homoglyphs. Detector's exact-match table doesn't include the mixed-script variant.

## Reproduction

```ts
import { stubAgent } from '@vetlock/assurance/agent-panel';
import { runBounded } from '@vetlock/assurance/runner';

const hypotheses = await stubAgent.propose({ seed: 42, capabilityMap: /* … */ });
const h = hypotheses.find((h) => h.id === 'stub-process.env-2-s42')!;

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
  /homoglyph-env/secret-read@0.3.0:
    resolution:
      integrity: sha512-CCCC
      tarball: https://packages.example/homoglyph-env/secret-read/-/homoglyph-env/secret-read-0.3.0.tgz
    description: 'homoglyph on process.env — cyrillic o replaces latin o in the identifier'
```

## Status

- **Found:** 2026-07-14 (panel run seed=42, stub agent)
- **Filed as:** OPEN — waiting for detector wiring OR closer completeness-vector coverage.
- **Blocking on:** Unicode-normalization pass over sink-identifier matches (NFKC +
  confusable-script folding per the Unicode Security Mechanisms report).
- **Superseded by:** (empty)
