# panel-stub-http.request-2-s42 — unicode-homoglyph evasion of net-egress

**Class:** net-egress (STARTUP enumerates via `packages/detectors/src/capability-map.json` — sinks: `http`, `https`, `net`, `dns`, `fetch`, `websocket`, `url-literal`, `encoded-url`).
**Technique:** unicode-homoglyph (from `agent-panel/stub-agent.ts`).
**Target sink:** `http.request` (with mixed-script character substitution).

## Discovery

Found by the adversarial-agent panel's stub agent, seed=42, run 2026-07-14 (see
`assurance/report/panel-report.json` — hypothesis id `stub-http.request-2-s42`).
All 12 stub-panel hypotheses evaded (outcome kind `ok`, findings `[]`) because they
targeted classes/sinks the panel's own hypothesis generator names but no detector-wired
`engine:extractCapabilities` test currently covers with a matching fixture.

## Why blocking matters

Homoglyph attacks on net-egress identifiers hide `http.request` and `https.request`
call sites from grep-shaped scanners: the payload text looks identical to a reviewer AND
to a naive exact-match table, but the Unicode code points differ. The completeness gate
must fold confusable scripts before matching sink identifiers — otherwise "net-egress
covered" is a lie that lets a homoglyphed C2 call slip through.

## Rationale (from the stub agent)

> Replace ASCII characters in the sink identifier with visually identical unicode
> homoglyphs. Detector's exact-match table doesn't include the mixed-script variant.

## Reproduction

```ts
import { stubAgent } from '@vetlock/assurance/agent-panel';
import { runBounded } from '@vetlock/assurance/runner';

const hypotheses = await stubAgent.propose({ seed: 42, capabilityMap: /* … */ });
const h = hypotheses.find((h) => h.id === 'stub-http.request-2-s42')!;

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
  /homoglyph-net-egress@0.3.0:
    resolution:
      integrity: sha512-CCCC
      tarball: https://packages.example/homoglyph-net-egress/-/homoglyph-net-egress-0.3.0.tgz
    description: 'homoglyph on http.request — cyrillic o replaces latin o in the identifier'
```

## Status

- **Found:** 2026-07-14 (panel run seed=42, stub agent)
- **Filed as:** OPEN — waiting for detector wiring OR closer completeness-vector coverage.
- **Blocking on:** Unicode-normalization pass over sink-identifier matches (NFKC +
  confusable-script folding per the Unicode Security Mechanisms report).
- **Superseded by:** (empty)
