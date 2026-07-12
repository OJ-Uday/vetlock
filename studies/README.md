# FP Study — measuring vetlock's noise floor on real routine bumps

**Purpose:** determine what vetlock says about legitimate, everyday version
bumps. Any finding at WARN or BLOCK on a routine bump is, by definition, a
false positive. This document exists to measure the noise floor honestly and
tune defaults accordingly.

## Status (v0.2.0)

**Not yet run.** The FP study is a launch-blocker per the original packet.
Requires live npm registry access, which is blocked by the current dev
environment's corporate proxy. The infrastructure is in place and ready to run
in any environment with public-npm access.

To run:
```bash
node packages/cli/dist/corpus/fp-study.js --input studies/top-100.txt --output studies/latest.json --verbose
```

The output JSON schema:
- `totalBumps`, `bumpsSucceeded`, `bumpsFailed`
- `findingsPerBump` — the headline number
- `perDetectorFpRate` — hits and rate-per-bump for each detector
- `perSeverity` — how many bumps landed in each verdict
- `worstOffenders` — 10 bumps with the most findings (candidates for fixture inclusion or config allowlists)

## Expected shape of results

Based on manual sampling and the fixture-based FP smoke (which we DO have —
`packages/cli/test/fp-smoke.test.ts`, 8 realistic benign bumps, 0 findings):

- Most bumps should be CLEAN
- `meta.maintainer-change` will fire on packages with team-based publishing rotations — expected, medium noise
- `net.new-endpoint` may fire on packages that add new fetch destinations for legitimate reasons (CDN cutover, new dashboard URL in docs) — need tuning
- `deps.new-direct-dep` firing at INFO level is fine
- Anything above 1 BLOCK finding per 1000 routine bumps is a problem — investigate

## Tuning workflow after study completes

1. Sort `worstOffenders` — do they cluster on specific packages?
2. If yes: add those packages to the built-in trust store, or ship them with `meta.maintainer-change` set to INFO by default via config
3. Look at high `perDetectorFpRate` entries — if a detector fires on > 5% of routine bumps at BLOCK, consider downgrading its default severity
4. Regenerate this document with the actual results

## Post-launch cadence

The FP study should re-run **monthly**. New attacker techniques emerge; detector
tuning that was optimal in July may over-fire in August. The infrastructure is
cheap to re-run.
