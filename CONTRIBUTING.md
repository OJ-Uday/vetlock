# Contributing

Thanks for considering a contribution. vetlock is an open-source security tool; the community's
job of both proposing detectors AND reporting false positives is the biggest lever we have on
whether the tool actually stays useful.

## Ways to help

### 1. False-positive reports

The most valuable thing you can send us. If vetlock yelled about a legitimate update:

- Open a bug report ("FP: <package>@<from> → <to> flagged as X").
- Attach the two `package-lock.json` files if you can share them (they can be trimmed to
  just the changed package + its transitives).
- Tell us which detector fired and why the finding is wrong.

We use FP reports to tune the detector defaults for the next release. Every one of them
sharpens the tool.

### 2. Missed-attack reports

Similarly valuable. If you know of a real npm supply-chain attack that vetlock did NOT flag
(or that we should be able to flag), open an issue with the attack summary and any published
postmortem links.

### 3. New detectors

Detectors are pure functions:

```ts
export interface Detector {
  id: string;
  category: DetectorCategory;
  run(pair: SnapshotPair, ctx: DetectorContext): Finding[];
}
```

Copy an existing one (`packages/detectors/src/env.ts` is a good template), write tests first
(TDD), and open a PR. The tests must include:

1. Positive case — a pair that produces exactly one finding of the right shape.
2. Negative case — a matched pair that produces no findings.
3. Diff-framing case — capability in both sides → no finding.
4. Schema validation — the finding passes `validateFinding()`.

Good candidates for new detectors: crypto-mining call patterns, clipboard access, screenshot
APIs, cross-origin `fetch` with credential inclusion, publish-cadence anomalies.

### 4. New lockfile formats

pnpm `pnpm-lock.yaml` (v5+) and yarn berry are the most-requested.

Parser goes in `packages/core/src/lockfile.ts` under a new format branch. Existing
`LockGraph` interface is the target output — everything downstream (changeset, engine,
provenance) already works generically.

## Local dev

```bash
git clone https://github.com/OJ-Uday/vetlock.git
cd vetlock
pnpm install
pnpm build
pnpm test   # 76 tests should be green
```

## Commit and PR conventions

- No AI-authored trailers.
- Match existing indentation (2 spaces).
- No `LEARNING NOTE:` comments in committed code.
- Minimal diffs: no drive-by refactors in a feature PR.
- If your PR adds a detector, include an entry in
  [docs/DETECTIONS.md](docs/DETECTIONS.md) if your detector catches (or misses) a known
  attack.

## Rulebook: things we won't accept

- Anything that requires executing analyzed package code (violates ADR 0005).
- Anything that phones home or introduces analytics.
- Anything that materially widens the finding schema without a compat plan.

## Getting help

Open a discussion on the repo for questions that don't fit a bug report. We tag issues
`good-first-issue` when they're a natural first contribution.
