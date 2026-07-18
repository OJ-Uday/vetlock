# ADR 0006: Open-core boundary — engine is the product, wrapper is thin

**Status:** Accepted, 2026-07-13

## Context

vetlock has an existing OSS core (`packages/{core,detectors,cli}`, Apache-2.0,
375+ tests). The STARTUP packet (§4 D1) calls for a commercial wrapper (hosted
API, GitHub App, org dashboard). Where do we draw the line between "OSS" and
"paid"?

Getting this wrong in either direction kills the project:
- **Wrap too little:** paid tier isn't sell-able, no business.
- **Wrap too much:** community loses trust, the OSS core stagnates or forks —
  the moat *is* the community's trust in the auditable core.

Every open-core company faces this. Some end up moving detection quality
behind the paid wall to force upgrades (Snyk in its later years), and every
one of them paid for it with community anger and forks.

## Decision

**The engine is the product; the wrapper is thin.** Concretely:

1. **All detection logic lives in the OSS core**, under `packages/detectors/`
   (Apache-2.0). Every finding a paid customer sees originates from the same
   `runAll(pair, ctx)` a `npx @oj-uday/vetlock` user runs locally. There is exactly one
   detection code path across every tier.

2. **The commercial layer sells convenience, scale, collaboration, governance,
   and support — not detections.** Specifically it sells:
   - **Convenience:** one-click GitHub App install → PR checks across every
     repo, no per-repo Action YAML to maintain.
   - **Scale:** hosted runners so users don't burn their own CI minutes;
     background scans on schedule; cross-repo aggregation.
   - **Collaboration:** org dashboard, findings triage workflow, saved config,
     policy inheritance, member management.
   - **Governance:** SSO/SAML, audit log, policy-as-code
     (`.vetlock-policy.yml`), SBOM/VEX export, self-hosted deployment for
     regulated buyers.
   - **Support:** SLA, priority disclosure channel, custom-detector
     consultation for enterprise.

3. **New detectors, new lockfile parsers, new ecosystems, new capability
   classes always land in OSS first.** They may become sell-able (e.g. an
   enterprise-tier PyPI-behavior baseline dataset), but the *detection*
   remains open.

4. **License:** OSS core stays Apache-2.0 in perpetuity. The commercial wrapper
   (which will live in a separate repo `vetlock-dev/vetlock-app` per ADR 0007)
   uses a source-available or proprietary license — never a modified Apache
   with a "commons clause" or similar (see §Non-goals — those licenses split
   the community).

## Enforcement

- **`oss-no-network.test`** (invariant): the OSS CLI and Action code paths
  never phone home to any first-party vetlock domain. If the code ever tries
  to open a socket to `*.vetlock.dev` (or whatever the hosted domain is), the
  test fails. See ADR 0005 (NEVER-EXECUTE) for the analogous canary style.

- **PR review checklist**: any PR that adds a new detector, a new capability
  class, or a new sink/entry-point to the CAPABILITY-MAP (ADR 0011) MUST land
  in `packages/detectors/*`. The commercial `vetlock-app` repo never contains
  detection logic — CI on that repo asserts the dependency is on the published
  `@oj-uday/vetlock` npm package (or the workspace symlink during dev), not on a forked
  or reimplemented detector.

- **Public statement**: the `README.md` and the marketing site say explicitly
  that all detections are OSS. This is a *commitment* that can be broken only
  by breaking a public promise.

## Rationale

- **Trust is the moat, and trust needs auditability.** A security tool whose
  detections are opaque asks the customer to trust the vendor. That's a hard
  sell for regulated buyers, and it's a competitor-easy story to attack
  ("but their detections are closed — how do you know what they miss?").
  Open-core answers this with source, tests, and a public red-team.
- **Community durability.** OSS detectors accept community-submitted attack
  fixtures and detector improvements (the CONTRIBUTING funnel — packet §7).
  Each contribution improves the paid tier for free. This is Semgrep's model,
  and it's the model that actually generates a compounding advantage over a
  detector-hoarding competitor.
- **Support-and-convenience is genuinely paid-tier work.** A GitHub App with
  webhook handling, a queue, tenant isolation, sandboxed runners, an SSO
  layer, and a policy engine is real engineering value that a self-hoster
  would have to reimplement.

## Consequences

- We deliberately give up the "put a killer detector behind the paywall"
  tactic. In exchange we keep the community, and we compete on trust +
  workflow polish + governance — which is where regulated buyers actually
  spend.
- Anyone can self-host the OSS core + write their own thin wrapper. That's
  fine. We win because building the wrapper *well* — SSO, audit, SLA, policy —
  is genuinely non-trivial, and buyers who need those features want to buy
  them, not build them.
- Detector improvements from the community accrue to the paid tier at zero
  marginal cost. Reciprocally, red-team findings against the paid tier's
  hosted infrastructure (e.g. a sandbox escape in the ephemeral worker per
  ADR 0008) accrue to nobody but us — those fixes stay in `vetlock-app` and
  do not benefit competitors. Fair trade.

## Non-goals

- No BSL, Commons Clause, or SSPL. Those licenses split the community by
  design and would betray the "open core" promise.
- No "premium detectors" tier inside the OSS package. If a detector exists at
  all, every user gets it.
- No detection-quality difference between the CLI and the hosted product.
  Speed, UI, and scale differ; detections don't.
