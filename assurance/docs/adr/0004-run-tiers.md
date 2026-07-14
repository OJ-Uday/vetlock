# ADR 0004 (assurance): Two run tiers — fast PR gate, comprehensive scheduled

**Status:** Accepted, 2026-07-14

Scope: `@vetlock/assurance` only.

## Context

The harness has two competing demands:

- **Merge safety** — every PR must be blocked from landing if it regresses a robustness or
  completeness guarantee. That gate must be fast enough that people don't rubber-stamp it or
  skip it: seconds-to-a-few-minutes, not tens of minutes.
- **Discovery** — the property-based, generative, differential, and adversarial-agent
  modalities want *hours* of budget to find novel gaps. Running them on every PR would burn
  cost, slow the pipeline, and blur "I broke it" from "someone else's PR from last week
  broke it."

Also: some modalities produce *proposals*, not verdicts. The agent panel finding a candidate
new evasion is a lead to investigate, not a merge block — if we blocked on it, false alarms
would grind PRs to a halt.

## Decision

Two tiers, each with a defined role:

### PR tier — blocking, deterministic, fast

Runs on every `packages/core`, `packages/detectors`, or `assurance/` PR. Must pass to merge.
Composition:

- **Robustness smoke.** The committed adversarial corpus at `assurance/corpus/` fed through
  the runner (ADR-0003). Oracle set asserts no-crash, no-hang, no-OOM, fail-safe.
- **Completeness regressions.** Every historically-caught malicious fixture, with its
  canonical *and* its semantics-preserving mutations, must still be caught (finding-survives
  oracle). Every metamorphic pair must be identity-invariant.
- **Coverage gate.** For every enumerated sink / entry-point in the CAPABILITY-MAP, the
  matching detection is exercised. A newly-enumerated map member without a matching test
  fails the gate.

Budget target: ≤ 3 minutes on CI. Deterministic (seeded), reproducible from the seed
recorded in `ASSURANCE.md`.

### Scheduled tier — non-blocking, generative, thorough

Runs nightly (or on-demand). May take hours. Composition:

- **Property fuzzing.** fast-check with a large budget over robustness invariants.
- **Differential.** Same corpus through vetlock + ≥ 2 other public scanners; deltas
  classified into the ledger (real-gap / intentional-non-goal / advisory-only).
- **Adversarial-agent panel** (ADR-0002 modality 4). Cheap models proposing novel evasion
  hypotheses, filing candidates as issues/PRs with the fixture + the class it breaks.

Failures in the scheduled tier open issues; they do not block merge. Confirmed gaps must be
triaged, promoted to the corpus, and become new PR-tier tests before the finding is closed.

## Rationale

- **A slow blocking gate becomes an ignored gate.** People `--no-verify` past long checks.
  The PR tier must be uncomfortable-to-skip fast.
- **A noisy blocking gate becomes a muted gate.** Non-verdict signals (agent proposals,
  differential deltas) don't belong on the merge path. They belong on the human triage path.
- **Two tiers = two rhythms.** The PR tier enforces *"we didn't regress today."* The
  scheduled tier enforces *"we're still finding new gaps to plug."* Both matter.

## Consequences

- **Two GitHub Actions workflows.** `assurance-pr.yml` (blocking, on `pull_request`) and
  `assurance-scheduled.yml` (nightly cron + `workflow_dispatch`). Landed in P5.
- **Two seeds.** PR tier uses a fixed seed (checked into the workflow) so reproducibility is
  trivial. Scheduled tier draws a fresh seed per run and records it in every artifact.
- **Corpus grows monotonically.** Anything the scheduled tier + human triage confirms goes
  into the PR-tier corpus, tightening the blocking gate over time. The PR budget therefore
  needs occasional attention (retire slow-to-check redundant fixtures when a stronger
  generalization replaces them).
- **No release ships without green PR-tier assurance.** Enforced by branch protection at P5.

## Alternatives considered

- **Single tier, everything blocks.** Rejected: too slow, too noisy.
- **Single tier, nothing blocks (advisory only).** Rejected: assurance that doesn't gate
  merges is decoration.
- **Per-modality tiering.** Rejected: too many knobs. Two tiers is the schelling point that
  people can remember and reason about.
