# ADR 0002 (assurance): Four modalities — property, corpus, generative, agent-panel

**Status:** Accepted, 2026-07-14

Scope: `@vetlock/assurance` only.

## Context

Two failure modes for a supply-chain security engine (packet §1): it gets taken down, or it
gets fooled. Each failure mode has a large search space — an adversary can be creative in
either dimension. No single test methodology finds them all:

- **Unit tests** (which the engine already has 375 of) prove specific inputs produce specific
  outputs. They cannot enumerate the *shape* of "any input that could crash us."
- **Fuzzing alone** finds crashes but has no notion of "did the engine still detect the
  malicious behavior after mutation?" — no *semantics-aware* invariant.
- **A fixed corpus** is authoritative but static. Once written down, adversaries route around
  it; the corpus becomes proof of "we catch these five things," not "we catch this class."
- **Human red-team** finds novel gaps but doesn't scale, isn't repeatable, and isn't a build gate.

The harness needs breadth (fuzzing), depth (semantic invariants), regression durability (corpus),
and novelty (agent panel) simultaneously.

## Decision

Four modalities, one oracle set:

1. **Property-based** (fast-check). Invariants over generated adversarial inputs. Examples:
   for any well-formed lockfile, the engine returns *a verdict* (never crashes, never hangs
   past budget). For any semantics-preserving mutation of a known-caught fixture, the finding
   *survives*. Fast, deterministic under seed.
2. **Corpus-based**. A committed set of defanged adversarial fixtures under
   `assurance/corpus/`. Every gap discovered by any other modality lands here as a permanent
   regression (packet rule #6). The corpus is the *institutional memory* of the harness.
3. **Generative / fuzzers**. Bomb generators, ReDoS-string generators, obfuscation transforms,
   metamorphic pair batteries. Seeded (ADR-0003) for reproducibility; unbounded for coverage.
4. **Adversarial-agent panel**. A scheduled multi-agent job (§P4) that proposes *novel*
   evasion hypotheses against the current CAPABILITY-MAP, generates defanged fixtures, files
   any that evade as coverage gaps. This is the human red-team, automated + perpetual.

**All four feed the same oracle set** (ADR-0003 defines it): no-crash, no-hang, no-OOM,
fail-safe-verdict, finding-survives, identity-invariant. A gap found by any modality becomes
an oracle failure in a specific input, which becomes a corpus entry, which becomes a permanent
regression test — one flow regardless of who found it.

## Rationale

- **Complementary coverage.** Property tests find invariant violations *fast* on random inputs.
  Corpus tests prove specific historical attacks stay caught. Fuzzers find bombs and pathological
  shapes. Agents find *novel* attack ideas humans haven't enumerated. Each modality's blind spot
  is another's specialty.
- **One oracle set = one truth.** Different modalities finding gaps with different assertion
  vocabularies would fragment the "did we regress?" signal. One oracle set unifies the harness.
- **Permanence.** The corpus modality is the sink for everything the other three find. Nothing
  the harness catches is ever "we found it once and moved on."

## Consequences

- The harness has four subtrees (`corpus/`, plus generators in `robustness/` `evasion/`
  `metamorphic/`, plus `agents/`, plus property tests co-located with each). P0 stubs none of
  these — it delivers only the oracle set and the runner they'll all share.
- The agent panel is a scheduled tier (ADR-0004), not blocking. It costs money to run and its
  findings need human triage before joining the blocking corpus.
- Adding a new modality later doesn't require an oracle rework — just point it at the same
  oracles.

## Alternatives considered

- **Property tests only.** Rejected: no notion of "novel attack shape," no institutional
  memory of specific historical exploits.
- **Corpus only.** Rejected: adversaries route around a fixed list; no coverage of the
  *class*, only the members.
- **Fuzzing only.** Rejected: finds crashes, misses completeness gaps (the semantics-preserving
  mutation invariant is beyond raw fuzzing's assertion vocabulary).
