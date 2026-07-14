# @vetlock/assurance corpus

**Institutional memory of the standing adversary** (ADR-0002 modality 2).

Every gap the harness finds — whether from property fuzzing (modality 1), generative
robustness (modality 3), or the adversarial-agent panel (modality 4) — lands here as a
permanent regression. Nothing the harness catches is ever "we found it once and moved on"
(packet rule #6).

## Directory layout

```
assurance/corpus/
  robustness/           inputs that historically crashed / hung / OOM'd / fail-open'd the engine
    <slug>/             one directory per gap
      README.md         what the input demonstrates, when it was found, why it's here
      fixture.<ext>     the defanged input (lockfile, source string, tarball spec, etc.)
      regression.test.ts named test that feeds fixture through the runner + oracles
  evasion/              (P2) semantics-preserving mutations of known-caught fixtures
  metamorphic/          (P3) identity-invariant program pairs
  differential/         (P3) inputs where public scanners disagree
```

## Contract for adding to the corpus

1. **Every fixture is DEFANGED** (packet rule #2). No live network endpoints, no runnable
   exec targets, no encoded payloads that decode+exec. The `assurance-defang-guard.test`
   scans this whole tree on every run — a violation is a build failure, not a review note.

2. **Every fixture has a README.md** stating: (a) what class of gap it demonstrates,
   (b) when + how it was found (e.g. "agent-panel run 2026-08-03 seed 12345"),
   (c) why blocking it matters (the class of attack in the wild).

3. **Every fixture has a named regression test** that runs it through the bounded runner
   and asserts the appropriate oracle passes. When the gap gets fixed in the engine, this
   test proves the fix; when the engine regresses, this test fires.

4. **Corpus is monotonic.** We never delete an entry. If a fixture becomes redundant with
   a stronger generalization, we mark it superseded via a note in its README but keep the
   file so the historical record stays intact.

## P0/early-P1 state

Empty except for this README and per-subtree `.gitkeep` markers. The first entry will land
with P1's first robustness generator (packet §5 P1). Every entry after that follows the
contract above.
