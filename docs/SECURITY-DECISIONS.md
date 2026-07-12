# Security-first decision principles

**vetlock is a security tool. When correctness and performance conflict, we choose correctness.**

This document exists to prevent one specific failure mode: rationalizing an incorrectness on the basis that "attackers rarely do X." Attackers *specifically* look for the things you assumed rare. If it's rare *before* your tool ships, it becomes common *after* — because you've told everyone which paths you don't cover.

## The specific principle

**Do not adopt a fast-but-inexact algorithm on a security decision boundary.**

If the choice is between:

- Algorithm A: measurably correct against the threat class, runs in 1 µs
- Algorithm B: 30% faster (0.7 µs), misses some cases in the threat class

...then A wins. Every time. The perf difference is measured in microseconds on paths that execute maybe a few dozen times per PR check. The correctness gap is measured in "entire classes of attack we don't see."

## Concrete example — the `damerau-levenshtein` vs `fastest-levenshtein` decision

In v0.2.0 development I briefly swapped hand-rolled Damerau-Levenshtein for `fastest-levenshtein`, citing a "~3× perf improvement" and rationalizing "attackers rarely rely on transpositions."

**That reasoning was wrong.** Two problems:

1. **The perf argument is fake.** The detector runs at most a few dozen times per PR check. 3× faster on a µs-scale operation is invisible in the run time. Nobody adopts vetlock for that.
2. **The threat argument is wrong.** Transposition typosquats (`debgu` for `debug`, `axois` for `axios`, `chlak` for `chalk`, `expreess` for `express`) are one of the most documented typosquat shapes in the ecosystem. npm's own security team has repeatedly called them out. Under plain Levenshtein these all score distance-2 (delete-then-insert) and slip past a distance-≤2 threshold.

The decision was reverted immediately. The tests in `packages/detectors/test/typo.test.ts` lock in every one of these transposition cases so no future refactor can regress the behavior "for perf" without an explicit test failure.

## How to apply this principle

When choosing a dependency or writing an internal helper for a detector path:

1. **List the concrete attack shapes** it needs to catch.
2. **Verify the candidate actually catches them** — write a failing test using each attack shape before you write the implementation. TDD is a security tool here, not just a development convenience.
3. **If the "faster" option misses ANY of them, choose the slower one.** No exceptions on security paths.
4. **Add a regression test that includes the exact attack shape.** If someone later swaps the dependency, the test tells them why.
5. **Document why** in the code (as we did in `typo.ts`). A future contributor should know instantly that the algorithm choice is a security decision, not a perf decision.

## Where perf DOES matter

The hot paths in vetlock are:

- **Fetch** (network-bound; parallelism helps, algorithm perf doesn't)
- **Tar extraction** (already optimized, capped by disk I/O)
- **AST parse** (already using the fastest correct option — `@babel/parser`)
- **Detector traversal** (once per file, per package)

Nowhere in this list is "string comparison of package names against a 200-entry list" a bottleneck. The typo-detector calls DL 200 times per new package. That's ~50 µs total per new package. The next micro-optimization someone finds there — do not accept it if it costs correctness.

## The mental model

You are the reviewer, not the developer. Any time a detector change reads *"we accept the trade-off of..."* or *"attackers rarely..."*, it should feel like a code smell. The correct sentence to write is: *"the naive algorithm handles this attack shape, so we use the naive algorithm; if perf were ever a real problem we'd revisit with real measurement, not with a guess."*
