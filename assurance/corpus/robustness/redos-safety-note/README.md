# redos-safety-note — ReDoS probes against the engine's regex surface came back CLEAN

**Robustness class: ReDoS (catastrophic regex backtracking).** Packet §2.1 threat family.
Landed with P1 assurance wave 1 (Agent E).

## Executive summary

Every regex exposed on the engine's public parse surface (reachable from
`parseLockfileText`) was probed with adversarial input scaled to force backtracking at
100, 1000, and 10000 chars. **All candidates completed within a 1500ms wallMs bound at
every scale** — no timeouts, no OOM.

**This is a legitimate class-safe outcome** (packet §7): "If nothing survives, note it in
the corpus README as 'class covered by delegation to vendored libs; direct regex surface
is safe.'" Applies to the engine's regex surface as of `origin/main@9fec287` (2026-07-14).

## Regexes probed

Every literal regex reachable from `parseLockfileText(text, filename)` was enumerated by
reading these engine source files line-by-line:

- `packages/core/src/lockfile-any.ts`
- `packages/core/src/lockfile-yarn.ts`
- `packages/core/src/lockfile-pnpm.ts` (no direct regex — delegates all parsing to `js-yaml`)
- `packages/core/src/lockfile.ts` (no direct regex — pure map iteration over parsed JSON)

Result:

| Source | Line | Pattern | Backtracking risk | Adversarial-input verdict |
|---|---|---|---|---|
| lockfile-any.ts | 52 | `filename.split(/[\\/]/)` | none — single-char class | trivially safe |
| lockfile-any.ts | 57 | `/^\s*__metadata:/m` | none — anchored literal prefix | trivially safe |
| lockfile-any.ts | 63 | `/^lockfileVersion:/m` | none — anchored literal | trivially safe |
| lockfile-any.ts | 64 | `/^__metadata:/m` | none — anchored literal | trivially safe |
| lockfile-any.ts | 65 | `/^# yarn lockfile v1/m` | none — anchored literal | trivially safe |
| **lockfile-any.ts** | **65** | **`/^\w[\w./@-]*@[^:]+:\s*$/m`** | **PLAUSIBLE (quantifier + `@` in char class)** | **PROBED — safe at spec'd scales** |
| lockfile-yarn.ts | 53 | `/^\s*__metadata:/m` | none — anchored literal | trivially safe |
| lockfile-yarn.ts | 53 | `/^__metadata\b/m` | none — anchored literal + `\b` | trivially safe |
| lockfile-yarn.ts | 211 | `/^[\^~><=*]/` | none — anchored single-char class | trivially safe |

The only regex worth stressing on the direct surface is
**`/^\w[\w./@-]*@[^:]+:\s*$/m`** (`lockfile-any.ts:65`) — the yarn-classic content-only
detector. It has three properties that MIGHT enable backtracking:

1. `[\w./@-]*` is greedy AND its char class **includes `@`**; the literal `@` that
   follows must then also match — so any `@` in a run is a candidate anchor position.
2. `[^:]+` is greedy AND matches newlines (no `s` flag); input without `:` forces
   `[^:]+` to consume all remaining bytes then backtrack byte-by-byte hunting for a
   terminal `:` that isn't there.
3. The `m` flag re-anchors `^` at every line start; each fresh anchor pays the full
   probe cost.

## Adversarial input tested

Generator `redosCandidates[0]` at
`assurance/src/robustness/redos.ts` — `lockfile-any-yarn-classic-detect-many-ats`:

```ts
// scale=N produces one line: 'a' + '@' * N + '\n'
//
//   • no colon anywhere → [^:]+ must scan to end of string then fail
//   • many @ chars → many candidate anchor positions for the outer group
//   • no leading '{', no 'lockfileVersion:', no '__metadata:', no '# yarn lockfile v1'
//     → every earlier short-circuit in detectKind() misses and control falls straight
//     into our target regex
```

Filename set to `lockfile.txt` — an unrecognized basename — so `detectKind()` skips the
filename-branch and runs the content-only detector, which is our target.

## Observed engine behavior at each scale

Using `runBounded` (worker_threads sandbox, wallMs=1500, heapMb=128) with the
`engine:parseLockfileText` scenario:

| Scale | Outcome | Notes |
|---|---|---|
| 100   | `crash` (`UnsupportedLockfileError: could not detect lockfile format from content`) | Target regex executes (returns false), then `detectKind` throws. Wall time ≈ 200-300ms (dominated by worker cold-start; target regex ≪ 1ms). |
| 1_000 | `crash` (same) | Wall time ≈ 200-300ms. Regex CPU ≈ 1ms. |
| 10_000 | `crash` (same) | Wall time ≈ 250-400ms. Regex CPU ≈ 35ms. |

`crash` here is INFORMATIVE, not a defect for this class: the target regex ran to
completion (returning `false`), all detector regexes in `detectKind` executed cleanly,
then the function threw because no detector matched. This is exactly the behavior we'd
expect from a *safe* regex on adversarial input — it completes, doesn't hang, doesn't
allocate, and the parser's error path takes over.

**No `timeout` was observed at any scale.** No `oom`. That is the packet §7 safe-class
outcome for this candidate.

## Polynomial worst case (informational — outside spec'd scales)

Direct out-of-worker measurement (a short node script executing `regex.test(input)` in
process, no worker overhead) shows the `/^\w[\w./@-]*@[^:]+:\s*$/m` regex IS O(N²):

| n     | regex time |
|-------|-----------:|
|  1000 |      1ms   |
| 10000 |     38ms   |
| 20000 |    145ms   |
| 40000 |    577ms   |
| 80000 |   2319ms   |
|100000 |   3475ms   |

At the packet's spec'd scales (100 / 1000 / 10000) the small constant keeps this
comfortably safe — 38ms even at the top end. If real-world lockfile inputs grow to
100k+ chars on a single line (unusual — yarn lockfile entries are short), a follow-up
robustness sub-phase should introduce a `stress-scale` tier (100k, 1M) and pin whatever
timeout falls out. Until then, this candidate is **safe within the current spec** and
does not warrant a corpus fixture pinning a specific gap.

## Why the vendored parser surface is NOT probed here

Once `detectKind()` picks a format, parsing delegates to:
- `JSON.parse` (`npm` branch) — built-in, not our surface
- `js-yaml.load` (`pnpm` branch) — vendored, covered by `deep-nested-yaml`
- `@yarnpkg/lockfile` / `@yarnpkg/parsers` — vendored, deep parsing

Any ReDoS lurking inside those vendored libraries is a supply-chain / upstream concern.
The scout report (see task packet) explicitly scoped this candidate to the engine's own
regex surface.

## Assertion-flip instructions (protocol for when a ReDoS IS ever found here)

When a future change to the engine's regex surface DOES introduce a ReDoS:

1. Add a NEW `ReDosCandidate` in `assurance/src/robustness/redos.ts` pointing at the
   offending regex (source location in `targetRegex`).
2. Choose an adversarial `generate(scale)` that exercises the pathological path.
3. Run the test — expect one or more `scale=N — outcome is 'ok' or 'timeout'` test
   cases to observe `timeout` outcomes. The `console.warn("[redos] REAL FINDING ...")`
   line will fire, naming the candidate + scale.
4. Add a corpus entry under `assurance/corpus/robustness/redos-<candidate-id>/`:
   - `README.md` — same shape as this note, but documenting the FINDING (which regex,
     which scale started timing out, what an attacker gains).
   - `fixture.<ext>` — the exact byte-for-byte adversarial input produced by
     `generate(scale)`. Chose the smallest scale that reproducibly times out.
5. STARTUP fixes the regex (usually: swap the greedy quantifier for a possessive-ish
   pattern, or split the regex into two anchored halves that can't nest).
6. When the fix lands: the timing test flips green (outcome becomes `ok`); if you want
   to prove the fix, tighten the corresponding scale's assertion to
   `expect(outcome.kind).toBe('ok')`.

## Regeneration protocol (someone changed the engine's regex surface)

**If you edit any of these files, you MUST re-run this test class before merging:**

- `packages/core/src/lockfile-any.ts` (detectKind + parseLockfileText)
- `packages/core/src/lockfile-yarn.ts` (parseYarnLockText + parseYarnAlias)
- `packages/core/src/lockfile-pnpm.ts` (parsePnpmLockText — currently delegates all to js-yaml)
- `packages/core/src/lockfile.ts` (parseLockfile — currently no regex)

Command:

```bash
pnpm --filter @vetlock/assurance test -- test/robustness/redos.test.ts
```

Any NEW regex you add to those files must be enumerated (add a row to the table above)
and probed (add a `ReDosCandidate` if the shape has any quantifier ambiguity).

## Status

- **Found:** 2026-07-14 (assurance P1 wave 1, Agent E — ReDoS)
- **Class verdict:** SAFE at spec'd scales (100 / 1000 / 10000). No corpus fixture pinning
  a gap because no gap was observed.
- **Filed as engine gap:** N/A.
- **Next re-scan trigger:** any diff touching regex literals in the four engine files listed above.
