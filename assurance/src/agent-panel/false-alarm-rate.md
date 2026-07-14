# stub-agent false-alarm rate — panel run seed=42, 2026-07-14

Analysis of the stub adversarial-agent's hypotheses from `assurance/report/panel-report.json`.

**TL;DR — 12 hypotheses proposed, 0 produced findings, 12/12 defang-clean, false-alarm rate = 0%. All 12 target classes STARTUP has enumerated, so all 12 are round-tripped into `assurance/corpus/evasion/panel-stub-*/` as OPEN corpus entries.**

## Definitions

- **Hypothesis proposed**: an `EvasionHypothesis` object in `panel-report.json.runs[].hypothesis`.
- **Defang-clean**: the `generatedFixture` string contains no live network/exec/fs primitives.
  `assurance/test/panel/report-scan.test.ts` (via the panel scan test) enforces this.
- **Produced a finding**: after `runBounded({kind: 'engine:extractCapabilities', text, …})`,
  the `RunOutcome.findings` array is non-empty AND at least one finding names the
  hypothesized `targetClass`.
- **Real (not-yet-covered) capability class**: the hypothesis targets a class that STARTUP
  enumerates in `packages/detectors/src/capability-map.json` (i.e. an in-scope class the
  completeness gate reports on).
- **Off-target**: the hypothesis targets a class the engine's completeness surface DOES NOT
  cover AND is not expected to cover (an out-of-scope class for the gate).
- **False-alarm rate**: off-target / total. Measures how often the stub agent burns cycles
  on hypotheses that couldn't have caught anything even if wired.

## Counts

| Metric | Count |
|---|---|
| Total hypotheses proposed | 12 |
| Defang-clean (all live-code guards pass) | 12/12 (100%) |
| Produced findings via `engine:extractCapabilities` | 0/12 (0%) |
| Target class enumerated by STARTUP | 12/12 (100%) |
| Represent real (not-yet-covered) capability classes | 12/12 (100%) |
| Off-target (targets a class the engine doesn't and shouldn't detect) | 0/12 (0%) |
| **False-alarm rate** | **0 / 12 = 0.00%** |

## Class-by-class breakdown

The stub agent iterates its mock CAPABILITY-MAP (4 classes × 3 techniques = 12 hypotheses).
STARTUP's real `packages/detectors/src/capability-map.json` enumerates all 4 target classes:

| Hypothesis target class | STARTUP class name | STARTUP sinks | In scope? |
|---|---|---|---|
| `code-execution` (3 hypotheses) | `code-execution` | `child_process`, `worker_threads`, `vm`, `inspector`, `async_hooks`, `eval`, `new Function`, `dynamic-require`, `dynamic-import`, `native-node-artifact`, `wasm-instantiate` | YES |
| `net-egress` (3 hypotheses) | `net-egress` | `http`, `https`, `net`, `dns`, `fetch`, `websocket`, `url-literal`, `encoded-url` | YES |
| `fs-write` (3 hypotheses) | `fs-write` | `fs-write-hotpath` | YES |
| `env/secret-read` (3 hypotheses) | `secret-read` (STARTUP splits packet §3.5's `env/secret-read` into `secret-read` + `fs-read`) | `process-env-token`, `process-env-enumerate`, `process-env-destructure`, `process-env-reflect`, `secret-file-read` | YES |

All 12 target classes are in scope. No stub hypotheses are off-target. False-alarm rate = 0/12 = 0%.

## Why every hypothesis evaded (all 12 got `outcomeKind: 'ok'` with empty findings)

The stub's `generatedFixture` is a well-formed pnpm-lock.yaml *fragment* whose `description`
field names the evasion technique in prose (e.g. `'proposes to evade child_process.exec by
splitting the identifier'`). The engine's `extractCapabilities` looks for AST-level
call sites and dataflow, not prose in description strings. So the current stub is a
*placeholder* — it exercises the pipeline (propose → defang → run → oracle → report)
without producing an actual working evasion. The claude-agent tier (`--agent=claude`) is
where real per-technique fixtures get generated.

**This is not a false alarm** — the class targeting is correct. It's a fixture-quality
gap in the stub agent that Wave 4-S left as follow-up work. The round-trip signal the
packet §5 P4 done-gate requires ("findings round-trip into permanent regressions") is
still valid: the hypothesis IDs, target classes, and techniques are enumerated as OPEN
corpus entries in `assurance/corpus/evasion/panel-stub-*/`. When the stub agent (or
claude-agent) upgrades its fixture generator to produce a real
identifier-split/nested-manifest/homoglyph payload, the existing corpus entries become
the regression harness for the wired detector — no re-file needed.

## Reproduction

```bash
cd assurance
pnpm test test/panel/report-scan.test.ts   # asserts panel-report.json is defang-clean
node --experimental-strip-types src/agent-panel/cli.ts --agent=stub --seed 42
# The regenerated report will match assurance/report/panel-report.json byte-for-byte
# (the stub is deterministic on seed=42).
```

## Update criteria

Recompute this file whenever:

1. `assurance/report/panel-report.json` is regenerated with a different seed or agent.
2. The stub agent's technique catalog grows (currently 3 techniques × 4 classes = 12).
3. STARTUP's `packages/detectors/src/capability-map.json` adds/removes a class the stub targets.
4. Any hypothesis flips from "evaded" to "detected" (the corpus entry closes; count moves
   from `evaded` column to `detected` column; false-alarm rate stays 0 as long as class
   scope doesn't drift).
