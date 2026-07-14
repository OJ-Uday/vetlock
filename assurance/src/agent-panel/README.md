# Adversarial-agent panel (packet §5 P4)

The perpetual red-team, automated. A scheduled multi-agent job that:

1. Reads the CAPABILITY-MAP.
2. Asks a cheap-model agent (Sonnet or Haiku, never Opus) for novel evasion hypotheses per class.
3. Generates defanged fixtures for each hypothesis.
4. Runs them through the harness's bounded runner + `finding-survives` oracle.
5. Records any that evade as coverage gaps.

The human 31-exploit red-team campaign, made continuous.

## Tier

**SCHEDULED (nightly), NEVER PR-BLOCKING.** See packet §5 P4. The panel files coverage
gaps as issues/PRs; it does not fail CI. `runPanel(...)` returns a `PanelReport` — the
bytes are the signal.

## Modes

### `--agent=stub` (CI default)

Hard-coded hypotheses, byte-deterministic, no network, no API keys. This is what CI runs.
It exercises the whole pipeline (propose → defang → run → oracle → report) without an LLM
in the loop. Also acts as the reference implementation for the `EvasionAgent` interface.

### `--agent=claude` (scheduled tier, NOT CI)

Reserved for the future Anthropic-API integration. **Not wired yet** — attempting to use
it currently throws with a clear message. The follow-up commit will:

- Require `ANTHROPIC_API_KEY` in the environment.
- Ship an `EvasionAgent` implementation that calls the Anthropic Messages API with a
  cheap model (Haiku or Sonnet, per token & cost discipline).
- Never invoke the API from CI.

## CLI

```bash
node dist/agent-panel/cli.js --agent=stub --output=assurance/report/panel-report.json
```

Flags:

- `--agent=stub|claude` — agent to use (default: `stub`).
- `--output=<path>` — output JSON path (default: `assurance/report/panel-report.json`).
- `--seed=<int>` — deterministic seed (default: `42`).
- `--max-per-class=<int>` — max hypotheses per capability class (default: `3`).

Exits `0` always — the report is the signal, not the exit code.

## Defang guarantee (packet rule #2)

**Every fixture the panel runs is defang-clean.** The driver scans every hypothesis's
`generatedFixture` with `scanForDefangViolations` before running it. If the guard flags
even one violation, the hypothesis is REJECTED (recorded in `rejected[]`, not `runs[]`).
This is defense in depth — the stub-agent already produces clean fixtures, but the driver
enforces the rule regardless of which agent is plugged in. A hallucinating LLM cannot
introduce a live payload into the corpus this way.

## Human-in-the-loop triage protocol

The panel produces `panel-report.json`. A reviewer walks it as follows:

1. For each `run` where `evaded === true`:
   - Read the hypothesis (`technique`, `rationale`) and inspect `generatedFixture`.
   - Decide: is this a real gap, or an artifact of the mock CAPABILITY-MAP / no-detector
     wiring?
   - If real: file an issue against `OJ-Uday/vetlock` with the fixture + the class it
     breaks. Promote the fixture to `assurance/corpus/`. Add a regression test that
     currently fails (pins the gap; flips green when STARTUP wires the detector).
2. For each `rejected` entry:
   - Investigate why the defang guard flagged the fixture. If it's a false positive,
     tighten the guard's allow-list. If the hypothesis actually contained a live payload,
     that's a data point about the agent — worth logging.
3. Update the CAPABILITY-MAP with any newly discovered sink/entry-point. Bump enumerated
   coverage.

## What the report looks like

```json
{
  "runAt": "2026-07-14T12:00:00.000Z",
  "agent": "stub",
  "seed": 42,
  "hypothesesProposed": 12,
  "hypothesesAdmitted": 12,
  "hypothesesRejected": 0,
  "evasionsFound": 12,
  "runs": [
    {
      "hypothesis": {
        "id": "stub-child_process.exec-0-s42",
        "targetClass": "code-execution",
        "targetSink": "child_process.exec",
        "technique": "identifier-split-and-concat",
        "generatedFixture": "lockfileVersion: '6.0'\n...",
        "proposedBy": "stub",
        "rationale": "Split the sink identifier..."
      },
      "outcome": { "kind": "ok", "findings": [], "wallMs": 12, "seed": 42, "peakRssBytes": 134217728 },
      "evaded": true
    }
  ],
  "rejected": []
}
```

## Notes on the current mock

Until Wave 1B-H's `capability-map.json` merges, `loadCapabilityMap()` returns a hardcoded
four-class slice (`code-execution`, `net-egress`, `fs-write`, `env/secret-read`). When
1B-H lands, swap the import; the shape is already aligned.
