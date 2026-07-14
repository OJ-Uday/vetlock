/**
 * Adversarial-agent panel CLI entry.
 *
 * Runs the panel and writes `panel-report.json` to the requested path. Prints a summary
 * to stdout for human eyes.
 *
 * Usage:
 *   node dist/agent-panel/cli.js --agent=stub --output=assurance/report/panel-report.json
 *
 * Flags:
 *   --agent=stub           choose the agent (only 'stub' is wired for CI; 'claude' is
 *                          reserved for the future Anthropic-API implementation and
 *                          currently rejects with a clear message).
 *   --output=<path>        where to write the report JSON. Default:
 *                          assurance/report/panel-report.json (relative to CWD).
 *   --seed=<int>           deterministic seed. Default: 42.
 *   --max-per-class=<int>  maximum hypotheses per capability class. Default: 3.
 *
 * Exit status:
 *   0 always (scheduled tier — never blocking). Even when evasions are found we exit 0;
 *   the report bytes are the signal, and a downstream consumer (a scheduled job) is
 *   responsible for filing issues/PRs against confirmed evasions.
 */

import { writeFile, mkdir } from 'node:fs/promises';
import { dirname, resolve as pathResolve } from 'node:path';
import { runPanel } from './panel.js';
import { stubAgent } from './stub-agent.js';
import { loadCapabilityMap } from './capability-map.js';
import type { EvasionAgent, PanelReport } from './types.js';

interface ParsedArgs {
  readonly agent: 'stub' | 'claude';
  readonly output: string;
  readonly seed: number;
  readonly maxPerClass: number;
}

function parseArgs(argv: readonly string[]): ParsedArgs {
  let agent: 'stub' | 'claude' = 'stub';
  let output = 'assurance/report/panel-report.json';
  let seed = 42;
  let maxPerClass = 3;

  for (const arg of argv) {
    if (arg.startsWith('--agent=')) {
      const v = arg.slice('--agent='.length);
      if (v !== 'stub' && v !== 'claude') {
        throw new Error(`--agent must be 'stub' or 'claude'; got ${v}`);
      }
      agent = v;
    } else if (arg.startsWith('--output=')) {
      output = arg.slice('--output='.length);
    } else if (arg.startsWith('--seed=')) {
      const n = Number(arg.slice('--seed='.length));
      if (!Number.isInteger(n)) throw new Error(`--seed must be an integer; got ${arg}`);
      seed = n;
    } else if (arg.startsWith('--max-per-class=')) {
      const n = Number(arg.slice('--max-per-class='.length));
      if (!Number.isInteger(n) || n < 0) {
        throw new Error(`--max-per-class must be a non-negative integer; got ${arg}`);
      }
      maxPerClass = n;
    } else if (arg === '--help' || arg === '-h') {
      // Fall through — printed by main().
      throw new Error('help');
    }
  }
  return { agent, output, seed, maxPerClass };
}

/**
 * Pick the agent by name. 'claude' is intentionally NOT wired here — it's a future commit
 * gated on the user actually having credentials. Attempting to use it should fail loudly.
 */
function pickAgent(name: 'stub' | 'claude'): EvasionAgent {
  if (name === 'stub') return stubAgent;
  throw new Error(
    "agent=claude is not yet wired; the Anthropic-API integration is a follow-up commit. " +
      "The panel driver ships with the stub agent as the CI default (packet §5 P4, scheduled tier only).",
  );
}

/**
 * Format a one-line-per-run summary for stdout.
 */
function summarize(report: PanelReport): string {
  const lines: string[] = [];
  lines.push(`[agent-panel] runAt=${report.runAt} agent=${report.agent} seed=${report.seed}`);
  lines.push(
    `[agent-panel] proposed=${report.hypothesesProposed} admitted=${report.hypothesesAdmitted} rejected=${report.hypothesesRejected} evasions=${report.evasionsFound}`,
  );
  for (const run of report.runs) {
    const flag = run.evaded ? 'EVADED' : 'caught';
    lines.push(
      `  ${flag}  ${run.hypothesis.id}  class=${run.hypothesis.targetClass}  sink=${run.hypothesis.targetSink}  technique=${run.hypothesis.technique}  outcomeKind=${run.outcome.kind}`,
    );
  }
  for (const rej of report.rejected) {
    lines.push(`  REJECTED  ${rej.hypothesis.id}  ${rej.reason}`);
  }
  return lines.join('\n');
}

async function main(argv: readonly string[]): Promise<void> {
  let args: ParsedArgs;
  try {
    args = parseArgs(argv);
  } catch (err) {
    if (err instanceof Error && err.message === 'help') {
      process.stdout.write(HELP_TEXT);
      return;
    }
    throw err;
  }

  const agent = pickAgent(args.agent);
  const capabilityMap = loadCapabilityMap();

  const report = await runPanel({
    agent,
    capabilityMap,
    maxHypothesesPerClass: args.maxPerClass,
    seed: args.seed,
  });

  // Write JSON with a stable shape — 2-space indent, trailing newline. Any downstream
  // reader (a jq pipeline, a human review) benefits from readable output.
  const outputPath = pathResolve(process.cwd(), args.output);
  await mkdir(dirname(outputPath), { recursive: true });
  await writeFile(outputPath, JSON.stringify(report, null, 2) + '\n', 'utf8');

  process.stdout.write(summarize(report) + '\n');
  process.stdout.write(`[agent-panel] wrote ${outputPath}\n`);
}

const HELP_TEXT = `Usage: node dist/agent-panel/cli.js [flags]

Flags:
  --agent=stub|claude       agent to use (default: stub; claude is not yet wired)
  --output=<path>           output JSON path (default: assurance/report/panel-report.json)
  --seed=<int>              deterministic seed (default: 42)
  --max-per-class=<int>     max hypotheses per capability class (default: 3)
  --help, -h                show this help
`;

// Invoke main when run directly. In an ES module world, comparing import.meta.url to a
// file:// URL derived from process.argv[1] is the idiomatic "is this the entry point?"
// check. When imported as a library, main() is never invoked.
const isEntry = (() => {
  const invoked = process.argv[1];
  if (!invoked) return false;
  const invokedUrl = new URL(`file://${pathResolve(invoked)}`).href;
  return invokedUrl === import.meta.url;
})();

if (isEntry) {
  main(process.argv.slice(2)).catch((err: unknown) => {
    process.stderr.write(`[agent-panel] error: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exit(1);
  });
}
