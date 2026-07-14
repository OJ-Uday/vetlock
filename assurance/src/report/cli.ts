/**
 * Report generator CLI — writes assurance/report/ASSURANCE.md.
 *
 * The CLI is the impure wrapper around the pure `generateReport` function. Its job is to
 * (a) measure — via `collectMetrics` (see ../metrics/collector.ts) — what actually happened
 * when the assurance suite ran, and (b) stamp — capture git SHA, node version, timestamp,
 * and seed as of *this* invocation. Then it hands a fully-populated ReportInput to the
 * generator and writes the output to `assurance/report/ASSURANCE.md`.
 *
 * Reproducibility invariant: because the generator is pure and the stamp includes git SHA
 * (which is committed content) + seed (an env var), two runs at the same commit with the same
 * seed produce byte-identical Metrics sections. Only the timestamp naturally differs. This is
 * what `assurance-report-generated.test.ts` asserts.
 */

import { writeFile, mkdir } from 'node:fs/promises';
import { execSync } from 'node:child_process';
import { dirname, resolve as pathResolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateReport, type ReportInput } from './generator.js';
import { collectMetrics } from '../metrics/index.js';

function getGitSha(): string {
  try {
    return execSync('git rev-parse HEAD', {
      cwd: pathResolve(dirname(fileURLToPath(import.meta.url)), '..', '..'),
      encoding: 'utf-8',
    }).trim();
  } catch {
    return 'unknown';
  }
}

async function main(): Promise<void> {
  const stampSeed = Number(process.env.ASSURANCE_SEED ?? '0');
  // The CLI produces an ISO-second timestamp so casual re-runs a minute apart produce a
  // recognizable diff. Reproducibility for the *engine* metrics comes from `seed`, not from
  // wall-clock time — the timestamp is the "when was this rendered" fact, not an input.
  const now = new Date();
  const timestampIso = now.toISOString().replace(/\.\d{3}Z$/, 'Z');

  // Measure. collectMetrics spawns vitest with the JSON reporter and buckets the results by
  // test-directory root (test/robustness/, test/evasion/, test/metamorphic/). Empty buckets
  // stay null → the generator renders them as "no data (tier not yet active)".
  const measured = await collectMetrics();

  const input: ReportInput = {
    stamp: {
      timestampIso,
      gitSha: getGitSha(),
      nodeVersion: process.version,
      seed: stampSeed,
      tier: 'foundations',
    },
    metrics: {
      robustnessPassRate: measured.robustnessPassRate,
      enumeratedCoverage: measured.enumeratedCoverage,
      evasionCatchRate: measured.evasionCatchRate,
      metamorphicInvariance: measured.metamorphicInvariance,
      differentialLedgerNote: measured.differentialLedgerNote,
    },
    notes: [
      {
        title: 'P0 status — foundations only',
        body:
          'The oracle set, bounded runner, and stamped report generator constitute the P0 ' +
          'foundations layer. As of 2026-07-14, P0 landed and P1-P5 were scaffolded in one ' +
          'parallel-agent wave; see the P0-P5 progress note below.',
      },
      {
        title: 'P0-P5 progress (2026-07-14 integration)',
        body:
          'The full six-phase packet has been scaffolded end-to-end. P0 foundations: 6 oracles, ' +
          'bounded runner (worker_threads + child_process fallback for V8-abort scenarios), ' +
          'stamped report generator. P1 robustness: defang guard (rule #2), 10+ generators ' +
          '(deep-nested-yaml — real gap found + pinned as corpus entry #1; npm-deep-json, ' +
          'yarn-classic-deep, yarn-berry-deep, redos, tar-bomb, gzip-bomb, graph-dos), ' +
          'never-execute-under-stress canary, engine wiring for parseLockfileText / runDiff / ' +
          'extractCapabilities / analyzeTarball, harness self-invariants (fast-check property ' +
          'suite). P2 completeness: CAPABILITY-MAP artifact (41 members enumerated, STARTUP §3.5 ' +
          'handoff hook), coverage gate, 8 completeness-vector transforms across 3 families. ' +
          'P3 metamorphic + differential: 5 pair families, npm-audit + osv-scanner adapters, ' +
          'classified delta ledger. P4 agent panel: stub-mode orchestration driver with defang ' +
          'guard defense. P5 release gate: two-tier GitHub Actions workflows (assurance-pr.yml ' +
          'blocking, assurance-scheduled.yml nightly), README badge + link, CODEOWNERS. ' +
          'Real metrics now flow into this report via collectMetrics(). See ' +
          '`~/personal/packets/PACKET-VETLOCK-ASSURANCE.md` for the phase plan.',
      },
      {
        title: 'Corpus entries so far',
        body:
          '`assurance/corpus/robustness/deep-nested-yaml/` — pnpm-lock.yaml with 100-level ' +
          'YAML nesting crashes `parseLockfileText` because @vetlock/core does not catch ' +
          'js-yaml\'s maxDepth exception. STARTUP owns the fix (wrap js-yaml.load in a try/catch ' +
          'that emits an `analysis.failed` finding). Regression test at ' +
          'assurance/test/robustness/no-crash.test.ts pins current behavior; assertion flips ' +
          'when the engine wraps the exception. ' +
          '`assurance/corpus/robustness/redos-safety-note/` — engine regex surface probed CLEAN ' +
          '(regenerate this test when the engine\'s regex surface changes).',
      },
    ],
  };

  const output = generateReport(input);
  const reportPath = pathResolve(
    dirname(fileURLToPath(import.meta.url)),
    '..',
    '..',
    'report',
    'ASSURANCE.md',
  );
  await mkdir(dirname(reportPath), { recursive: true });
  await writeFile(reportPath, output, 'utf-8');
  // Emit the path to stdout so CI can pick it up.
  process.stdout.write(`${reportPath}\n`);
}

main().catch((err: unknown) => {
  process.stderr.write(`assurance:report failed: ${err}\n`);
  process.exit(1);
});
