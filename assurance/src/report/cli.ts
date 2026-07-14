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
          'This is the P0 baseline report. Only the shared oracle set, the bounded runner, ' +
          'and this generator exist. No robustness corpus, no evasion mutation engine, no ' +
          'metamorphic pairs, no differential adapters, and no adversarial-agent panel yet. ' +
          'Numbers arrive in P1-P4; the release gate lands in P5. See ' +
          '`~/personal/packets/PACKET-VETLOCK-ASSURANCE.md` for the phase plan.',
      },
      {
        title: 'P1 progress — engine wired, first generator + first corpus entry',
        body:
          'P1 wired the real @vetlock/core engine through two entrypoints (parseLockfileText, ' +
          'runDiff) and shipped the DEFANGED-ONLY guard (packet rule #2) as an always-on ' +
          'scan of assurance/corpus/. First robustness generator: `deep-nested-yaml` — ' +
          'exposed a real gap where @vetlock/core lets js-yaml\'s maxDepth exception escape ' +
          'unwrapped (should emit an `analysis.failed` finding via the engine\'s existing ' +
          'fail-safe convention). Gap pinned as corpus entry #1 (`assurance/corpus/robustness/' +
          'deep-nested-yaml/`) with the assertion-flip instructions for when STARTUP fixes it. ' +
          'Robustness metric is still `null` because the tier isn\'t fully populating yet ' +
          '(1 generator ≠ the full §2.1 threat family). It will populate as more generators ' +
          'land (parser-DoS, ReDoS, graph-DoS, resource-abuse, fail-open probes, hostile ' +
          'lifecycle scripts). Honest reporting: 1 gap discovered, 1 corpus regression filed.',
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
