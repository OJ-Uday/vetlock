/**
 * Report generator CLI — writes assurance/report/ASSURANCE.md.
 *
 * P0's report is the foundations tier: no metrics are measured yet, so every rate is null and
 * renders as "no data (tier not yet active)". Later phases (P1-P5) will populate the numbers.
 *
 * The stamp fields (git SHA, node version, timestamp, seed) come from environment / process
 * introspection here — but the generator itself is a pure function of ReportInput, so the
 * reproducibility invariant remains testable in isolation.
 */

import { writeFile, mkdir } from 'node:fs/promises';
import { execSync } from 'node:child_process';
import { dirname, resolve as pathResolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateReport, type ReportInput } from './generator.js';

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

  const input: ReportInput = {
    stamp: {
      timestampIso,
      gitSha: getGitSha(),
      nodeVersion: process.version,
      seed: stampSeed,
      tier: 'foundations',
    },
    metrics: {
      robustnessPassRate: null,
      enumeratedCoverage: null,
      evasionCatchRate: null,
      metamorphicInvariance: null,
      differentialLedgerNote: null,
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
