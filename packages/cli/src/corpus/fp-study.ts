/**
 * FP study infrastructure — measures vetlock's false-positive rate against real
 * routine version bumps.
 *
 * Given a list of `<package>@<old-version>..<new-version>` triples, this script:
 *   1. Fetches both versions via pacote (real network)
 *   2. Constructs the equivalent lockfile-before / lockfile-after
 *   3. Runs runDiff
 *   4. Records the findings per detector
 *
 * Assumption: every input pair is a KNOWN-GOOD, non-attack version bump. Anything
 * vetlock flags is a FALSE POSITIVE. The output report shows:
 *   - Total bumps analyzed
 *   - Per-detector count of findings (a proxy for FP rate)
 *   - Per-severity distribution
 *
 * Usage:
 *   node dist/corpus/fp-study.js --input studies/top-100.txt --output studies/results.json
 *
 * Input format: one line per bump: `pkg@old..new`. Comments start with `#`.
 *
 * WHY this is separate from the corpus tests:
 *   - Runs against LIVE npm (needs network access; slow)
 *   - No ground truth for individual findings (bumps assumed benign; the
 *     rate matters, not which specific things flagged)
 *   - Used to TUNE detector defaults, not to VERIFY them
 *
 * Once run, the results feed back into per-detector confidence thresholds
 * so we can say things like "net.new-endpoint fires on 0.7% of routine bumps
 * of the top 100, confidence level XYZ" in DETECTIONS.md.
 *
 * WHY we can't just include a big precomputed dataset:
 *   Real npm changes constantly. Running it against a canned dataset of yesterday's
 *   versions doesn't measure today's noise floor. Always run fresh.
 */

import { promises as fs } from 'node:fs';
import * as path from 'node:path';
import { parseArgs } from 'node:util';
import {
  runDiff,
  VETLOCK_VERSION,
  type Finding,
  type Severity,
} from '@vetlock/core';
import { runAll } from '@vetlock/detectors';

interface StudyBump {
  packageName: string;
  oldVersion: string;
  newVersion: string;
}

interface StudyResultRow {
  packageName: string;
  oldVersion: string;
  newVersion: string;
  verdict: string;
  findings: number;
  detectors: string[];
  errored?: boolean;
  errorMessage?: string;
}

interface StudyReport {
  vetlockVersion: string;
  ranAt: string;
  totalBumps: number;
  bumpsSucceeded: number;
  bumpsFailed: number;
  totalFindings: number;
  findingsPerBump: number;
  perDetectorFpRate: Record<string, { hits: number; ratePerBump: number }>;
  perSeverity: Record<Severity | 'CLEAN', number>;
  worstOffenders: Array<{ packageName: string; findings: number; detectors: string[] }>;
  rows: StudyResultRow[];
}

async function main() {
  const { values } = parseArgs({
    options: {
      input: { type: 'string' },
      output: { type: 'string', default: 'studies/fp-results.json' },
      verbose: { type: 'boolean', default: false },
    },
  });
  if (!values.input) {
    console.error('usage: fp-study.js --input <file.txt> [--output results.json] [--verbose]');
    process.exit(1);
  }

  const bumps = await parseInputFile(values.input);
  console.error(`fp-study: ${bumps.length} bumps queued`);

  const rows: StudyResultRow[] = [];
  const detectorHits = new Map<string, number>();
  const severityCounts: Record<string, number> = { BLOCK: 0, WARN: 0, INFO: 0, CLEAN: 0 };
  let succeeded = 0;
  let failed = 0;
  let totalFindings = 0;

  for (let i = 0; i < bumps.length; i++) {
    const bump = bumps[i]!;
    const label = `${bump.packageName}@${bump.oldVersion}..${bump.newVersion}`;
    process.stderr.write(`[${i + 1}/${bumps.length}] ${label}… `);
    try {
      const result = await analyzeSingleBump(bump);
      severityCounts[result.verdict]!++;
      totalFindings += result.findings.length;
      const detectors = [...new Set(result.findings.map((f) => f.detector))];
      for (const d of detectors) {
        detectorHits.set(d, (detectorHits.get(d) ?? 0) + 1);
      }
      const row: StudyResultRow = {
        packageName: bump.packageName,
        oldVersion: bump.oldVersion,
        newVersion: bump.newVersion,
        verdict: result.verdict,
        findings: result.findings.length,
        detectors,
      };
      rows.push(row);
      succeeded++;
      process.stderr.write(`${result.verdict} (${result.findings.length} findings)\n`);
    } catch (err) {
      failed++;
      const msg = err instanceof Error ? err.message : String(err);
      rows.push({
        packageName: bump.packageName,
        oldVersion: bump.oldVersion,
        newVersion: bump.newVersion,
        verdict: 'ERROR',
        findings: 0,
        detectors: [],
        errored: true,
        errorMessage: msg,
      });
      process.stderr.write(`ERROR: ${msg.slice(0, 80)}\n`);
    }
  }

  const perDetectorFpRate: Record<string, { hits: number; ratePerBump: number }> = {};
  for (const [d, hits] of detectorHits) {
    perDetectorFpRate[d] = {
      hits,
      ratePerBump: succeeded > 0 ? hits / succeeded : 0,
    };
  }

  const worst = rows
    .filter((r) => !r.errored)
    .sort((a, b) => b.findings - a.findings)
    .slice(0, 10)
    .map((r) => ({
      packageName: r.packageName,
      findings: r.findings,
      detectors: r.detectors,
    }));

  const report: StudyReport = {
    vetlockVersion: VETLOCK_VERSION,
    ranAt: new Date().toISOString(),
    totalBumps: bumps.length,
    bumpsSucceeded: succeeded,
    bumpsFailed: failed,
    totalFindings,
    findingsPerBump: succeeded > 0 ? totalFindings / succeeded : 0,
    perDetectorFpRate,
    perSeverity: severityCounts as StudyReport['perSeverity'],
    worstOffenders: worst,
    rows: values.verbose ? rows : [],
  };

  await fs.mkdir(path.dirname(values.output!), { recursive: true });
  await fs.writeFile(values.output!, JSON.stringify(report, null, 2));
  console.error(`\nfp-study: report → ${values.output}`);
  console.error(`  total: ${succeeded}/${bumps.length} succeeded (${failed} errored)`);
  console.error(`  findings/bump: ${report.findingsPerBump.toFixed(3)}`);
  console.error(`  verdicts: BLOCK=${severityCounts.BLOCK} WARN=${severityCounts.WARN} INFO=${severityCounts.INFO} CLEAN=${severityCounts.CLEAN}`);
  console.error(`  top FP detectors:`);
  const topDetectors = Object.entries(perDetectorFpRate)
    .sort(([, a], [, b]) => b.hits - a.hits)
    .slice(0, 5);
  for (const [d, r] of topDetectors) {
    console.error(`    ${d}: ${r.hits} hits (${(r.ratePerBump * 100).toFixed(1)}%)`);
  }
}

async function parseInputFile(inputPath: string): Promise<StudyBump[]> {
  const raw = await fs.readFile(inputPath, 'utf8');
  const bumps: StudyBump[] = [];
  for (const line of raw.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    // Format: pkg@old..new  OR  pkg@old..pkg@new
    const dotdot = trimmed.indexOf('..');
    if (dotdot === -1) continue;
    const leftPart = trimmed.slice(0, dotdot);
    const rightPart = trimmed.slice(dotdot + 2);
    const leftAt = leftPart.lastIndexOf('@');
    if (leftAt <= 0) continue;
    const packageName = leftPart.slice(0, leftAt);
    const oldVersion = leftPart.slice(leftAt + 1);
    // right may or may not have package@ prefix
    let newVersion = rightPart;
    if (rightPart.includes('@')) {
      newVersion = rightPart.slice(rightPart.lastIndexOf('@') + 1);
    }
    if (!packageName || !oldVersion || !newVersion) continue;
    bumps.push({ packageName, oldVersion, newVersion });
  }
  return bumps;
}

async function analyzeSingleBump(bump: StudyBump): Promise<{ verdict: string; findings: Finding[] }> {
  // Build synthetic lockfiles referencing the two versions.
  const lockBefore = JSON.stringify({
    name: 'fp-study-app',
    version: '1.0.0',
    lockfileVersion: 3,
    packages: {
      '': { name: 'fp-study-app', version: '1.0.0', dependencies: { [bump.packageName]: `^${bump.oldVersion}` } },
      [`node_modules/${bump.packageName}`]: {
        name: bump.packageName,
        version: bump.oldVersion,
        // Integrity intentionally empty — pacote will fetch by version.
        integrity: '',
        resolved: '',
      },
    },
  });
  const lockAfter = JSON.stringify({
    name: 'fp-study-app',
    version: '1.0.0',
    lockfileVersion: 3,
    packages: {
      '': { name: 'fp-study-app', version: '1.0.0', dependencies: { [bump.packageName]: `^${bump.newVersion}` } },
      [`node_modules/${bump.packageName}`]: {
        name: bump.packageName,
        version: bump.newVersion,
        integrity: '',
        resolved: '',
      },
    },
  });

  const result = await runDiff(lockBefore, lockAfter, {
    runDetectors: (pair) => runAll(pair),
    timeoutMs: 60_000,
  });
  return { verdict: result.verdict, findings: result.findings };
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
