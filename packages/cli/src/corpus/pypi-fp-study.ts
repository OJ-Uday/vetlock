/**
 * PyPI FP study — measures vetlock's false-positive rate against real
 * routine Python package version bumps.
 *
 * Usage:
 *   # Against public PyPI (default):
 *   node dist/corpus/pypi-fp-study.js --input studies/pypi-top-100.txt
 *
 *   # Against Artifactory proxy:
 *   VETLOCK_PYPI_JSON_URL=https://corp.jfrog.io/artifactory/api/pypi/pypi-remote \
 *   VETLOCK_PYPI_AUTH=$JF_AUTH \
 *   node dist/corpus/pypi-fp-study.js --input studies/pypi-top-100.txt
 *
 *   # With concurrency and output file:
 *   node dist/corpus/pypi-fp-study.js \
 *     --input studies/pypi-top-100.txt \
 *     --output studies/pypi-fp-results-v0.7.json \
 *     --concurrency 4
 *
 * Output: JSON with per-bump verdicts + aggregated per-detector FP counts.
 * Interpretation: anything vetlock flags is a false positive (all input bumps
 * are known-good). Use the output to tune detector thresholds.
 */

import { promises as fs } from 'node:fs';
import * as path from 'node:path';
import { parseArgs } from 'node:util';
import {
  fetchPypiArtifact,
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

interface FindingSummary {
  severity: Severity;
  detector: string;
  message: string;
}

interface StudyResultRow {
  package: string;
  packageName: string;
  oldVersion: string;
  newVersion: string;
  verdict: Severity | 'CLEAN' | 'ERROR';
  findingCount: number;
  detectors: string[];
  findings: FindingSummary[];
  durationMs: number;
  errorMessage?: string;
}

interface StudySummary {
  BLOCK: number;
  WARN: number;
  INFO: number;
  CLEAN: number;
  ERROR: number;
  blockRate: number;
  warnOrBlockRate: number;
  detectorHits: Record<string, number>;
}

interface StudyReport {
  version: string;
  ecosystem: 'pypi';
  vetlockVersion: string;
  ranAt: string;
  registryUsed: string;
  inputFile: string;
  sourceTotalBumps: number;
  batchOffset: number;
  batchSize: number;
  totalBumps: number;
  results: StudyResultRow[];
  summary: StudySummary;
}

const DEFAULT_OUTPUT = 'studies/pypi-fp-results.json';
const DEFAULT_CONCURRENCY = 4;
const DEFAULT_REGISTRY = 'https://pypi.org';
const HELP_TEXT = `PyPI FP study — benign routine bump analyzer

Usage:
  node packages/cli/dist/corpus/pypi-fp-study.js --input <file>
    [--output <file>] [--concurrency <n>]
    [--batch-offset <n>] [--batch-size <n>]

Options:
  --input          Input file with pkg@old..new lines
  --output         Results JSON path (default: ${DEFAULT_OUTPUT})
  --concurrency    Number of bumps to analyze at once (default: ${DEFAULT_CONCURRENCY})
  --batch-offset   Skip the first N parsed bumps before analyzing
  --batch-size     Analyze at most N bumps after applying the offset
  --help           Show this message

Auth / registry:
  VETLOCK_PYPI_JSON_URL   PyPI JSON API base or Artifactory PyPI proxy
  VETLOCK_PYPI_AUTH       Optional bearer token or user:token credential
`;

async function main(): Promise<void> {
  const { values } = parseArgs({
    options: {
      input: { type: 'string' },
      output: { type: 'string', default: DEFAULT_OUTPUT },
      concurrency: { type: 'string', default: String(DEFAULT_CONCURRENCY) },
      'batch-offset': { type: 'string', default: '0' },
      'batch-size': { type: 'string' },
      help: { type: 'boolean', default: false },
    },
    strict: true,
    allowPositionals: false,
  });

  if (values.help) {
    console.log(HELP_TEXT);
    return;
  }
  if (!values.input) {
    console.error(HELP_TEXT);
    process.exit(1);
  }

  const inputFile = values.input;
  const outputFile = values.output ?? DEFAULT_OUTPUT;
  const concurrency = parseIntegerOption(values.concurrency, '--concurrency', 1);
  const batchOffset = parseIntegerOption(values['batch-offset'], '--batch-offset', 0);
  const batchSize = values['batch-size'] === undefined
    ? undefined
    : parseIntegerOption(values['batch-size'], '--batch-size', 1);

  const allBumps = await parseInputFile(inputFile);
  const selectedBumps = batchSize === undefined
    ? allBumps.slice(batchOffset)
    : allBumps.slice(batchOffset, batchOffset + batchSize);
  const registryUsed = process.env.VETLOCK_PYPI_JSON_URL ?? DEFAULT_REGISTRY;

  console.error(`pypi-fp-study: parsed=${allBumps.length} selected=${selectedBumps.length}`);
  console.error(`pypi-fp-study: registry=${registryUsed}`);
  console.error(`pypi-fp-study: concurrency=${concurrency} offset=${batchOffset} batchSize=${batchSize ?? 'ALL'}`);

  const results = await mapConcurrent(selectedBumps, concurrency, async (bump, index) => {
    const label = `${bump.packageName}@${bump.oldVersion}..${bump.newVersion}`;
    const startedAt = Date.now();
    process.stderr.write(`[${index + 1}/${selectedBumps.length}] ${label}... `);
    try {
      const analyzed = await analyzeSingleBump(bump, registryUsed);
      process.stderr.write(`${analyzed.verdict} (${analyzed.findings.length} findings, ${analyzed.durationMs}ms)\n`);
      return {
        package: bump.packageName,
        packageName: bump.packageName,
        oldVersion: bump.oldVersion,
        newVersion: bump.newVersion,
        verdict: analyzed.verdict,
        findingCount: analyzed.findings.length,
        detectors: unique(analyzed.findings.map((finding) => finding.detector)),
        findings: analyzed.findings.map(summarizeFinding),
        durationMs: analyzed.durationMs,
      } satisfies StudyResultRow;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      const durationMs = Date.now() - startedAt;
      process.stderr.write(`ERROR (${durationMs}ms): ${message.slice(0, 160)}\n`);
      return {
        package: bump.packageName,
        packageName: bump.packageName,
        oldVersion: bump.oldVersion,
        newVersion: bump.newVersion,
        verdict: 'ERROR',
        findingCount: 0,
        detectors: [],
        findings: [],
        durationMs,
        errorMessage: message,
      } satisfies StudyResultRow;
    }
  });

  const summary = summarizeResults(results);
  const report: StudyReport = {
    version: '1',
    ecosystem: 'pypi',
    vetlockVersion: VETLOCK_VERSION,
    ranAt: new Date().toISOString(),
    registryUsed,
    inputFile,
    sourceTotalBumps: allBumps.length,
    batchOffset,
    batchSize: selectedBumps.length,
    totalBumps: selectedBumps.length,
    results,
    summary,
  };

  await fs.mkdir(path.dirname(outputFile), { recursive: true });
  await fs.writeFile(outputFile, JSON.stringify(report, null, 2));

  printSummary(report, outputFile);
}

async function parseInputFile(inputPath: string): Promise<StudyBump[]> {
  const raw = await fs.readFile(inputPath, 'utf8');
  const bumps: StudyBump[] = [];
  for (const line of raw.split(/\r?\n/)) {
    const bump = parseBumpLine(line);
    if (bump) bumps.push(bump);
  }
  return bumps;
}

function parseBumpLine(line: string): StudyBump | null {
  const trimmed = line.trim();
  if (!trimmed || trimmed.startsWith('#')) return null;
  const parts = trimmed.match(/^(.+?)@([^\s]+)\.\.([^\s]+)$/);
  if (!parts) return null;
  return {
    packageName: parts[1]!,
    oldVersion: parts[2]!,
    newVersion: parts[3]!,
  };
}

async function analyzeSingleBump(
  bump: StudyBump,
  registryUsed: string,
): Promise<{ verdict: Severity | 'CLEAN'; findings: Finding[]; durationMs: number }> {
  const reqBefore = `${bump.packageName}==${bump.oldVersion}\n`;
  const reqAfter = `${bump.packageName}==${bump.newVersion}\n`;
  const fetchedPaths = new Set<string>();

  const fetchOverride = async (ref: { name: string; version: string }): Promise<string> => {
    const artifact = await fetchPypiArtifact({
      name: ref.name,
      version: ref.version,
      registry: process.env.VETLOCK_PYPI_JSON_URL ?? registryUsed,
    });
    fetchedPaths.add(artifact.path);
    return artifact.path;
  };

  try {
    const result = await runDiff(reqBefore, reqAfter, {
      runDetectors: (pair) => runAll(pair),
      concurrency: 2,
      timeoutMs: 120_000,
      fetchOverride,
      oldLockfilePath: 'requirements.txt',
      newLockfilePath: 'requirements.txt',
    });
    return {
      verdict: result.verdict,
      findings: result.findings,
      durationMs: result.durationMs,
    };
  } finally {
    await Promise.all([...fetchedPaths].map(async (artifactPath) => {
      await fs.unlink(artifactPath).catch(() => {});
    }));
  }
}

function summarizeResults(results: StudyResultRow[]): StudySummary {
  const summary: StudySummary = {
    BLOCK: 0,
    WARN: 0,
    INFO: 0,
    CLEAN: 0,
    ERROR: 0,
    blockRate: 0,
    warnOrBlockRate: 0,
    detectorHits: {},
  };

  for (const row of results) {
    summary[row.verdict] += 1;
    for (const finding of row.findings) {
      summary.detectorHits[finding.detector] = (summary.detectorHits[finding.detector] ?? 0) + 1;
    }
  }

  const analyzed = results.length || 1;
  summary.blockRate = summary.BLOCK / analyzed;
  summary.warnOrBlockRate = (summary.BLOCK + summary.WARN) / analyzed;
  return summary;
}

function summarizeFinding(finding: Finding): FindingSummary {
  return {
    severity: finding.severity,
    detector: finding.detector,
    message: (finding.message ?? '').slice(0, 240),
  };
}

function printSummary(report: StudyReport, outputFile: string): void {
  console.error(`\npypi-fp-study: wrote ${outputFile}`);
  console.error(`  total=${report.totalBumps}`);
  console.error(
    `  verdicts: BLOCK=${report.summary.BLOCK} WARN=${report.summary.WARN} INFO=${report.summary.INFO} CLEAN=${report.summary.CLEAN} ERROR=${report.summary.ERROR}`,
  );
  console.error(`  blockRate=${(report.summary.blockRate * 100).toFixed(2)}%`);
  console.error(`  warnOrBlockRate=${(report.summary.warnOrBlockRate * 100).toFixed(2)}%`);

  const topDetectors = Object.entries(report.summary.detectorHits)
    .sort((left, right) => right[1] - left[1])
    .slice(0, 10);
  if (topDetectors.length === 0) {
    console.error('  detectorHits: none');
    return;
  }

  console.error('  detectorHits:');
  for (const [detector, hits] of topDetectors) {
    console.error(`    ${detector}: ${hits}`);
  }
}

function parseIntegerOption(raw: string | undefined, optionName: string, minimum: number): number {
  if (raw === undefined) {
    throw new Error(`${optionName} is required`);
  }
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed) || Number.isNaN(parsed) || parsed < minimum) {
    throw new Error(`${optionName} must be an integer >= ${minimum}`);
  }
  return parsed;
}

async function mapConcurrent<T, R>(
  items: T[],
  concurrency: number,
  mapper: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const results = new Array<R>(items.length);
  let nextIndex = 0;

  await Promise.all(
    Array.from({ length: Math.min(concurrency, Math.max(items.length, 1)) }, async () => {
      while (true) {
        const currentIndex = nextIndex;
        nextIndex += 1;
        if (currentIndex >= items.length) return;
        results[currentIndex] = await mapper(items[currentIndex]!, currentIndex);
      }
    }),
  );

  return results;
}

function unique(values: string[]): string[] {
  return [...new Set(values)];
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
