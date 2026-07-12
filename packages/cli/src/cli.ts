#!/usr/bin/env node
/**
 * vetlock — CLI entry.
 *
 * Sub-commands:
 *   diff <before> <after>        — diff two lockfiles, report behavioral changes
 *   scan <lockfile>              — baseline scan of a full tree (not yet implemented)
 *   demo                          — run against bundled Shai-Hulud fixture
 *   version                       — print version
 *
 * Flags:
 *   --json | --sarif | --md      — output format (default: pretty TTY)
 *   --fail-on=<detector,detector,…> — exit 2 on ANY of these detector ids
 *   --config <path>              — path to .vetlock.json (defaults to ./.vetlock.json)
 *   --no-progress                 — suppress the fetch/analyze progress spinner
 *   --quiet                       — no progress AND no stderr output; only final report on stdout
 *   --show-clean                  — print a CLEAN banner even when there are no changes
 */

import { promises as fs } from 'node:fs';
import * as fsSync from 'node:fs';
import * as path from 'node:path';
import { Command } from 'commander';
import ora, { type Ora } from 'ora';
import {
  runDiff,
  VETLOCK_VERSION,
  applyConfig,
  parseConfig,
  DEFAULT_CONFIG,
  isForcedFailure,
  ConfigError,
  type VetlockConfig,
  type ProgressEvent,
  parseLockfileText,
} from '@vetlock/core';
import { runAll } from '@vetlock/detectors';
import { renderTTY } from './tty.js';
import { renderJSON } from './json.js';
import { renderSARIF } from './sarif.js';
import { renderMarkdown } from './md.js';

interface CliFlags {
  json?: boolean;
  sarif?: boolean;
  md?: boolean;
  failOn?: string;
  config?: string;
  progress?: boolean;
  quiet?: boolean;
  showClean?: boolean;
}

const program = new Command();

program
  .name('vetlock')
  .description('Behavioral diff for npm dependency updates.')
  .version(VETLOCK_VERSION);

program
  .command('diff <before> <after>')
  .description('Diff two lockfiles (npm / pnpm / yarn) and report behavioral changes.')
  .option('--json', 'emit JSON')
  .option('--sarif', 'emit SARIF 2.1.0')
  .option('--md', 'emit GitHub-flavored Markdown')
  .option('--fail-on <detectors>', 'comma-separated detector ids that force exit 2')
  .option('--config <path>', 'path to .vetlock.json (defaults to ./.vetlock.json)')
  .option('--no-progress', 'suppress the progress spinner')
  .option('--quiet', 'no progress AND no stderr messages')
  .option('--show-clean', 'print a CLEAN banner even when no findings')
  .action(async (beforePath: string, afterPath: string, opts: CliFlags) => {
    try {
      const [before, after] = await Promise.all([
        fs.readFile(beforePath, 'utf8'),
        fs.readFile(afterPath, 'utf8'),
      ]);
      const config = loadConfig(opts);
      await runAndPrint(before, after, opts, config, { beforePath, afterPath });
    } catch (err) {
      writeErr(opts, `vetlock: ${err instanceof Error ? err.message : String(err)}`);
      process.exit(3);
    }
  });

program
  .command('demo')
  .description('Run vetlock against bundled Shai-Hulud fixture (no network, no config).')
  .option('--json', 'emit JSON')
  .option('--sarif', 'emit SARIF')
  .option('--md', 'emit Markdown')
  .option('--no-progress', 'suppress the progress spinner')
  .action(async (opts: CliFlags) => {
    const here = path.dirname(new URL(import.meta.url).pathname);
    const fixtureDir = path.resolve(here, '..', '..', '..', 'corpus', 'shai-hulud-2025');
    try {
      const [before, after] = await Promise.all([
        fs.readFile(path.join(fixtureDir, 'lockfile.before.json'), 'utf8'),
        fs.readFile(path.join(fixtureDir, 'lockfile.after.json'), 'utf8'),
      ]);
      await runAndPrint(before, after, opts, DEFAULT_CONFIG);
    } catch (err) {
      writeErr(opts, `vetlock demo: ${err instanceof Error ? err.message : String(err)}`);
      writeErr(opts, `(demo fixtures at ${fixtureDir})`);
      process.exit(3);
    }
  });

program
  .command('scan <lockfile>')
  .description('Baseline scan of one lockfile (no diff frame — roadmap).')
  .option('--json', 'emit JSON')
  .action(async (lockfilePath: string) => {
    process.stderr.write('vetlock scan: baseline mode is roadmap — not yet implemented.\n');
    process.stderr.write(`(reading ${lockfilePath})\n`);
    process.exit(2);
  });

function loadConfig(opts: CliFlags): VetlockConfig {
  const configPath = opts.config ?? '.vetlock.json';
  if (!fsSync.existsSync(configPath)) {
    // No config is the default. Return the schema-provided defaults.
    return DEFAULT_CONFIG;
  }
  try {
    const text = fsSync.readFileSync(configPath, 'utf8');
    return parseConfig(text);
  } catch (err) {
    if (err instanceof ConfigError) {
      writeErr(opts, err.message);
    } else {
      writeErr(opts, `Failed to read ${configPath}: ${err instanceof Error ? err.message : String(err)}`);
    }
    process.exit(3);
  }
}

async function runAndPrint(
  beforeText: string,
  afterText: string,
  opts: CliFlags,
  config: VetlockConfig,
  files?: { beforePath: string; afterPath: string },
): Promise<void> {
  const useSpinner = !opts.quiet && (opts.progress !== false) && process.stderr.isTTY;
  let spinner: Ora | null = null;
  const stats = { total: 0, done: 0, errors: 0, cacheHits: 0 };

  if (useSpinner) {
    spinner = ora({ stream: process.stderr, text: 'parsing lockfiles…' }).start();
  }

  const onProgress = (ev: ProgressEvent) => {
    if (ev.kind === 'start') {
      stats.total = ev.total;
      if (spinner) spinner.text = `analyzing ${ev.total} changed package${ev.total === 1 ? '' : 's'}…`;
    } else if (ev.kind === 'analyze') {
      stats.done++;
      if (spinner) spinner.text = `[${stats.done}/${stats.total}] ${ev.packageName}@${ev.version}`;
    } else if (ev.kind === 'cache-hit') {
      stats.cacheHits++;
      stats.done++;
      if (spinner) spinner.text = `[${stats.done}/${stats.total}] ${ev.packageName}@${ev.version} (cache hit)`;
    } else if (ev.kind === 'error') {
      stats.errors++;
    } else if (ev.kind === 'done') {
      if (spinner) {
        const parts: string[] = [`${ev.total} package${ev.total === 1 ? '' : 's'} analyzed`];
        if (stats.cacheHits > 0) parts.push(`${stats.cacheHits} cached`);
        if (stats.errors > 0) parts.push(`${stats.errors} errored`);
        spinner.succeed(parts.join(', '));
      }
    }
  };

  // Detect lockfile kind — support npm/pnpm/yarn
  // We use parseLockfileText separately to fail fast with a good error,
  // then hand the text to runDiff (which does its own npm parse; TODO in a
  // later pass: refactor runDiff to accept pre-parsed graphs).
  // For now this is a preflight check — runDiff still assumes npm.
  try {
    parseLockfileText(beforeText, files?.beforePath);
    parseLockfileText(afterText, files?.afterPath);
  } catch (err) {
    if (spinner) spinner.fail();
    throw err;
  }

  let result;
  try {
    result = await runDiff(beforeText, afterText, {
      runDetectors: (pair) => runAll(pair),
      onProgress,
      fetchOverride: async (ref) => {
        if (ref.resolved && ref.resolved.startsWith('file://')) {
          return new URL(ref.resolved).pathname;
        }
        const { fetchTarball } = await import('@vetlock/core');
        return await fetchTarball(ref);
      },
    });
  } catch (err) {
    if (spinner) spinner.fail();
    throw err;
  }

  // Apply user config — allowlists, severity overrides, ignored packages, trust
  result.findings = applyConfig(result.findings, config);
  // Recompute verdict after config applied.
  result.verdict = computeVerdict(result.findings);

  if (opts.json) {
    process.stdout.write(renderJSON(result) + '\n');
  } else if (opts.sarif) {
    process.stdout.write(renderSARIF(result) + '\n');
  } else if (opts.md) {
    process.stdout.write(renderMarkdown(result) + '\n');
  } else {
    process.stdout.write(renderTTY(result, { showClean: opts.showClean }) + '\n');
  }

  const failOnCli = (opts.failOn ?? '').split(',').map((s) => s.trim()).filter(Boolean);
  const shouldForce =
    (failOnCli.length > 0 && result.findings.some((f) => failOnCli.includes(f.detector))) ||
    isForcedFailure(result.findings, config);

  // Exit codes: 0 clean · 1 ≥ WARN · 2 ≥ BLOCK (or forced by --fail-on)
  let code = 0;
  if (result.verdict === 'BLOCK') code = 2;
  else if (result.verdict === 'WARN') code = 1;
  if (shouldForce) code = Math.max(code, 2);

  process.exit(code);
}

function computeVerdict(findings: import('@vetlock/core').Finding[]): 'BLOCK' | 'WARN' | 'INFO' | 'CLEAN' {
  let v: 'BLOCK' | 'WARN' | 'INFO' | 'CLEAN' = 'CLEAN';
  for (const f of findings) {
    if (f.severity === 'BLOCK') return 'BLOCK';
    if (f.severity === 'WARN' && v !== 'WARN') v = 'WARN';
    else if (f.severity === 'INFO' && v === 'CLEAN') v = 'INFO';
  }
  return v;
}

function writeErr(opts: CliFlags, msg: string) {
  if (opts.quiet) return;
  process.stderr.write(msg + '\n');
}

program.parseAsync(process.argv);
