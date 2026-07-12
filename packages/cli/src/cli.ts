#!/usr/bin/env node
/**
 * vetlock — CLI entry.
 *
 * Sub-commands:
 *   diff <before> <after>        — diff two lockfiles, report behavioral changes
 *   scan <lockfile>              — baseline scan of a full tree (weaker; self-labels)
 *   version                       — print version
 *
 * Flags:
 *   --json | --sarif | --md      — output format (default: pretty TTY)
 *   --fail-on=<detector,detector,…> — exit 2 on ANY of these detector ids
 *   --demo                        — use bundled fixture lockfiles
 *   --show-clean                  — print CLEAN banner even when there are no changes
 */

import { promises as fs } from 'node:fs';
import * as path from 'node:path';
import { Command } from 'commander';
import { runDiff, VETLOCK_VERSION } from '@vetlock/core';
import { runAll } from '@vetlock/detectors';
import { renderTTY } from './tty.js';
import { renderJSON } from './json.js';
import { renderSARIF } from './sarif.js';
import { renderMarkdown } from './md.js';

const program = new Command();

program
  .name('vetlock')
  .description('Behavioral diff for npm dependency updates. What does this update DO now that it didn\'t before?')
  .version(VETLOCK_VERSION);

program
  .command('diff <before> <after>')
  .description('Diff two package-lock.json files and report behavioral changes.')
  .option('--json', 'emit JSON')
  .option('--sarif', 'emit SARIF 2.1.0')
  .option('--md', 'emit GitHub-flavored Markdown')
  .option('--fail-on <detectors>', 'comma-separated detector ids that force exit 2')
  .option('--show-clean', 'print a CLEAN banner even when there are no changes')
  .action(async (beforePath: string, afterPath: string, opts) => {
    try {
      const [before, after] = await Promise.all([
        fs.readFile(beforePath, 'utf8'),
        fs.readFile(afterPath, 'utf8'),
      ]);
      await runAndPrint(before, after, opts);
    } catch (err) {
      process.stderr.write(`vetlock: ${err instanceof Error ? err.message : String(err)}\n`);
      process.exit(3);
    }
  });

program
  .command('demo')
  .description('Run vetlock against bundled fixture lockfiles (no network, no config).')
  .option('--json', 'emit JSON')
  .option('--sarif', 'emit SARIF')
  .option('--md', 'emit Markdown')
  .action(async (opts) => {
    // Bundled fixtures live under corpus/shai-hulud-2025/. They are DEFANGED per
    // the corpus protocol; no live exfil addresses.
    const here = path.dirname(new URL(import.meta.url).pathname);
    const fixtureDir = path.resolve(here, '..', '..', '..', 'corpus', 'shai-hulud-2025');
    try {
      const [before, after] = await Promise.all([
        fs.readFile(path.join(fixtureDir, 'lockfile.before.json'), 'utf8'),
        fs.readFile(path.join(fixtureDir, 'lockfile.after.json'), 'utf8'),
      ]);
      await runAndPrint(before, after, opts);
    } catch (err) {
      process.stderr.write(`vetlock demo: ${err instanceof Error ? err.message : String(err)}\n`);
      process.stderr.write(`(demo fixtures at ${fixtureDir})\n`);
      process.exit(3);
    }
  });

program
  .command('scan <lockfile>')
  .description('Baseline scan of one lockfile (no diff frame — weaker; self-labels).')
  .option('--json', 'emit JSON')
  .action(async (lockfilePath: string) => {
    process.stderr.write('vetlock scan: baseline mode is a P8 feature — not yet implemented in this release.\n');
    process.stderr.write(`(reading ${lockfilePath})\n`);
    process.exit(2);
  });

async function runAndPrint(
  beforeText: string,
  afterText: string,
  opts: { json?: boolean; sarif?: boolean; md?: boolean; failOn?: string; showClean?: boolean },
): Promise<void> {
  const result = await runDiff(beforeText, afterText, {
    runDetectors: (pair) => runAll(pair),
    fetchOverride: async (ref) => {
      // If the lockfile pins to file://, use that verbatim (corpus/demo mode).
      if (ref.resolved && ref.resolved.startsWith('file://')) {
        const p = new URL(ref.resolved).pathname;
        return p;
      }
      // Otherwise fall through to pacote by returning null-like — but we can't
      // return null here (typed Promise<string>). Fall back to a runtime import
      // of the default fetcher.
      const { fetchTarball } = await import('@vetlock/core');
      return await fetchTarball(ref);
    },
  });

  if (opts.json) {
    process.stdout.write(renderJSON(result) + '\n');
  } else if (opts.sarif) {
    process.stdout.write(renderSARIF(result) + '\n');
  } else if (opts.md) {
    process.stdout.write(renderMarkdown(result) + '\n');
  } else {
    process.stdout.write(renderTTY(result, { showClean: opts.showClean }) + '\n');
  }

  const failOn = (opts.failOn ?? '').split(',').map((s) => s.trim()).filter(Boolean);
  const shouldForce = failOn.length > 0 && result.findings.some((f) => failOn.includes(f.detector));

  // Exit codes: 0 clean · 1 ≥ WARN · 2 ≥ BLOCK (or forced by --fail-on)
  let code = 0;
  if (result.verdict === 'BLOCK') code = 2;
  else if (result.verdict === 'WARN') code = 1;
  if (shouldForce) code = Math.max(code, 2);

  process.exit(code);
}

program.parseAsync(process.argv);
