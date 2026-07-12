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
 *   --config-allow-in-diff        — accept a config that changed inside the PR
 *                                   (strict trust-check is disabled; a WARN is
 *                                    still recorded)
 *   --config-baseline-ref <ref>   — git ref to compare .vetlock.json against
 *                                   (default: HEAD).
 *   --no-progress                 — suppress the fetch/analyze progress spinner
 *   --quiet                       — no progress AND no stderr output; only final report on stdout
 *   --show-clean                  — print a CLEAN banner even when there are no changes
 */

import { promises as fs } from 'node:fs';
import * as fsSync from 'node:fs';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { Command } from 'commander';
import ora, { type Ora } from 'ora';
import {
  runDiff,
  VETLOCK_VERSION,
  applyConfig,
  parseConfig,
  DEFAULT_CONFIG,
  decideConfigApplication,
  isForcedFailure,
  ConfigError,
  type ConfigDecision,
  type Finding,
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
  configAllowInDiff?: boolean;
  configBaselineRef?: string;
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
  .option(
    '--config-allow-in-diff',
    'accept a .vetlock.json that changed inside this PR (a WARN is still recorded; default: strict — an in-diff config causes a BLOCK)',
  )
  .option(
    '--config-baseline-ref <ref>',
    'git ref to compare the config against (default: HEAD)',
    'HEAD',
  )
  .option('--no-progress', 'suppress the progress spinner')
  .option('--quiet', 'no progress AND no stderr messages')
  .option('--show-clean', 'print a CLEAN banner even when no findings')
  .action(async (beforePath: string, afterPath: string, opts: CliFlags) => {
    try {
      const [before, after] = await Promise.all([
        fs.readFile(beforePath, 'utf8'),
        fs.readFile(afterPath, 'utf8'),
      ]);
      const decision = loadConfigWithTrustCheck(opts);
      await runAndPrint(before, after, opts, decision, { beforePath, afterPath });
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
    // Two possible fixture locations:
    //   - dist/demo-fixture/           (published npm tarball; ships alongside cli.js)
    //   - <repo-root>/corpus/shai-hulud-2025/  (dev-repo run)
    const here = path.dirname(new URL(import.meta.url).pathname);
    const shippedFixture = path.resolve(here, 'demo-fixture');
    const devFixture = path.resolve(here, '..', '..', '..', 'corpus', 'shai-hulud-2025');
    const fixtureDir = fsSync.existsSync(path.join(shippedFixture, 'lockfile.before.json'))
      ? shippedFixture
      : devFixture;
    try {
      const [before, after] = await Promise.all([
        fs.readFile(path.join(fixtureDir, 'lockfile.before.json'), 'utf8'),
        fs.readFile(path.join(fixtureDir, 'lockfile.after.json'), 'utf8'),
      ]);
      // demo always runs with the default config — no trust check needed.
      const decision: ConfigDecision = {
        config: DEFAULT_CONFIG,
        inDiff: false,
        source: 'default',
        findings: [],
        blocked: false,
      };
      // Point the CLI's fetchOverride at the fixture dir so its relative
      // `file:./...` refs resolve correctly.
      await runAndPrint(
        before,
        after,
        opts,
        decision,
        {
          beforePath: path.join(fixtureDir, 'lockfile.before.json'),
          afterPath: path.join(fixtureDir, 'lockfile.after.json'),
        },
      );
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

/**
 * REDTEAM S2/C1/C2/D1 FIX: load the config with a trust boundary check.
 *
 * The `.vetlock.json` file that lives in the working tree came from the same
 * PR that mutates the lockfile.  An attacker who can add a lockfile entry can
 * also add a config that silences every finding against it.
 *
 * Strategy:
 *  1. Read the current (working-tree) text.
 *  2. Read the baseline text via `git show <ref>:.vetlock.json` — HEAD by
 *     default; overridable with --config-baseline-ref.
 *  3. Hand both to `decideConfigApplication` in the core.  It emits a
 *     synthetic BLOCK-tier finding when the config is in-diff (strict mode)
 *     and returns DEFAULT_CONFIG instead of the attacker's config.
 *  4. `--config-allow-in-diff` switches to WARN mode: the config is applied
 *     but a WARN finding is still recorded on the report.
 *
 * When git is not available (e.g. `vetlock diff` outside a repo), we treat
 * the baseline as absent, which makes any present config "in-diff" — the
 * safe default.  Users on shell-out-less environments can either commit the
 * config to the baseline branch, remove it, or pass `--config-allow-in-diff`.
 */
function loadConfigWithTrustCheck(opts: CliFlags): ConfigDecision {
  const configPath = opts.config ?? '.vetlock.json';
  const strict = opts.configAllowInDiff !== true;
  const baselineRef = opts.configBaselineRef ?? 'HEAD';

  // 1. Read current text.
  let currentText: string | null = null;
  if (fsSync.existsSync(configPath)) {
    try {
      currentText = fsSync.readFileSync(configPath, 'utf8');
    } catch (err) {
      writeErr(opts, `Failed to read ${configPath}: ${err instanceof Error ? err.message : String(err)}`);
      process.exit(3);
    }
  }

  // 2. Read baseline text via git.  When --config is used with a non-default
  //    path we still ask git for the path relative to the repo root — commander
  //    forwards the raw string.  On error (path missing / not a git repo) we
  //    treat baseline as absent, which produces an in-diff verdict.
  const baselineText = readBaselineConfigText(configPath, baselineRef);

  // 3. Parse the current text (if any) BEFORE the trust check.  Parse errors
  //    are surfaced directly — a malformed config is always fatal, regardless
  //    of trust.
  let parsed: VetlockConfig | null = null;
  if (currentText !== null) {
    try {
      parsed = parseConfig(currentText);
    } catch (err) {
      if (err instanceof ConfigError) {
        writeErr(opts, err.message);
      } else {
        writeErr(opts, `Failed to parse ${configPath}: ${err instanceof Error ? err.message : String(err)}`);
      }
      process.exit(3);
    }
  }

  // 4. Decide.
  const decision = decideConfigApplication(
    parsed,
    { currentText, baselineText },
    strict,
  );

  return decision;
}

/**
 * Return the text of `.vetlock.json` as it exists at `baselineRef` (default
 * HEAD) via `git show`.  Returns null when git can't produce it — file
 * absent, path not in that ref, not a git repo, or git binary missing.
 */
function readBaselineConfigText(configPath: string, baselineRef: string): string | null {
  // Normalize to a repo-relative path.  If the user passed an absolute path,
  // we drop it — git can't address absolute paths in `git show`.  The safe
  // default is to treat baseline as absent, i.e. IN-DIFF.
  const relPath = path.isAbsolute(configPath) ? path.relative(process.cwd(), configPath) : configPath;
  if (relPath.startsWith('..')) return null;

  const spec = `${baselineRef}:${relPath}`;
  const res = spawnSync('git', ['show', spec], {
    encoding: 'utf8',
    // A repo the user runs `vetlock diff` inside — no need to override cwd.
    stdio: ['ignore', 'pipe', 'ignore'],
  });
  if (res.error) return null;
  if (typeof res.status !== 'number' || res.status !== 0) return null;
  return typeof res.stdout === 'string' ? res.stdout : null;
}

async function runAndPrint(
  beforeText: string,
  afterText: string,
  opts: CliFlags,
  decision: ConfigDecision,
  files?: { beforePath: string; afterPath: string },
): Promise<void> {
  // Surface any synthetic findings from the trust decision at the top of the
  // report — e.g. `config.in-diff-untrusted` when .vetlock.json is in the
  // diff.  Emit an early stderr warning too, so operators see it even when
  // they render JSON to a file.
  if (decision.inDiff) {
    if (decision.blocked) {
      writeErr(
        opts,
        `vetlock: .vetlock.json is part of this diff — treating as UNTRUSTED (BLOCK). Pass --config-allow-in-diff to override.`,
      );
    } else {
      writeErr(
        opts,
        `vetlock: .vetlock.json changed in this diff — applying anyway (WARN); review the config changes carefully.`,
      );
    }
  }

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
    // Base directory used to resolve any `file:./relative` refs in the AFTER
    // lockfile (corpus fixtures and demo mode use these — see build-all.ts).
    // For stdin diffs we fall back to cwd.
    const afterBaseDir = files?.afterPath
      ? path.dirname(path.resolve(files.afterPath))
      : process.cwd();
    result = await runDiff(beforeText, afterText, {
      runDetectors: (pair) => runAll(pair),
      onProgress,
      fetchOverride: async (ref) => {
        if (ref.resolved && ref.resolved.startsWith('file:')) {
          const raw = ref.resolved.slice('file:'.length);
          // Absolute forms first (canonical + host + non-standard single-slash).
          if (raw.startsWith('///')) return raw.slice(2);
          if (raw.startsWith('//')) return raw.slice(raw.indexOf('/', 2));
          if (raw.startsWith('/')) return raw;
          // Relative form: `file:./x`, `file:../x`, `file:x` — resolve against
          // the after-lockfile's directory.
          return path.resolve(afterBaseDir, raw.replace(/^\.\//, ''));
        }
        const { fetchTarball } = await import('@vetlock/core');
        return await fetchTarball(ref);
      },
    });
  } catch (err) {
    if (spinner) spinner.fail();
    throw err;
  }

  // REDTEAM S2/C1/C2/D1: prepend any synthetic findings from the trust
  // decision.  When decision.blocked === true, the decision.config is already
  // DEFAULT_CONFIG (no allowlist / no ignorePackages / no severityOverride),
  // so applyConfig cannot silence real findings from the report.
  const syntheticFindings: Finding[] = decision.findings;
  result.findings = [
    ...syntheticFindings,
    ...applyConfig(result.findings, decision.config),
  ];
  // Recompute verdict after synthetic findings + config applied.
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
    isForcedFailure(result.findings, decision.config);

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
