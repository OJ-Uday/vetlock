/**
 * `vetlock add <pkg>[@version]` — the pre-install gate.
 *
 * THREAT MODEL (why this exists):
 *   The largest attack window in the npm supply chain is the
 *   "postinstall runs before CI sees the diff" gap:
 *
 *     1. developer runs `npm install evil@1.0`
 *     2. npm downloads + extracts + runs preinstall/install/postinstall
 *     3. postinstall exfiltrates ~/.npmrc, ~/.aws/credentials, env vars, etc.
 *     4. postinstall completes; developer is compromised
 *     5. ONLY THEN does a file diff exist for CI to review
 *
 *   Every CI-time scanner (Socket, npm audit, guarddog, Snyk) looks at
 *   packages AFTER they already had the chance to run on the dev machine.
 *   `vetlock add` closes that window by putting the detector suite BEFORE
 *   the package manager ever gets to run lifecycle scripts.
 *
 * FLOW:
 *   1. Resolve target `<name>@<version>` (default `latest` via pacote).
 *   2. Fetch tarball via `@vetlock/core::fetchTarball` — the same
 *      never-execute path used by `vetlock diff` / `vetlock scan`.
 *      Bytes are extracted with `ignore-scripts` semantics enforced by
 *      `safeExtract` — no code from the tarball ever runs (ADR 0005).
 *   3. Run detectors (`runAll`) against a synthetic snapshot pair.
 *      If the package is already installed at some version, we form a
 *      real (old, new) pair; otherwise the "old" side is null and
 *      detectors see it as an `added` change.
 *   4. If any finding has severity BLOCK → refuse, exit code 3.
 *   5. Otherwise shell out to the real package manager. The tarball has
 *      NEVER been executed on this machine by vetlock — the OS-level
 *      `execFile` we invoke is the FIRST time any process associated with
 *      this package runs on the developer's machine.
 *
 * NEVER-EXECUTE INVARIANT (ADR 0005):
 *   Everything up to and including the verdict is static analysis of
 *   extracted bytes. We do NOT import, require, dlopen, exec, or spawn
 *   anything from the analyzed package. The `execFile` at the end runs
 *   the ACTUAL package manager (npm/pnpm/yarn) — that IS the install.
 *   If the developer decides to abort based on the verdict, no code
 *   from the analyzed package has ever executed. See `commands/add.ts`
 *   for the audit trail; test `add.test.ts` asserts the no-exec path
 *   when a BLOCK finding fires.
 */

import { promises as fs } from 'node:fs';
import * as fsSync from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { spawn } from 'node:child_process';
import pc from 'picocolors';
import {
  analyzeTarball,
  fetchTarball,
  computeRiskScore,
  type PackageSnapshot,
  type SnapshotPair,
  type Finding,
  type Change,
  type RunResult,
  parsePackageSpec,
} from '@vetlock/core';
import { runAll } from '@vetlock/detectors';
import { renderTTY } from '../tty.js';
import { renderJSON } from '../json.js';

/** Detected or explicitly-selected package manager. */
export type PackageManagerKind = 'npm' | 'pnpm' | 'yarn';

export interface AddCommandOptions {
  pm?: PackageManagerKind;
  registry?: string;
  forceDanger?: boolean;
  dryRun?: boolean;
  json?: boolean;
  cwd?: string;
  /** For tests: force the PM binary path (overridden by env `VETLOCK_PM_BIN`). */
  pmBinOverride?: string;
  /** For tests: silence the scary banner in output. */
  quiet?: boolean;
  /** For tests: skip reading ~/.vetlock/allowlist. */
  ignoreAllowlist?: boolean;
  /**
   * Test hook: override the fetch step. Same shape as `@vetlock/core`
   * `PackageRef` — return an on-disk .tgz path. When omitted, we call
   * the real pacote-backed `fetchTarball`.
   *
   * Used by add.test.ts to point at corpus fixture tarballs without
   * hitting the network. Never used in production — the CLI code path
   * never wires this from the outside.
   */
  fetchOverride?: (ref: { name: string; version: string; registry?: string }) => Promise<string>;
}

export interface AddCommandResult {
  /** Terminal exit code: 0 install proceeded (clean or forced), 3 refused, 4 usage error. */
  exitCode: number;
  /** Package name resolved. */
  packageName: string;
  /** Version resolved (may be 'latest' if pacote failed to pin — best-effort). */
  version: string;
  /** Which package manager the shellout targeted, if any. */
  pm: PackageManagerKind | null;
  /** Whether we actually invoked the PM. */
  installed: boolean;
  /** Verdict of the pre-install analysis. */
  verdict: 'CLEAN' | 'INFO' | 'WARN' | 'BLOCK';
  /** Findings surfaced (may be empty). */
  findings: Finding[];
  /** Wall time of the fetch+analyze+detect step. */
  gateDurationMs: number;
  /** Was the package in the developer's allowlist? */
  allowlisted: boolean;
}

/**
 * Parse `<pkgName>` or `<pkgName>@<version>` — supports scoped names
 * (`@scope/name`, `@scope/name@1.2.3`).
 *
 * Returns null on invalid input so the caller can print a usage message.
 */
export { parsePackageSpec } from '@vetlock/core';

/**
 * Detect the developer's package manager from lockfiles in `cwd`.
 * Order matches how tools usually pick: pnpm > yarn > npm.
 *
 * Returns null when nothing is present — caller can fall back to npm.
 */
export function detectPackageManager(cwd: string): PackageManagerKind | null {
  if (fsSync.existsSync(path.join(cwd, 'pnpm-lock.yaml'))) return 'pnpm';
  if (fsSync.existsSync(path.join(cwd, 'yarn.lock'))) return 'yarn';
  if (fsSync.existsSync(path.join(cwd, 'package-lock.json'))) return 'npm';
  // npm-shrinkwrap.json is npm too
  if (fsSync.existsSync(path.join(cwd, 'npm-shrinkwrap.json'))) return 'npm';
  return null;
}

/**
 * Look up the currently-installed version of `pkgName` in `cwd` by reading
 * `node_modules/<pkgName>/package.json`. Returns null when not installed.
 *
 * We deliberately DO NOT parse the lockfile: for the pre-install gate the
 * question "what is currently installed on disk?" is what matters. If a
 * lockfile says A@1 but node_modules has A@2, the gate should compare
 * against A@2 (the code actually running in this workspace).
 */
export async function readInstalledVersion(
  cwd: string,
  pkgName: string,
): Promise<string | null> {
  const manifestPath = path.join(cwd, 'node_modules', pkgName, 'package.json');
  try {
    const raw = await fs.readFile(manifestPath, 'utf8');
    const parsed = JSON.parse(raw) as { version?: string };
    return typeof parsed.version === 'string' ? parsed.version : null;
  } catch {
    return null;
  }
}

/** Location of the vetlock user-level state (allowlist, guard shims). */
export function vetlockUserDir(): string {
  return process.env.VETLOCK_HOME ?? path.join(os.homedir(), '.vetlock');
}

/** ~/.vetlock/allowlist — one JSON object per file. */
export interface AllowlistEntry {
  package: string;
  reason: string;
  addedAt: string;
}

export async function readAllowlist(): Promise<AllowlistEntry[]> {
  const p = path.join(vetlockUserDir(), 'allowlist.json');
  try {
    const raw = await fs.readFile(p, 'utf8');
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(
      (e): e is AllowlistEntry =>
        typeof e === 'object' && e !== null &&
        typeof (e as AllowlistEntry).package === 'string' &&
        typeof (e as AllowlistEntry).reason === 'string' &&
        typeof (e as AllowlistEntry).addedAt === 'string',
    );
  } catch {
    return [];
  }
}

/**
 * Main entry point invoked by `cli.ts`. Returns an `AddCommandResult` and
 * (except in tests) calls `process.exit` on the caller's behalf.
 */
export async function runAddCommand(
  spec: string,
  opts: AddCommandOptions,
): Promise<AddCommandResult> {
  const cwd = opts.cwd ?? process.cwd();
  const parsed = parsePackageSpec(spec);
  if (!parsed) {
    printErr(opts, `vetlock add: invalid package spec '${spec}'.`);
    printErr(opts, `Usage: vetlock add <package>[@version] [--pm npm|pnpm|yarn] [--registry <url>]`);
    return {
      exitCode: 4, packageName: '', version: '', pm: null, installed: false,
      verdict: 'CLEAN', findings: [], gateDurationMs: 0, allowlisted: false,
    };
  }
  const { name, version } = parsed;

  // Allowlist: developer explicitly opted a package out of the gate.
  const allowlist = opts.ignoreAllowlist ? [] : await readAllowlist();
  const allowlisted = allowlist.some((e) => e.package === name);

  // Pick pm: explicit flag > lockfile-detected > default npm.
  const pm: PackageManagerKind = opts.pm ?? detectPackageManager(cwd) ?? 'npm';

  const t0 = Date.now();

  if (allowlisted) {
    // Skip the fetch entirely — dev has explicitly trusted this package.
    // We still surface the fact prominently.
    printOut(opts, `${pc.yellow('[allowlisted]')} ${name} — pre-install gate skipped by ~/.vetlock/allowlist.json`);
    if (opts.dryRun) {
      return {
        exitCode: 0, packageName: name, version, pm, installed: false,
        verdict: 'CLEAN', findings: [], gateDurationMs: Date.now() - t0, allowlisted: true,
      };
    }
    const shellCode = await shellOutToPm(pm, name, version, opts);
    return {
      exitCode: shellCode, packageName: name, version, pm, installed: shellCode === 0,
      verdict: 'CLEAN', findings: [], gateDurationMs: Date.now() - t0, allowlisted: true,
    };
  }

  // Static gate — fetch, analyze, run detectors. NO code from the package
  // executes on this machine here: fetchTarball is bytes-only (pacote.tarball),
  // analyzeTarball extracts with the never-execute safeExtract, and runAll is
  // a pure function over PackageSnapshot pairs. See ADR 0005.
  printOut(opts, pc.dim(`vetlock: analyzing ${name}@${version} before install…`));

  let tarballPath: string;
  let ownsTarball = false;
  let newSnap: PackageSnapshot;
  try {
    if (opts.fetchOverride) {
      // Test-hook: caller owns the file; do NOT unlink.
      tarballPath = await opts.fetchOverride({ name, version, registry: opts.registry });
    } else {
      tarballPath = await fetchTarball({
        name,
        version,
        registry: opts.registry,
      });
      ownsTarball = true;
    }
  } catch (err) {
    // Fetch failure is treated as fail-closed — do NOT proceed to install.
    // A missing tarball could still mean an unknown network route; the safer
    // action is to refuse.
    printErr(opts, `vetlock add: failed to fetch ${name}@${version}: ${
      err instanceof Error ? err.message : String(err)
    }`);
    return {
      exitCode: 3, packageName: name, version, pm, installed: false,
      verdict: 'BLOCK', findings: [], gateDurationMs: Date.now() - t0, allowlisted: false,
    };
  }

  try {
    newSnap = await analyzeTarball(tarballPath);
  } catch (err) {
    printErr(opts, `vetlock add: failed to analyze ${name}@${version}: ${
      err instanceof Error ? err.message : String(err)
    }`);
    if (ownsTarball) await fs.unlink(tarballPath).catch(() => { /* best-effort cleanup */ });
    return {
      exitCode: 3, packageName: name, version, pm, installed: false,
      verdict: 'BLOCK', findings: [], gateDurationMs: Date.now() - t0, allowlisted: false,
    };
  }
  // Best-effort cleanup — the tarball path is a scratch file under ~/.cache/vetlock.
  if (ownsTarball) await fs.unlink(tarballPath).catch(() => { /* best-effort cleanup */ });

  // Try to build a real (old, new) snapshot pair if the package is already
  // installed in this workspace. This gives change-oriented detectors like
  // meta.maintainer-change something to compare against, and yields a much
  // stronger signal than treating everything as `added` from an empty tree.
  let oldSnap: PackageSnapshot | null = null;
  const installedVersion = await readInstalledVersion(cwd, name);
  if (installedVersion && installedVersion !== newSnap.version) {
    try {
      const oldTarball = opts.fetchOverride
        ? await opts.fetchOverride({ name, version: installedVersion, registry: opts.registry })
        : await fetchTarball({
          name,
          version: installedVersion,
          registry: opts.registry,
        });
      try {
        oldSnap = await analyzeTarball(oldTarball);
      } catch {
        // Old-side analysis failure is non-fatal; treat as if not installed.
        oldSnap = null;
      }
      if (!opts.fetchOverride) await fs.unlink(oldTarball).catch(() => { /* best-effort cleanup */ });
    } catch {
      // Old-side fetch failure is non-fatal; treat as if not installed.
      oldSnap = null;
    }
  }

  const pair: SnapshotPair = { old: oldSnap, new: newSnap };
  const findings = runAll(pair);
  const verdict = computeVerdict(findings);
  const gateDurationMs = Date.now() - t0;

  // Render the report BEFORE any install decision so the developer sees
  // exactly what was checked. Match the diff/scan output shape via a
  // synthetic RunResult so `renderTTY` / `renderJSON` work unchanged.
  const change: Change = {
    kind: oldSnap ? 'upgraded' : 'added',
    name,
    oldVersion: oldSnap?.version ?? null,
    newVersion: newSnap.version,
    oldIntegrity: null,
    newIntegrity: null,
    nodeKeyOld: null,
    nodeKeyNew: null,
  };
  const syntheticResult: RunResult = {
    verdict,
    findings,
    rollupByDirect: {},
    changes: [change],
    errors: [],
    durationMs: gateDurationMs,
    riskScore: computeRiskScore(findings),
  };
  if (opts.json) {
    printOut(opts, renderJSON(syntheticResult));
  } else {
    printOut(opts, renderTTY(syntheticResult, { showClean: true }));
  }

  const shouldBlock = verdict === 'BLOCK';
  if (shouldBlock && !opts.forceDanger) {
    printErr(opts, pc.red(pc.bold(
      `\nvetlock add: REFUSING to install ${name}@${newSnap.version}. `
      + `${findings.filter((f) => f.severity === 'BLOCK').length} BLOCK-tier finding(s) fired.`,
    )));
    printErr(opts, `Use ${pc.bold('--force-danger')} to override, or `
      + `${pc.bold(`vetlock guard --allowlist add ${name} --reason "…"`)} to permanently permit.`);
    return {
      exitCode: 3, packageName: name, version: newSnap.version, pm, installed: false,
      verdict, findings, gateDurationMs, allowlisted: false,
    };
  }
  if (shouldBlock && opts.forceDanger) {
    printErr(opts, '');
    printErr(opts, pc.red(pc.bold('╔════════════════════════════════════════════════════════════════════╗')));
    printErr(opts, pc.red(pc.bold('║  --force-danger: installing a package with BLOCK-tier findings.   ║')));
    printErr(opts, pc.red(pc.bold('║  This bypasses vetlock. You are on your own.                       ║')));
    printErr(opts, pc.red(pc.bold('╚════════════════════════════════════════════════════════════════════╝')));
    printErr(opts, '');
  }
  if (opts.dryRun) {
    printOut(opts, pc.dim(`vetlock add: --dry-run — not invoking ${pm}.`));
    return {
      exitCode: 0, packageName: name, version: newSnap.version, pm, installed: false,
      verdict, findings, gateDurationMs, allowlisted: false,
    };
  }
  const shellCode = await shellOutToPm(pm, name, version, opts);
  return {
    exitCode: shellCode, packageName: name, version: newSnap.version, pm,
    installed: shellCode === 0, verdict, findings, gateDurationMs, allowlisted: false,
  };
}

function computeVerdict(findings: Finding[]): 'BLOCK' | 'WARN' | 'INFO' | 'CLEAN' {
  let v: 'BLOCK' | 'WARN' | 'INFO' | 'CLEAN' = 'CLEAN';
  for (const f of findings) {
    if (f.severity === 'BLOCK') return 'BLOCK';
    if (f.severity === 'WARN' && v !== 'WARN') v = 'WARN';
    else if (f.severity === 'INFO' && v === 'CLEAN') v = 'INFO';
  }
  return v;
}

/**
 * Invoke the real package manager as a subprocess.
 *
 * Test escape hatch: env `VETLOCK_PM_BIN` overrides the resolved binary path.
 * We spawn detached=false and inherit stdio so the developer sees the
 * package-manager's own output. Return the pm's exit code (bubbled).
 *
 * IMPORTANT: this is the ONLY subprocess we spawn on behalf of the analyzed
 * package. It runs the ACTUAL npm/pnpm/yarn binary — not code from the
 * package — so this doesn't violate NEVER-EXECUTE. From this point on, the
 * package IS installing (npm runs its lifecycle scripts as usual). vetlock's
 * job was to gate BEFORE this call.
 */
async function shellOutToPm(
  pm: PackageManagerKind,
  name: string,
  version: string,
  opts: AddCommandOptions,
): Promise<number> {
  const bin = opts.pmBinOverride ?? process.env.VETLOCK_PM_BIN ?? pm;
  const args = buildPmArgs(pm, name, version, opts.registry);
  return new Promise<number>((resolve) => {
    const child = spawn(bin, args, {
      stdio: 'inherit',
      env: {
        ...process.env,
        // Prevent recursion when the guard shim is on PATH: guard sets this
        // env so its own shim doesn't call itself if the developer
        // accidentally uses the shim.
        VETLOCK_GUARD_BYPASS: '1',
      },
    });
    child.on('exit', (code) => resolve(typeof code === 'number' ? code : 1));
    child.on('error', (err) => {
      printErr(opts, `vetlock add: failed to invoke ${bin}: ${err.message}`);
      resolve(1);
    });
  });
}

/**
 * Build the CLI args each package manager expects for "install this
 * one package with this version". These are the smallest-surface calls
 * that don't touch other deps:
 *   npm:  npm install <name>@<version>
 *   pnpm: pnpm add <name>@<version>
 *   yarn: yarn add <name>@<version>  (works for both classic v1 and berry)
 *
 * For 'latest' we pass just the name — every PM defaults to latest.
 * When a registry override is present we pass --registry (npm, pnpm) or
 * --registry (yarn v1 also supports this).
 */
export function buildPmArgs(
  pm: PackageManagerKind,
  name: string,
  version: string,
  registry?: string,
): string[] {
  const spec = version === 'latest' ? name : `${name}@${version}`;
  const registryArgs = registry ? ['--registry', registry] : [];
  if (pm === 'pnpm') return ['add', spec, ...registryArgs];
  if (pm === 'yarn') return ['add', spec, ...registryArgs];
  return ['install', spec, ...registryArgs];
}

function printOut(opts: AddCommandOptions, msg: string): void {
  if (opts.quiet) return;
  process.stdout.write(msg + '\n');
}

function printErr(opts: AddCommandOptions, msg: string): void {
  if (opts.quiet) return;
  process.stderr.write(msg + '\n');
}
