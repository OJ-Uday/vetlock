/**
 * scan-runner — the subprocess entry point spawned by `runScanInSandbox`
 * (see ./sandbox.ts, ADR 0008).
 *
 * This file is intentionally tiny and intentionally boring: it is the ONLY
 * code that runs inside the sandboxed subprocess (launched under
 * `--experimental-permission --allow-fs-read=<sandboxdir>
 * --allow-fs-write=<sandboxdir>`), so its job is narrowly:
 *
 *   1. Read the two lockfile paths from argv (both already written inside
 *      the sandbox dir by the parent — see sandbox.ts step 2).
 *   2. Call `runDiff(beforeText, afterText, { runDetectors, timeoutMs })`
 *      from @vetlock/core — the same OSS engine the CLI uses.
 *   3. Write the resulting `ScanResult` as JSON to stdout, then
 *      `process.exit(0)`.
 *
 * On ANY error, write `{ error }` to stdout and `process.exit(1)`. This file
 * NEVER catches an error from `runDiff` and continues — a failed scan must
 * fail loudly, not silently report a partial/empty result. It also NEVER
 * writes to any file (only stdout/stderr) — the Node permission model
 * enforced by the parent (`--allow-fs-write=<sandboxdir>`) would block a
 * write anyway, but we don't rely on that alone; this file structurally
 * doesn't import `fs` for writes.
 *
 * NEVER-EXECUTE (ADR 0005) still applies: `runDiff` performs only static
 * analysis (parse, hash, AST-walk) of the lockfile-referenced packages. This
 * runner does not — and must not — execute anything from either lockfile's
 * content itself. It reads two text files and hands their *text* to the
 * engine; nothing here interprets that text as code.
 */

import { promises as fs } from 'node:fs';
import { runDiff, type EngineOptions } from '@vetlock/core';
import { runAll } from '@vetlock/detectors';

/**
 * The subset of @vetlock/core's `RunResult` we pass through unchanged, named
 * `ScanResult` at the API layer per ADR 0008's spec. Kept as a thin alias
 * (not a re-shape) so a future core-schema change surfaces here at
 * compile-time rather than silently drifting.
 */
export type ScanResult = Awaited<ReturnType<typeof runDiff>>;

/**
 * Per-package analyze timeout handed to the engine. This is a fixed,
 * hardcoded default — NOT threaded in from `runScanInSandbox`'s caller-
 * supplied `limits`. Argv to this process is exactly the two sandboxed
 * lockfile paths (see sandbox.ts step 3); no other caller-controlled value
 * crosses the process boundary via argv. The outer wall-clock budget
 * (`limits.timeoutMs`) is enforced by the PARENT killing this whole
 * subprocess (sandbox.ts step 4) — a concern independent of this
 * per-package figure.
 */
const DEFAULT_PER_PACKAGE_TIMEOUT_MS = 30_000;

async function main(): Promise<void> {
  const [beforePath, afterPath] = process.argv.slice(2);
  if (!beforePath || !afterPath) {
    throw new Error(
      'scan-runner requires exactly two argv paths: <beforeLockfilePath> <afterLockfilePath>',
    );
  }

  // Read-only: both paths are files the parent wrote inside the sandbox dir
  // before spawning us (see sandbox.ts). The permission model
  // (--allow-fs-read=<sandboxdir>) is the enforcement layer; reading here is
  // just the mechanism.
  const [beforeText, afterText] = await Promise.all([
    fs.readFile(beforePath, 'utf8'),
    fs.readFile(afterPath, 'utf8'),
  ]);

  const engineOpts: EngineOptions = {
    runDetectors: (pair) => runAll(pair),
    timeoutMs: DEFAULT_PER_PACKAGE_TIMEOUT_MS,
  };

  // NEVER catch-and-continue here: if runDiff throws, we want the outer
  // try/catch below to write { error } and exit(1) — a scan that partially
  // failed must not be reported as a clean/complete ScanResult.
  const result = await runDiff(beforeText, afterText, engineOpts);

  process.stdout.write(JSON.stringify(result));
  process.exit(0);
}

main().catch((err: unknown) => {
  const message = err instanceof Error ? err.message : String(err);
  process.stdout.write(JSON.stringify({ error: message }));
  process.exit(1);
});
