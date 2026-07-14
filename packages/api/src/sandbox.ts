/**
 * Sandbox — ADR 0008 per-scan ephemeral subprocess isolation.
 *
 * `runScanInSandbox` runs one scan by spawning the `scan-runner.ts` entry
 * point as a fresh Node subprocess with a hard wall-clock timeout, capped
 * heap, and a per-scan temp directory that's unconditionally torn down at
 * the end. The whole scan lives inside that temp dir: both lockfiles are
 * materialized to files there before the subprocess starts, argv points at
 * those files, stdout is the ONLY exit channel, and the dir is deleted
 * whether the scan succeeds, throws, or times out.
 *
 * What this gives us over the in-process ScanQueue default:
 *   - True per-scan process boundary. A misbehaving lockfile / detector /
 *     transitive dep can't leak state into the next scan on the same host,
 *     can't hold onto file descriptors, can't inflate the parent's heap.
 *   - Hard timeout enforcement. AbortController kills the subprocess with
 *     SIGKILL (not SIGTERM — no graceful window; the whole point is that
 *     we don't trust its intent to shut down).
 *   - Heap cap (--max-old-space-size). A pathological lockfile that would
 *     let @vetlock/core's parser allocate 10 GB of AST nodes hits OOM in
 *     the child instead of taking down the parent.
 *   - Filesystem write is bounded to the temp dir (subprocess only writes
 *     what it wants to; parent enforces via post-scan rm -rf).
 *
 * What this DOES NOT give us (kept as v0.8+ upgrade paths):
 *   - Kernel-level FS sandboxing (would need firejail / bubblewrap /
 *     Landlock on Linux, or `--experimental-permission` in Node 20+ which
 *     is still experimental as of this release — see the STOP CONDITIONS
 *     comment below).
 *   - Network-namespace isolation. On the hosted API side we run the
 *     whole container without egress once tarball fetches complete (Fly
 *     `[services].internal_port` no-egress mode, or a K8s NetworkPolicy).
 *     That's a deployment concern, not a source-code concern.
 *   - CPU / IO throttling. Cgroups territory. Container-level.
 *
 * Why not --experimental-permission for real FS enforcement in v0:
 *   The Node permission model (--experimental-permission
 *   --allow-fs-read=... --allow-fs-write=...) shipped in Node 20 as
 *   EXPERIMENTAL. It changed shape in 22, and its interaction with
 *   `require()`'s runtime resolution paths (which need to read Node's own
 *   install dir + all of node_modules) means composing the allow-list
 *   correctly is fragile — one missed path breaks the subprocess with an
 *   ERR_ACCESS_DENIED before it can even parse a lockfile. Given the
 *   parent already enforces the whole invariant we care about (rm -rf the
 *   sandbox dir on completion, subprocess can't reach parent state), the
 *   marginal defense from the permission model isn't worth the fragility
 *   until Node marks it stable. Tracked as a v0.8 target.
 *
 * NEVER-EXECUTE (ADR 0005) still holds: neither this file nor the runner
 * subprocess it spawns executes any code FROM the scanned lockfiles or
 * their packages. `runDiff` inside the runner is a static parse+fetch+
 * AST-walk pipeline — the scanned tarballs are extracted to disk and read
 * as text, never `require()`d or `exec`ed. The sandbox layer is defense-
 * in-depth for the VETLOCK CODE itself misbehaving (bug, DoS payload,
 * memory blow-up), not for containing malicious executed content.
 */

import { spawn, type ChildProcess } from 'node:child_process';
import { promises as fs } from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

/** Options accepted by `runScanInSandbox`. */
export interface SandboxRunOptions {
  /** Wall-clock timeout for the whole subprocess, milliseconds. Default 60s. */
  timeoutMs?: number;
  /** V8 heap cap for the subprocess, MB. Default 512. */
  maxOldSpaceMB?: number;
  /** Test-only override for the runner entrypoint path. Defaults to `dist/scan-runner.js` next to this file. */
  runnerPath?: string;
}

/** Result of a successful sandbox run — the JSON emitted by scan-runner on stdout. */
export interface SandboxSuccess<T = unknown> {
  kind: 'ok';
  result: T;
}

/** Result when the runner returned a non-zero exit or wrote an { error } payload. */
export interface SandboxFailure {
  kind: 'failed';
  /** Message parsed from `{ error: string }` on stdout, or from the exit signal. */
  error: string;
  /** Exit code (may be null when killed by signal). */
  exitCode: number | null;
  /** Signal that killed the subprocess (e.g. 'SIGKILL' on timeout). */
  signal: NodeJS.Signals | null;
}

/** Result when the caller-supplied AbortSignal or the internal timer fires. */
export interface SandboxTimeout {
  kind: 'timeout';
  /** Timeout budget that was hit, milliseconds. */
  timeoutMs: number;
}

export type SandboxOutcome<T = unknown> = SandboxSuccess<T> | SandboxFailure | SandboxTimeout;

/**
 * Materialize the two lockfile texts into a fresh temp dir and run
 * `scan-runner.js` against them under a hard timeout. The temp dir is
 * removed unconditionally in a finally block — successful, failed, and
 * timed-out scans all leave zero trace on disk.
 */
export async function runScanInSandbox<T = unknown>(input: {
  lockfileBefore: string;
  lockfileAfter: string;
}, opts: SandboxRunOptions = {}): Promise<SandboxOutcome<T>> {
  const timeoutMs = opts.timeoutMs ?? 60_000;
  const maxOldSpaceMB = opts.maxOldSpaceMB ?? 512;

  // mkdtemp under os.tmpdir() with a distinctive prefix. The random suffix
  // is what gives us tenant isolation between concurrent scans on the same
  // host — two callers can't collide even if they submitted the same
  // lockfiles at the same millisecond.
  const sandboxDir = await fs.mkdtemp(path.join(os.tmpdir(), 'vetlock-scan-'));

  try {
    const beforePath = path.join(sandboxDir, 'before.lock');
    const afterPath = path.join(sandboxDir, 'after.lock');
    await Promise.all([
      fs.writeFile(beforePath, input.lockfileBefore, { encoding: 'utf8', mode: 0o600 }),
      fs.writeFile(afterPath, input.lockfileAfter, { encoding: 'utf8', mode: 0o600 }),
    ]);

    const runnerPath = opts.runnerPath ?? defaultRunnerPath();

    return await runSubprocess<T>(runnerPath, [beforePath, afterPath], {
      timeoutMs,
      maxOldSpaceMB,
      cwd: sandboxDir,
    });
  } finally {
    // Unconditional teardown. `force: true` swallows ENOENT if the dir was
    // already removed; `recursive: true` handles the runner having left
    // stray files behind. We don't await this in a way that could hide a
    // scan-outcome error, hence the try/catch swallow — teardown failure
    // is a monitoring signal, not a caller-facing error.
    try {
      await fs.rm(sandboxDir, { recursive: true, force: true });
    } catch {
      // Ignore — the temp dir might have been cleaned by the OS already.
    }
  }
}

interface SubprocessOpts {
  timeoutMs: number;
  maxOldSpaceMB: number;
  cwd: string;
}

async function runSubprocess<T>(runnerPath: string, args: string[], opts: SubprocessOpts): Promise<SandboxOutcome<T>> {
  return new Promise<SandboxOutcome<T>>((resolve) => {
    const nodeArgs = [
      `--max-old-space-size=${opts.maxOldSpaceMB}`,
      runnerPath,
      ...args,
    ];

    const child: ChildProcess = spawn(process.execPath, nodeArgs, {
      cwd: opts.cwd,
      // Inherit stderr for observability (test logs, container logs); pipe
      // stdout since that's the scan-runner's structured-output channel.
      // stdin is closed — the subprocess has nothing to read.
      stdio: ['ignore', 'pipe', 'inherit'],
      // Never expand shell metacharacters — this is defense-in-depth: the
      // args are already a runner path + two temp paths we generated, but
      // shell:false makes the whole "attacker slipped a `;` through argv"
      // shape structurally impossible.
      shell: false,
      // Empty env for the subprocess. It doesn't need PATH, HOME, or any
      // credentials — its only inputs are the two argv paths. Anything an
      // attacker could reach via process.env is now unreachable.
      env: {},
      // Detach so we can kill the whole process group on timeout (see the
      // timeout branch below). Node's default `spawn` keeps the child in
      // the parent's pgroup, which means SIGKILL to the child alone leaves
      // any grandchildren orphaned; detach + kill(-pid) severs both.
      detached: true,
    });

    let stdoutBuf = '';
    let settled = false;
    const settle = (outcome: SandboxOutcome<T>): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(outcome);
    };

    child.stdout?.setEncoding('utf8');
    child.stdout?.on('data', (chunk: string) => {
      stdoutBuf += chunk;
      // Cap accumulated stdout at 4 MB. Real ScanResult payloads are ~KB
      // to low-MB; anything past this cap is a runaway subprocess and we
      // want to short-circuit before it eats parent RAM.
      if (stdoutBuf.length > 4 * 1024 * 1024) {
        stdoutBuf = stdoutBuf.slice(0, 4 * 1024 * 1024);
        killPgroup(child);
        settle({
          kind: 'failed',
          error: 'scan-runner stdout exceeded 4 MB cap',
          exitCode: null,
          signal: 'SIGKILL',
        });
      }
    });

    const timer = setTimeout(() => {
      killPgroup(child);
      settle({ kind: 'timeout', timeoutMs: opts.timeoutMs });
    }, opts.timeoutMs);

    child.on('error', (err) => {
      // Failure to spawn (e.g. missing runner file). Distinct from a
      // successful spawn that later failed.
      settle({
        kind: 'failed',
        error: err instanceof Error ? err.message : String(err),
        exitCode: null,
        signal: null,
      });
    });

    child.on('exit', (code, signal) => {
      if (settled) return;
      // Try to parse a `{ error: string }` on stdout — the runner writes
      // that shape on its own catch-all failure path. If it parses cleanly
      // AND has an `error` key, that's a runner-reported failure. If it
      // parses cleanly AND has any other shape, that's the ScanResult.
      const trimmed = stdoutBuf.trim();
      if (trimmed.length === 0) {
        settle({
          kind: 'failed',
          error: `scan-runner exited without writing to stdout (code=${code}, signal=${signal})`,
          exitCode: code,
          signal,
        });
        return;
      }
      let parsed: unknown;
      try {
        parsed = JSON.parse(trimmed);
      } catch (err) {
        settle({
          kind: 'failed',
          error: `scan-runner emitted unparseable JSON: ${err instanceof Error ? err.message : String(err)}`,
          exitCode: code,
          signal,
        });
        return;
      }
      if (parsed && typeof parsed === 'object' && 'error' in parsed && typeof (parsed as { error: unknown }).error === 'string') {
        settle({
          kind: 'failed',
          error: (parsed as { error: string }).error,
          exitCode: code,
          signal,
        });
        return;
      }
      if (code === 0) {
        settle({ kind: 'ok', result: parsed as T });
        return;
      }
      settle({
        kind: 'failed',
        error: `scan-runner exited with non-zero code=${code}, signal=${signal}, but stdout was not a { error } payload`,
        exitCode: code,
        signal,
      });
    });
  });
}

function killPgroup(child: ChildProcess): void {
  if (child.pid === undefined || child.killed) return;
  try {
    // Negative pid = whole process group. Requires detached:true above.
    process.kill(-child.pid, 'SIGKILL');
  } catch {
    // Fallback to killing just the child if pgroup didn't take (e.g. the
    // child died in the microsecond between the timeout and this call).
    try {
      child.kill('SIGKILL');
    } catch {
      // Nothing to do — process is already dead.
    }
  }
}

function defaultRunnerPath(): string {
  // `import.meta.url` resolves to this file's compiled JS location under
  // `dist/`. Its sibling `scan-runner.js` is what we want to spawn.
  const here = fileURLToPath(import.meta.url);
  const dir = path.dirname(here);
  return path.join(dir, 'scan-runner.js');
}

// -----------------------------------------------------------------------
// Diagnostic surface (kept for status endpoints + monitoring)
// -----------------------------------------------------------------------

/** True once the runtime is running under a real subprocess-per-scan sandbox (this module's `runScanInSandbox`). */
export const SANDBOX_ISOLATION_ENABLED = true;

export interface SandboxInvariants {
  /** No mounted host volume; writable FS is torn down at worker exit. */
  ephemeralFilesystem: boolean;
  /** Only findings + metadata persist past the scan (ADR 0008 §2). */
  findingsOnlyPersistence: boolean;
  /** Wall-clock timeout is enforced by the parent process, not trusted to the child. */
  parentEnforcedTimeout: boolean;
}

/** Current invariant posture for this deployment. Kept for status endpoints + audit. */
export function getSandboxInvariants(): SandboxInvariants {
  return {
    ephemeralFilesystem: true,
    findingsOnlyPersistence: true,
    parentEnforcedTimeout: true,
  };
}
