/**
 * Bounded runner parent — child_process fallback (ADR-0003 extension).
 *
 * Same contract as `runBounded` (worker_threads-based): given a Scenario and Bounds, resolve
 * to exactly one RunOutcome. Never throws. The difference is *isolation strength*:
 *
 *   worker_threads.Worker — cheap, but shares the Node runtime with the parent. A native
 *     abort (`process.abort()`, uncatchable V8 assertion, segfault in a native module) kills
 *     the entire runtime, including whatever test host is driving the harness.
 *
 *   child_process.spawn (this file) — expensive (fresh V8 heap, fresh event loop, spawn cost),
 *     but its own OS process. When the child dies from SIGABRT / SIGSEGV / SIGKILL, only the
 *     child dies; the parent sees the signal on exit and maps it to a RunOutcome kind.
 *
 * Callers reach for this runner explicitly when a scenario is known (or suspected) to
 * V8-abort. The worker_threads path (`runBounded`) remains the default for the 99% case
 * where thrown errors, timeouts, and normal OOM are the failure modes to observe.
 *
 * Enforcement:
 *   - wallMs: parent arms a setTimeout; on fire, `child.kill('SIGKILL')` and resolve
 *     `kind: 'timeout'`. SIGKILL is used (not SIGTERM) to avoid the child intercepting it.
 *   - heapMb: spawned with `--max-old-space-size=<heapMb>`. When V8 exceeds the cap, the
 *     child aborts (typically SIGABRT + "JavaScript heap out of memory" on stderr, or the
 *     historical exit code 5). Both signals map to `kind: 'oom'`.
 *
 * Protocol with the child (see child-entry.ts for the flip side):
 *   1. Parent JSON-stringifies the Scenario, writes to child stdin, closes stdin.
 *   2. Child executes, writes a JSON child-outcome to stdout (channels: ok / fail-safe / error),
 *      exits(0).
 *   3. If the child dies without emitting stdout (native abort / SIGKILL from parent), the
 *      parent uses exit code + signal + stderr patterns to classify.
 */

import { spawn, type ChildProcess } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, resolve as pathResolve } from 'node:path';
import { existsSync } from 'node:fs';
import { performance } from 'node:perf_hooks';
import type { Bounds, RunOutcome, SerializedError, Findings } from '../oracles/types.js';
import type { Scenario } from './types.js';

// Path resolution mirrors runner.ts: production points at the compiled sibling
// `child-entry.js`, tests fall back to `../../dist/runner/child-entry.js` because TS-source
// imports can't be executed directly by a spawned Node.
const CHILD_ENTRY_PATH: string = (() => {
  const here = dirname(fileURLToPath(import.meta.url));
  const candidates = [
    pathResolve(here, 'child-entry.js'),
    pathResolve(here, '..', '..', 'dist', 'runner', 'child-entry.js'),
  ];
  for (const candidate of candidates) {
    if (existsSync(candidate)) return candidate;
  }
  throw new Error(
    `[@vetlock/assurance] child-entry.js not found. Run \`pnpm build\` first. Tried: ${candidates.join(', ')}`,
  );
})();

// -- OOM detection heuristics -------------------------------------------------------------
// A child_process hitting the heap cap can surface it four different ways depending on the
// Node/V8 build:
//   1. exit signal SIGABRT (most common on modern Node — V8 calls abort() after logging OOM)
//   2. exit code 134 (128 + SIGABRT signal number)
//   3. exit code 5 (V8's historical abort code — older Node)
//   4. stderr contains one of the OOM message patterns; exit code non-zero
//
// The stderr patterns match runner.ts; they're what V8 prints before aborting.
const OOM_STDERR_PATTERNS = [
  /out of memory/i,
  /heap out of memory/i,
  /allocation failed/i,
  /reached heap limit/i,
];
const OOM_EXIT_CODES = new Set<number>([5, 134]);

function serializeError(err: unknown): SerializedError {
  if (err instanceof Error) {
    return {
      name: err.name,
      message: err.message,
      stack: err.stack,
      cause: (err as { cause?: unknown }).cause,
    };
  }
  if (typeof err === 'object' && err !== null) {
    const rec = err as Record<string, unknown>;
    return {
      name: typeof rec.name === 'string' ? rec.name : 'Error',
      message: typeof rec.message === 'string' ? rec.message : JSON.stringify(err),
      stack: typeof rec.stack === 'string' ? rec.stack : undefined,
    };
  }
  return { name: 'Error', message: String(err) };
}

/** JSON payloads emitted by the child. Mirror of ChildOutcome in child-entry.ts. */
type ChildOutcomeMessage =
  | { readonly channel: 'ok'; readonly findings: Findings; readonly wallMs: number }
  | {
      readonly channel: 'fail-safe';
      readonly reason: string;
      readonly findings: Findings;
      readonly wallMs: number;
    }
  | {
      readonly channel: 'error';
      readonly error: SerializedError;
      readonly wallMs: number;
    };

function classifyNoStdoutExit(
  code: number | null,
  signal: NodeJS.Signals | null,
  stderr: string,
  bounds: Bounds,
  wallMs: number,
): RunOutcome {
  // SIGABRT is the strongest OOM tell — that's what V8 emits after logging a heap error, and
  // it's also what process.abort() emits (the V8-abort case the fallback exists for).
  if (signal === 'SIGABRT') {
    return { kind: 'oom', peakRssBytes: bounds.heapMb * 1024 * 1024, seed: bounds.seed };
  }
  // stderr OOM signature — set by V8 before aborting on some Node builds.
  if (OOM_STDERR_PATTERNS.some((p) => p.test(stderr))) {
    return { kind: 'oom', peakRssBytes: bounds.heapMb * 1024 * 1024, seed: bounds.seed };
  }
  // Historical V8 abort exit codes (5 / 134).
  if (code !== null && OOM_EXIT_CODES.has(code)) {
    return { kind: 'oom', peakRssBytes: bounds.heapMb * 1024 * 1024, seed: bounds.seed };
  }
  // Anything else non-zero without a child-emitted result is a crash. Include what we know.
  return {
    kind: 'crash',
    error: {
      name: 'ChildExitedWithoutResult',
      message: signal
        ? `child killed by signal ${signal} before producing a result`
        : `child exited with code ${code ?? 'null'} before producing a result`,
      stack: stderr.length > 0 ? stderr.slice(0, 4096) : undefined,
    },
    wallMs,
    seed: bounds.seed,
  };
}

/**
 * Run one scenario with hard wall-clock and heap bounds using a full child_process.
 * Resolves to exactly one RunOutcome. Never throws.
 *
 * Prefer this over `runBounded` when the scenario is known to V8-abort (SIGABRT / segfault /
 * catastrophic native failure). Everyday scenarios should stick with the cheaper
 * worker_threads runner.
 */
export function runBoundedInProcess(scenario: Scenario, bounds: Bounds): Promise<RunOutcome> {
  return new Promise<RunOutcome>((resolve) => {
    const start = performance.now();
    let settled = false;
    let timeoutHandle: ReturnType<typeof setTimeout> | undefined;
    let terminatedForTimeout = false;

    const finish = (outcome: RunOutcome): void => {
      if (settled) return;
      settled = true;
      if (timeoutHandle) clearTimeout(timeoutHandle);
      // Best-effort teardown: if the child is still alive (racy exit path) send SIGKILL.
      // We don't await — the parent has its outcome, teardown is fire-and-forget.
      if (child.exitCode === null && child.signalCode === null) {
        try {
          child.kill('SIGKILL');
        } catch {
          /* already dead / permission — not oracle-observable */
        }
      }
      resolve(outcome);
    };

    // Spawn a fresh Node with the heap cap wired in via V8 flag. execArgv is inherited from
    // the parent's execPath; we pass ONLY our heap flag to keep the child's runtime minimal.
    const child: ChildProcess = spawn(
      process.execPath,
      [`--max-old-space-size=${bounds.heapMb}`, CHILD_ENTRY_PATH],
      {
        stdio: ['pipe', 'pipe', 'pipe'],
      },
    );

    let stdout = '';
    let stderr = '';
    child.stdout?.on('data', (chunk: Buffer) => {
      stdout += chunk.toString('utf8');
    });
    child.stderr?.on('data', (chunk: Buffer) => {
      stderr += chunk.toString('utf8');
    });

    // If the parent can't even spawn the child (path missing, ENOENT, etc.), surface as crash.
    child.on('error', (err) => {
      finish({
        kind: 'crash',
        error: serializeError(err),
        wallMs: performance.now() - start,
        seed: bounds.seed,
      });
    });

    child.on('exit', (code, signal) => {
      const wallMs = performance.now() - start;

      if (terminatedForTimeout) {
        // The wallMs path already resolved (see setTimeout below). If somehow it didn't,
        // resolve as timeout defensively.
        finish({ kind: 'timeout', wallMs: bounds.wallMs, seed: bounds.seed });
        return;
      }

      // Try to parse a child-emitted outcome first. If the child produced stdout it means
      // it reached its own emit path — success, fail-safe, or a caught throw.
      const trimmed = stdout.trim();
      if (trimmed.length > 0) {
        // The child may have written diagnostics before the outcome; take the LAST JSON line
        // (its emit is a single trailing line, per child-entry.ts).
        const lastNewlineIdx = trimmed.lastIndexOf('\n');
        const lastLine = lastNewlineIdx === -1 ? trimmed : trimmed.slice(lastNewlineIdx + 1);
        let parsed: ChildOutcomeMessage | null = null;
        try {
          parsed = JSON.parse(lastLine) as ChildOutcomeMessage;
        } catch {
          parsed = null;
        }
        if (parsed) {
          if (parsed.channel === 'ok') {
            finish({
              kind: 'ok',
              findings: parsed.findings,
              wallMs,
              peakRssBytes: bounds.heapMb * 1024 * 1024,
              seed: bounds.seed,
            });
            return;
          }
          if (parsed.channel === 'fail-safe') {
            finish({
              kind: 'fail-safe',
              reason: parsed.reason,
              findings: parsed.findings,
              wallMs,
              seed: bounds.seed,
            });
            return;
          }
          if (parsed.channel === 'error') {
            finish({
              kind: 'crash',
              error: parsed.error,
              wallMs,
              seed: bounds.seed,
            });
            return;
          }
        }
        // Stdout present but unparseable — fall through to signal-based classification.
      }

      // No stdout (or unparseable): classify from exit signal / code / stderr.
      finish(classifyNoStdoutExit(code, signal as NodeJS.Signals | null, stderr, bounds, wallMs));
    });

    // Hand the scenario to the child via stdin. structuredClone-compatible fields serialize
    // fine as JSON; the Scenario type is deliberately kept plain-data.
    const stdin = child.stdin;
    if (stdin) {
      stdin.on('error', () => {
        /* child may have died before we finished writing; the exit handler covers classification */
      });
      stdin.end(JSON.stringify(scenario));
    }

    timeoutHandle = setTimeout(() => {
      if (settled) return;
      terminatedForTimeout = true;
      // Kill with SIGKILL so the child cannot intercept it. The exit handler will fire
      // shortly after; we resolve first so the outcome is authoritative.
      try {
        child.kill('SIGKILL');
      } catch {
        /* already dead — no-op */
      }
      finish({
        kind: 'timeout',
        wallMs: bounds.wallMs,
        seed: bounds.seed,
      });
    }, bounds.wallMs);
  });
}
