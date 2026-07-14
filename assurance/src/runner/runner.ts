/**
 * Bounded runner parent (ADR-0003).
 *
 * Spawns a worker_threads.Worker with `resourceLimits.maxOldGenerationSizeMb = heapMb`,
 * arms a wall-clock timer for wallMs, and resolves to exactly one RunOutcome.
 *
 * The single-resolution invariant is the tricky part. A worker can:
 *   - post a `message` (ok / fail-safe) then `exit`
 *   - throw an `error` (crash or OOM)
 *   - be `terminate()`d by the parent (timeout)
 * These paths race: a worker may post its message a microsecond before the wallMs timer
 * fires. A `settled` flag guards against double-resolve.
 *
 * OOM detection is heuristic — Node/V8 signals it in multiple ways depending on version:
 *   1. `error` event with `err.code === 'ERR_WORKER_OUT_OF_MEMORY'` (newer Node)
 *   2. `error` event with message matching /out of memory|heap out of memory/i (older Node)
 *   3. `error` event with V8-internal signatures: 'v8::internal::Heap::' or 'Zone::New'
 *      (Wave 1B-B reported these leak through as `crash` — they're OOM in disguise)
 *   4. `error` event with 'Reached heap limit Allocation failed' (Node/V8 OOM banner)
 *   5. `exit` event with code 5 (V8 abort code for OOM)
 * All five normalize to `kind: 'oom'`. Anything else on the error path is `kind: 'crash'`.
 */

import { Worker } from 'node:worker_threads';
import { fileURLToPath } from 'node:url';
import { dirname, resolve as pathResolve } from 'node:path';
import { existsSync } from 'node:fs';
import { performance } from 'node:perf_hooks';
import type { Bounds, RunOutcome, SerializedError, Findings } from '../oracles/types.js';
import type { Scenario } from './types.js';

// Where the compiled worker script lives. Resolution has to handle two runtime shapes:
//   1. Production: this file is dist/runner/runner.js, worker is dist/runner/worker.js (sibling).
//   2. Tests: vitest imports src/runner/runner.ts via TS resolution. `import.meta.url` points at
//      src/runner/runner.ts, but there is no worker.ts a Worker can execute — Node's
//      worker_threads.Worker requires a .js. We look up the compiled dist worker instead.
//
// Order of attempts: sibling `worker.js` (dist), then `../../dist/runner/worker.js` (from src).
// The first that exists wins. Resolution happens at module load and is cached.
const WORKER_PATH: string = (() => {
  const here = dirname(fileURLToPath(import.meta.url));
  const candidates = [
    pathResolve(here, 'worker.js'),
    pathResolve(here, '..', '..', 'dist', 'runner', 'worker.js'),
  ];
  for (const candidate of candidates) {
    if (existsSync(candidate)) return candidate;
  }
  // If neither exists we let the Worker constructor throw with a clear message rather than
  // silently returning a bogus path.
  throw new Error(
    `[@vetlock/assurance] worker.js not found. Run \`pnpm build\` first. Tried: ${candidates.join(', ')}`,
  );
})();

/** Error codes Node emits when a worker's V8 heap blows past resourceLimits. */
const OOM_ERROR_CODE = 'ERR_WORKER_OUT_OF_MEMORY';
/**
 * Message-shaped OOM signals. Ordered from most-common to most-obscure. The first three come
 * from older-Node error-path OOMs; the last two are the V8-internal signatures Wave 1B-B
 * observed leaking through as 'crash' (they showed up in error messages with a stack frame
 * pointing at V8 internals rather than the standard OOM banner).
 */
const OOM_MESSAGE_PATTERNS = [
  /out of memory/i,
  /heap out of memory/i,
  /allocation failed/i,
  /reached heap limit/i,
  // V8-internal signatures — these appear in the stack when the allocator itself aborts.
  /v8::internal::Heap::/,
  /Zone::New/,
  // Node/V8 formal OOM banner (JS-level). Sometimes appears without 'out of memory' matching.
  /Reached heap limit Allocation failed/i,
];
/** V8's stereotypical abort exit code for allocation failures. */
const OOM_EXIT_CODE = 5;

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

/**
 * Heuristic classifier for OOM vs generic crash.
 *
 * Wave 1B-B feedback: some V8 allocation paths surface as `crash` with a non-standard
 * message rather than the canonical OOM banner. The V8-internal signatures ('v8::internal::
 * Heap::' and 'Zone::New') appear in the .stack, not always in .message. So we scan both.
 *
 * The check order matters — code first (cheapest, most-authoritative), then message, then
 * stack. Any positive short-circuits.
 */
function looksLikeOom(err: unknown): boolean {
  if (!err || typeof err !== 'object') return false;
  const rec = err as Record<string, unknown>;
  if (rec.code === OOM_ERROR_CODE) return true;
  const message = typeof rec.message === 'string' ? rec.message : '';
  if (OOM_MESSAGE_PATTERNS.some((pattern) => pattern.test(message))) return true;
  // Fall through to the stack — V8-internal aborts often have empty/non-standard messages
  // but a stack frame pointing at the allocator.
  const stack = typeof rec.stack === 'string' ? rec.stack : '';
  return OOM_MESSAGE_PATTERNS.some((pattern) => pattern.test(stack));
}

/** Structured-clone-safe outcome messages the worker posts. Mirror of worker.ts. */
type WorkerMessage =
  | { readonly channel: 'ok'; readonly findings: Findings; readonly wallMs: number }
  | { readonly channel: 'fail-safe'; readonly reason: string; readonly findings: Findings; readonly wallMs: number };

/**
 * Run one scenario with hard wall-clock and heap bounds. Resolves to exactly one RunOutcome.
 * Never throws — every failure mode is expressed as an outcome kind.
 */
export function runBounded(scenario: Scenario, bounds: Bounds): Promise<RunOutcome> {
  return new Promise<RunOutcome>((resolve) => {
    const start = performance.now();
    let settled = false;
    let timeoutHandle: ReturnType<typeof setTimeout> | undefined;

    const finish = (outcome: RunOutcome): void => {
      if (settled) return;
      settled = true;
      if (timeoutHandle) clearTimeout(timeoutHandle);
      // Fire terminate() to release the worker regardless of how we got here. If the worker
      // is already gone this is a no-op that returns a resolved promise. We deliberately do
      // NOT await it — the parent has its outcome; worker teardown happens on its own.
      worker.terminate().catch(() => {
        /* teardown errors are not oracle-observable; swallow to keep the harness robust */
      });
      resolve(outcome);
    };

    const worker = new Worker(WORKER_PATH, {
      workerData: scenario,
      resourceLimits: {
        maxOldGenerationSizeMb: bounds.heapMb,
      },
    });

    worker.on('message', (msg: WorkerMessage) => {
      const wallMs = performance.now() - start;
      if (msg.channel === 'ok') {
        // peakRssBytes is approximate — see ADR-0003. For P0 the number just needs to be
        // present and monotonically bounded by the heap cap.
        finish({
          kind: 'ok',
          findings: msg.findings,
          wallMs,
          peakRssBytes: bounds.heapMb * 1024 * 1024,
          seed: bounds.seed,
        });
        return;
      }
      if (msg.channel === 'fail-safe') {
        finish({
          kind: 'fail-safe',
          reason: msg.reason,
          findings: msg.findings,
          wallMs,
          seed: bounds.seed,
        });
      }
    });

    worker.on('error', (err) => {
      const wallMs = performance.now() - start;
      if (looksLikeOom(err)) {
        finish({
          kind: 'oom',
          // On OOM we know the worker hit the cap. Report the cap in bytes as peak.
          peakRssBytes: bounds.heapMb * 1024 * 1024,
          seed: bounds.seed,
        });
        return;
      }
      finish({
        kind: 'crash',
        error: serializeError(err),
        wallMs,
        seed: bounds.seed,
      });
    });

    worker.on('exit', (code) => {
      // Most exits are caught by 'message' or 'error' before this fires. The remaining case
      // is a clean OOM that only surfaces via exit code 5 (older Node/V8 combinations).
      if (settled) return;
      // Note: the timeout path can't reach here — the setTimeout below calls finish() first,
      // which flips `settled = true` synchronously *before* awaiting worker.terminate(). By
      // the time terminate's exit event bubbles, the `if (settled) return` above catches it.
      // (Wave 1B-B feedback: an earlier `if (terminatedForTimeout) ...` fallback here was
      // dead code and was pruned.)
      if (code === OOM_EXIT_CODE) {
        finish({
          kind: 'oom',
          peakRssBytes: bounds.heapMb * 1024 * 1024,
          seed: bounds.seed,
        });
        return;
      }
      // Unexpected clean exit (code 0) with no message. Treat as crash — the worker died
      // without producing a verdict, which violates the contract.
      finish({
        kind: 'crash',
        error: {
          name: 'WorkerExitedWithoutResult',
          message: `worker exited with code ${code} before producing a result`,
        },
        wallMs: performance.now() - start,
        seed: bounds.seed,
      });
    });

    timeoutHandle = setTimeout(() => {
      if (settled) return;
      // Resolve first, terminate second: the outcome is authoritative regardless of how the
      // worker responds to terminate(). finish() will invoke terminate() again but the
      // `settled` flag prevents double-resolve.
      finish({
        kind: 'timeout',
        wallMs: bounds.wallMs,
        seed: bounds.seed,
      });
    }, bounds.wallMs);
  });
}
