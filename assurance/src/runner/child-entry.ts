/**
 * Bounded runner child-process entrypoint (ADR-0003 extension).
 *
 * Runs INSIDE a full Node child_process spawned by runBoundedInProcess. Unlike worker.ts
 * (worker_threads.Worker), a child_process is its own OS process. That isolation is heavier
 * (more RAM, slower start) but survives failure modes worker_threads cannot contain:
 *   - Native SIGABRT (`process.abort()`, catastrophic V8 assertions)
 *   - Native segfaults from bad native modules
 *   - V8 fatal errors that abort the entire runtime
 *
 * All of those in a worker_threads.Worker take the parent Node process with them. In a child
 * process, the parent survives; it observes the child's exit signal/code and maps it to a
 * RunOutcome kind (oom / crash / timeout).
 *
 * Protocol:
 *   1. Parent writes a single JSON-serialized Scenario to this process's stdin, then closes it.
 *   2. This process reads all of stdin, parses the Scenario, executes it.
 *   3. On success (ok / fail-safe): writes a JSON child-outcome to stdout, then exits(0).
 *   4. On a thrown error: writes a JSON child-outcome with channel 'error', exits(0).
 *      The parent maps 'error' → RunOutcome kind 'crash'.
 *   5. On an uncatchable native abort (`process.abort()`, segfault): the process dies with
 *      signal SIGABRT (or SIGSEGV) BEFORE writing anything. Parent sees the signal on exit.
 *
 * The handlers here duplicate the shape from worker.ts on purpose: the two runners are
 * independent isolation strategies with slightly different protocols (stdio vs postMessage,
 * process signals vs Worker events). Keeping them separate avoids coupling the assurance
 * runner to a Node worker_threads-flavored abstraction, and the touch-scope for this phase
 * forbids editing worker.ts.
 */

import { performance } from 'node:perf_hooks';
import type { Scenario } from './types.js';
import type { Finding, Findings, SerializedError } from '../oracles/types.js';
import {
  adaptFindings,
  findingsSignalFailSafe,
  extractFailSafeReason,
  adaptFileCapabilities,
  adaptPackageSnapshot,
} from './engine-adapter.js';
import type {
  Finding as EngineFinding,
  FileCapabilities,
  PackageSnapshot,
} from '@vetlock/core';

/**
 * Local widening of the shared Scenario union. Only the child-process runner exposes these
 * kinds; the worker_threads runner never sees them. They exist purely to exercise the
 * fallback's ability to observe uncatchable native aborts — that's the whole reason it exists.
 */
type ChildOnlyScenario =
  | {
      readonly kind: 'synthetic:v8-abort';
      /** Which uncatchable-abort strategy to use. `process.abort()` is the canonical one. */
      readonly mode?: 'process-abort';
    };

type AnyChildScenario = Scenario | ChildOnlyScenario;

// -- outcome shapes exchanged over stdout with the parent ----------------------------------
// These are plain JSON. The parent maps them into RunOutcome after adding kind-specific
// metadata (seed, timings, RSS).

interface ChildOkOutcome {
  readonly channel: 'ok';
  readonly findings: Findings;
  readonly wallMs: number;
}
interface ChildFailSafeOutcome {
  readonly channel: 'fail-safe';
  readonly reason: string;
  readonly findings: Findings;
  readonly wallMs: number;
}
interface ChildErrorOutcome {
  readonly channel: 'error';
  readonly error: SerializedError;
  readonly wallMs: number;
}
type ChildOutcome = ChildOkOutcome | ChildFailSafeOutcome | ChildErrorOutcome;

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

// -- scenario handlers ---------------------------------------------------------------------

async function runNormal(
  scenario: Extract<Scenario, { kind: 'synthetic:normal' }>,
): Promise<ChildOkOutcome> {
  const start = performance.now();
  const workMs = scenario.workMs ?? 0;
  if (workMs > 0) {
    await new Promise<void>((resolve) => setTimeout(resolve, workMs));
  }
  const findings: Findings = (scenario.findings ?? []).map<Finding>((f) => ({
    capabilityClass: f.capabilityClass,
    severity: f.severity,
    reason: f.reason,
  }));
  return { channel: 'ok', findings, wallMs: performance.now() - start };
}

async function runHang(scenario: Extract<Scenario, { kind: 'synthetic:hang' }>): Promise<never> {
  const mode = scenario.mode ?? 'busy-loop';
  if (mode === 'busy-loop') {
    // eslint-disable-next-line no-constant-condition
    while (true) {
      Math.sqrt(Math.random() + 1);
    }
  }
  // await-forever: keep the event loop alive so the child doesn't exit cleanly before the
  // parent's wallMs kill fires — otherwise we'd surface as crash instead of timeout.
  const keepAlive = setInterval(() => {
    /* no-op */
  }, 1_000_000);
  try {
    await new Promise<never>(() => {});
    throw new Error('unreachable');
  } finally {
    clearInterval(keepAlive);
  }
}

function runCrash(scenario: Extract<Scenario, { kind: 'synthetic:crash' }>): never {
  const name = scenario.errorName ?? 'Error';
  const message = scenario.errorMessage ?? 'synthetic crash';
  const err = new Error(message);
  err.name = name;
  throw err;
}

function runOom(scenario: Extract<Scenario, { kind: 'synthetic:oom' }>): never {
  const mode = scenario.mode ?? 'grow-array';
  if (mode === 'grow-array') {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const acc: any[] = [];
    // eslint-disable-next-line no-constant-condition
    while (true) {
      const chunk = new Array(1_000_000).fill({ retained: true });
      acc.push(chunk);
    }
  }
  if (mode === 'grow-string') {
    let s = 'x';
    // eslint-disable-next-line no-constant-condition
    while (true) {
      s = s + s;
    }
  }
  const bufs: Uint8Array[] = [];
  // eslint-disable-next-line no-constant-condition
  while (true) {
    bufs.push(new Uint8Array(1024 * 1024));
  }
}

function runFailSafe(
  scenario: Extract<Scenario, { kind: 'synthetic:fail-safe' }>,
): ChildFailSafeOutcome {
  const reason = scenario.reason ?? 'analysis-failed';
  const cls = scenario.capabilityClass ?? 'analysis-failed';
  const findings: Findings = [{ capabilityClass: cls, severity: 'BLOCK', reason }];
  return { channel: 'fail-safe', reason, findings, wallMs: 0 };
}

/**
 * The V8-abort scenario. This is the whole raison-d'être of the child_process fallback:
 * `process.abort()` triggers a native SIGABRT that is UNCATCHABLE by any JS-level handler.
 * In a worker_threads.Worker, this abort kills the entire Node runtime — including the
 * parent's tinypool test host. In a child_process, only the child dies; the parent sees
 * the SIGABRT signal on exit and maps it to `kind: 'oom'` (V8's abort code convention).
 */
function runV8Abort(_scenario: Extract<ChildOnlyScenario, { kind: 'synthetic:v8-abort' }>): never {
  // process.abort() is a synchronous, uncatchable native abort. No JS handler can intercept it.
  // We intentionally do NOT emit an outcome first — the whole point is to prove the parent
  // can detect a child that dies with no stdout at all.
  process.abort();
}

async function runEngine(
  scenario: Extract<Scenario, { kind: `engine:${string}` }>,
): Promise<ChildOutcome> {
  const start = performance.now();
  const mod: unknown = await import(scenario.enginePath);
  const engine = mod as Record<string, unknown>;

  if (scenario.kind === 'engine:parseLockfileText') {
    const parseLockfileText = engine.parseLockfileText as
      | ((text: string, filename?: string) => unknown)
      | undefined;
    if (typeof parseLockfileText !== 'function') {
      throw new Error(
        `[child-entry] enginePath ${scenario.enginePath} does not export parseLockfileText`,
      );
    }
    parseLockfileText(scenario.text, scenario.filename);
    return { channel: 'ok', findings: [], wallMs: performance.now() - start };
  }

  if (scenario.kind === 'engine:runDiff') {
    const runDiff = engine.runDiff as
      | ((oldText: string, newText: string, opts: unknown) => Promise<unknown>)
      | undefined;
    if (typeof runDiff !== 'function') {
      throw new Error(`[child-entry] enginePath ${scenario.enginePath} does not export runDiff`);
    }
    const runDetectors = () => [];
    const fetchOverride =
      scenario.disableFetch === false
        ? undefined
        : async () => {
            throw new Error('[assurance] engine fetch is disabled in the harness');
          };
    const opts = {
      runDetectors,
      oldLockfilePath: scenario.oldLockfilePath,
      newLockfilePath: scenario.newLockfilePath,
      fetchOverride,
    };
    const result = (await runDiff(scenario.oldLockfileText, scenario.newLockfileText, opts)) as {
      findings: readonly EngineFinding[];
    };
    const engineFindings = result.findings ?? [];
    if (findingsSignalFailSafe(engineFindings)) {
      return {
        channel: 'fail-safe',
        reason: extractFailSafeReason(engineFindings),
        findings: adaptFindings(engineFindings),
        wallMs: performance.now() - start,
      };
    }
    return {
      channel: 'ok',
      findings: adaptFindings(engineFindings),
      wallMs: performance.now() - start,
    };
  }

  if (scenario.kind === 'engine:extractCapabilities') {
    // Wave 3-O engine scenario. Mirrors worker.ts's handler exactly — text-in, capabilities-
    // out, adapted to assurance Findings. The child-process runner supports it too since
    // extractCapabilities is a pure text-scanner (no I/O, so nothing about child_process
    // isolation changes what the engine sees).
    const extractCapabilities = engine.extractCapabilities as
      | ((relPath: string, text: string, sha256: string, bytes: number) => FileCapabilities)
      | undefined;
    if (typeof extractCapabilities !== 'function') {
      throw new Error(
        `[child-entry] enginePath ${scenario.enginePath} does not export extractCapabilities`,
      );
    }
    const cap = extractCapabilities(
      scenario.relPath,
      scenario.text,
      scenario.sha256 ?? '',
      scenario.bytes ?? scenario.text.length,
    );
    return {
      channel: 'ok',
      findings: adaptFileCapabilities(cap),
      wallMs: performance.now() - start,
    };
  }

  if (scenario.kind === 'engine:analyzeTarball') {
    // Wave 3-O engine scenario. Full pipeline: extract + per-file scan + manifest read.
    // The child_process fallback exists specifically for scenarios like adversarial tarballs
    // where the extractor could hit native aborts — this is a primary target for it.
    const analyzeTarball = engine.analyzeTarball as
      | ((tarballPath: string, opts?: unknown) => Promise<PackageSnapshot>)
      | undefined;
    if (typeof analyzeTarball !== 'function') {
      throw new Error(
        `[child-entry] enginePath ${scenario.enginePath} does not export analyzeTarball`,
      );
    }
    const snap = await analyzeTarball(scenario.tarballPath);
    return {
      channel: 'ok',
      findings: adaptPackageSnapshot(snap),
      wallMs: performance.now() - start,
    };
  }

  const _exhaustive: never = scenario;
  throw new Error(`[child-entry] unknown engine scenario kind: ${JSON.stringify(_exhaustive)}`);
}

// -- entrypoint -----------------------------------------------------------------------------

/** Read all of stdin as UTF-8. Parent writes exactly one JSON payload then closes stdin. */
function readStdin(): Promise<string> {
  return new Promise<string>((resolve, reject) => {
    const chunks: Buffer[] = [];
    process.stdin.on('data', (chunk: Buffer) => chunks.push(chunk));
    process.stdin.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    process.stdin.on('error', reject);
  });
}

/**
 * Emit a child outcome to stdout as a single JSON line, then flush. We intentionally use
 * process.stdout.write with a callback so the write completes before the process exits —
 * a bare console.log with a `process.exit(0)` chained via microtask can lose the last chunk.
 */
function writeOutcomeAndExit(outcome: ChildOutcome, exitCode: number): void {
  const payload = JSON.stringify(outcome);
  process.stdout.write(payload + '\n', () => {
    process.exit(exitCode);
  });
}

async function main(): Promise<void> {
  const raw = await readStdin();
  const scenario = JSON.parse(raw) as AnyChildScenario;
  let outcome: ChildOutcome;
  switch (scenario.kind) {
    case 'synthetic:normal':
      outcome = await runNormal(scenario);
      break;
    case 'synthetic:hang':
      // eslint-disable-next-line no-await-in-loop
      await runHang(scenario);
      throw new Error('unreachable');
    case 'synthetic:crash':
      runCrash(scenario);
      throw new Error('unreachable');
    case 'synthetic:oom':
      runOom(scenario);
      throw new Error('unreachable');
    case 'synthetic:fail-safe':
      outcome = runFailSafe(scenario);
      break;
    case 'synthetic:v8-abort':
      // Never returns; kills the process with SIGABRT. Parent detects this on exit.
      runV8Abort(scenario);
      throw new Error('unreachable');
    case 'engine:parseLockfileText':
    case 'engine:runDiff':
    case 'engine:extractCapabilities':
    case 'engine:analyzeTarball':
      outcome = await runEngine(scenario);
      break;
    default: {
      const _exhaustive: never = scenario;
      throw new Error(`unknown scenario kind: ${JSON.stringify(_exhaustive)}`);
    }
  }
  writeOutcomeAndExit(outcome, 0);
}

main().catch((err: unknown) => {
  // Emit a channel:'error' outcome so the parent can capture the error identity + message.
  // Then exit(0). The parent uses the presence of a channel:'error' payload (not the exit
  // code) to distinguish a caught throw from an uncatchable native abort.
  const outcome: ChildErrorOutcome = {
    channel: 'error',
    error: serializeError(err),
    wallMs: 0,
  };
  writeOutcomeAndExit(outcome, 0);
});
