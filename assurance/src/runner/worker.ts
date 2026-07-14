/**
 * Bounded runner worker (ADR-0003).
 *
 * Runs INSIDE a worker_threads.Worker. Receives a Scenario via workerData, executes it,
 * and posts back exactly one message with the outcome. The parent runner drives the
 * lifecycle (wallMs timer, resourceLimits, terminate, exit-code mapping); this file only
 * cares about producing the payload.
 *
 * Never do anything CPU-heavy here that isn't part of the scenario — the wallMs bound
 * belongs to the scenario, not to worker setup.
 */

import { parentPort, workerData } from 'node:worker_threads';
import { performance } from 'node:perf_hooks';
import type { Scenario } from './types.js';
import type { Finding, Findings } from '../oracles/types.js';

// -- outcome shapes exchanged with the parent ------------------------------------------------
// These are structured-clone-safe. Kept local (not exported types) because the parent maps
// them into RunOutcome after adding kind-specific metadata (seed, timings, RSS).

interface WorkerOkOutcome {
  readonly channel: 'ok';
  readonly findings: Findings;
  readonly wallMs: number;
}
interface WorkerFailSafeOutcome {
  readonly channel: 'fail-safe';
  readonly reason: string;
  readonly findings: Findings;
  readonly wallMs: number;
}
// `crash` from the worker side is signaled by throwing (parent listens on 'error');
// no need for a dedicated channel here.
type WorkerOutcome = WorkerOkOutcome | WorkerFailSafeOutcome;

// -- scenario handlers -----------------------------------------------------------------------

async function runNormal(
  scenario: Extract<Scenario, { kind: 'synthetic:normal' }>,
): Promise<WorkerOkOutcome> {
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
    // Tight loop; never yields. The parent's wallMs timer + worker.terminate() must break us out.
    // eslint-disable-next-line no-constant-condition
    while (true) {
      // Do a bit of work each iteration so JIT doesn't optimize the whole loop into nothing.
      Math.sqrt(Math.random() + 1);
    }
  }
  // await-forever: block on a promise that never resolves. Distinguishes microtask starvation
  // from busy-loop; both must trip the wallMs bound. We keep the event loop alive with a
  // long-lived interval — without it, Node sees "no pending work" and cleanly exits before
  // our wallMs bound trips, which would surface as a crash (WorkerExitedWithoutResult) rather
  // than the timeout the scenario is designed to produce.
  const keepAlive = setInterval(() => {
    // No-op. The reference is enough to keep the event loop alive.
  }, 1_000_000);
  try {
    await new Promise<never>(() => {});
    // Unreachable — type system doesn't know that. Present to satisfy `Promise<never>`.
    throw new Error('unreachable');
  } finally {
    clearInterval(keepAlive);
  }
}

function runCrash(scenario: Extract<Scenario, { kind: 'synthetic:crash' }>): never {
  const name = scenario.errorName ?? 'Error';
  const message = scenario.errorMessage ?? 'synthetic crash';
  // Throw with a specific `.name` so the parent captures the exact identity.
  const err = new Error(message);
  err.name = name;
  throw err;
}

function runOom(scenario: Extract<Scenario, { kind: 'synthetic:oom' }>): never {
  const mode = scenario.mode ?? 'grow-array';
  // Allocate past the heap cap. The specific shape doesn't matter — Node's OOM guard fires
  // once V8 can't satisfy an allocation within resourceLimits.maxOldGenerationSizeMb.
  if (mode === 'grow-array') {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const acc: any[] = [];
    // eslint-disable-next-line no-constant-condition
    while (true) {
      // Push in chunks so each push produces retained references (not GC'd).
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
  // grow-buffer
  const bufs: Uint8Array[] = [];
  // eslint-disable-next-line no-constant-condition
  while (true) {
    bufs.push(new Uint8Array(1024 * 1024));
  }
}

function runFailSafe(
  scenario: Extract<Scenario, { kind: 'synthetic:fail-safe' }>,
): WorkerFailSafeOutcome {
  const reason = scenario.reason ?? 'analysis-failed';
  const cls = scenario.capabilityClass ?? 'analysis-failed';
  const findings: Findings = [
    { capabilityClass: cls, severity: 'BLOCK', reason },
  ];
  return { channel: 'fail-safe', reason, findings, wallMs: 0 };
}

// P1 wires this into the actual engine. For P0 we stub it so the type completes and
// unknown engine scenarios don't slip through as undefined.
async function runEngine(_scenario: Extract<Scenario, { kind: 'engine' }>): Promise<WorkerOutcome> {
  throw new Error('engine scenario not wired in P0 — see PACKET-VETLOCK-ASSURANCE P1');
}

// -- entrypoint ------------------------------------------------------------------------------

async function main(): Promise<void> {
  const scenario = workerData as Scenario;
  let outcome: WorkerOutcome;
  switch (scenario.kind) {
    case 'synthetic:normal':
      outcome = await runNormal(scenario);
      break;
    case 'synthetic:hang':
      // eslint-disable-next-line no-await-in-loop
      await runHang(scenario); // never returns
      // Unreachable — appeases the switch exhaustiveness check.
      throw new Error('unreachable');
    case 'synthetic:crash':
      runCrash(scenario); // throws
      throw new Error('unreachable');
    case 'synthetic:oom':
      runOom(scenario); // never returns cleanly
      throw new Error('unreachable');
    case 'synthetic:fail-safe':
      outcome = runFailSafe(scenario);
      break;
    case 'engine':
      outcome = await runEngine(scenario);
      break;
    default: {
      const _exhaustive: never = scenario;
      throw new Error(`unknown scenario kind: ${JSON.stringify(_exhaustive)}`);
    }
  }
  parentPort?.postMessage(outcome);
}

main().catch((err: unknown) => {
  // Rethrow so the parent's 'error' handler sees it. postMessage of an Error doesn't preserve
  // .name; throwing does.
  throw err;
});
