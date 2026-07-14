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

// P1 wires the actual engine scenarios. The worker imports @vetlock/core (or a caller-
// supplied enginePath), calls the requested entrypoint, and adapts the result into the
// worker outcome channels. Findings translation lives in engine-adapter (parent-side) but
// is duplicated in the worker so we don't have to send the whole engine finding shape
// across structured-clone.
import {
  adaptFindings,
  findingsSignalFailSafe,
  extractFailSafeReason,
  adaptFileCapabilities,
  adaptPackageSnapshot,
} from './engine-adapter.js';
import type { Finding as EngineFinding, FileCapabilities, PackageSnapshot } from '@vetlock/core';

async function runEngine(scenario: Extract<Scenario, { kind: `engine:${string}` }>): Promise<WorkerOutcome> {
  const start = performance.now();
  const mod: unknown = await import(scenario.enginePath);
  const engine = mod as Record<string, unknown>;

  if (scenario.kind === 'engine:parseLockfileText') {
    const parseLockfileText = engine.parseLockfileText as
      | ((text: string, filename?: string) => unknown)
      | undefined;
    if (typeof parseLockfileText !== 'function') {
      throw new Error(
        `[worker] enginePath ${scenario.enginePath} does not export parseLockfileText`,
      );
    }
    // Pure parser call — returns DetectionResult. The parser produces no findings; success
    // is expressed as an ok outcome with an empty findings array. The intent for callers is
    // "did this hostile input crash the parser?" — the answer surfaces via the runner's
    // outcome kind (crash/timeout/oom vs ok).
    parseLockfileText(scenario.text, scenario.filename);
    return { channel: 'ok', findings: [], wallMs: performance.now() - start };
  }

  if (scenario.kind === 'engine:runDiff') {
    const runDiff = engine.runDiff as
      | ((oldText: string, newText: string, opts: unknown) => Promise<unknown>)
      | undefined;
    if (typeof runDiff !== 'function') {
      throw new Error(`[worker] enginePath ${scenario.enginePath} does not export runDiff`);
    }
    // Detector closure is constructed worker-side. Mode 'none' = a no-op closure that
    // returns zero findings. Later phases will register 'all' (@vetlock/detectors wired).
    const runDetectors = () => [];
    const fetchOverride = scenario.disableFetch === false
      ? undefined
      : async () => {
          // No-op fetch — the assurance harness must not touch the network. Callers that
          // legitimately want to exercise fetching will pass fixtures via cache instead.
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
    // The engine's fail-safe channel is a finding with detector === 'analysis.failed'.
    // When it fires, translate to the WorkerFailSafeOutcome so the parent's oracleFailSafe
    // sees the give-up path (not silent-green).
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
    // Wave 3-O: pure text-in → per-file capability extract. Unblocks Wave 1B-J's
    // metamorphic tests — they need a way to feed source text through the AST scanner
    // and inspect the emitted capability set as assurance Findings.
    const extractCapabilities = engine.extractCapabilities as
      | ((filePath: string, text: string, sha256: string, bytes: number) => FileCapabilities)
      | undefined;
    if (typeof extractCapabilities !== 'function') {
      throw new Error(
        `[worker] enginePath ${scenario.enginePath} does not export extractCapabilities`,
      );
    }
    const cap = extractCapabilities(
      scenario.relPath,
      scenario.text,
      scenario.sha256 ?? '',
      scenario.bytes ?? scenario.text.length,
    );
    // extractCapabilities never throws for parse errors — it returns FileCapabilities with
    // parseError set. adaptFileCapabilities routes that to an analysis-failed Finding of
    // BLOCK severity, which the parent's engine-adapter uses to signal fail-safe.
    if (cap.parseError) {
      return {
        channel: 'fail-safe',
        reason: cap.parseError,
        findings: adaptFileCapabilities(cap),
        wallMs: performance.now() - start,
      };
    }
    return {
      channel: 'ok',
      findings: adaptFileCapabilities(cap),
      wallMs: performance.now() - start,
    };
  }

  if (scenario.kind === 'engine:analyzeTarball') {
    // Wave 3-O: full-pipeline entrypoint — extract tarball, scan every file, read manifest.
    // Unblocks Wave 3-M's archive test vectors which feed adversarial tarballs (path
    // traversal, symlinks, size bombs) through the real extractor + analyzer.
    const analyzeTarball = engine.analyzeTarball as
      | ((tarballPath: string, opts?: unknown) => Promise<PackageSnapshot>)
      | undefined;
    if (typeof analyzeTarball !== 'function') {
      throw new Error(
        `[worker] enginePath ${scenario.enginePath} does not export analyzeTarball`,
      );
    }
    const snap = await analyzeTarball(scenario.tarballPath);
    return {
      channel: 'ok',
      findings: adaptPackageSnapshot(snap),
      wallMs: performance.now() - start,
    };
  }

  // Exhaustiveness — any new engine:* kind added to the union must have a case here.
  const _exhaustive: never = scenario;
  throw new Error(`[worker] unknown engine scenario kind: ${JSON.stringify(_exhaustive)}`);
}

// The engine's Finding shape lives in @vetlock/core; imported above via `import type` so
// the worker doesn't pay any runtime cost for the reference.

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
  parentPort?.postMessage(outcome);
}

main().catch((err: unknown) => {
  // Rethrow so the parent's 'error' handler sees it. postMessage of an Error doesn't preserve
  // .name; throwing does.
  throw err;
});
