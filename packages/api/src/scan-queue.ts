/**
 * ScanQueue — async job queue backing `POST /scan` / `GET /scan/:id`.
 *
 * NOTE: this file lives at packages/api/src/scan-queue.ts. It exposes the
 * minimal contract server.ts depends on (enqueue → scanId; getResult →
 * status/verdict/findings). A more complete ephemeral-worker-backed queue
 * (ADR 0008 — fresh container per scan, real persistence store) may extend
 * the default backend below; the public ScanQueue surface is the stable
 * import server.ts and its tests rely on.
 *
 * Backend is constructor-injected specifically so tests can swap in a fake
 * that never touches the network or the real analysis pipeline.
 */

import { runDiff, type Finding, type Severity } from '@vetlock/core';
import { runAll } from '@vetlock/detectors';
import * as crypto from 'node:crypto';

export interface ScanInput {
  lockfileBefore: string;
  lockfileAfter: string;
  ecosystem?: 'npm' | 'pypi';
}

export interface ScanResultOk {
  verdict: Severity | 'CLEAN';
  findings: Finding[];
}

export type ScanRecord =
  | { status: 'pending'; stage: string; elapsedMs: number }
  | ({ status: 'done'; elapsedMs: number } & ScanResultOk)
  | { status: 'error'; error: string; elapsedMs: number }
  | { status: 'expired' };

/** Pluggable unit of work. The default hits the real engine; tests inject a fake. */
export interface ScanBackend {
  run(input: ScanInput): Promise<ScanResultOk>;
}

const SCAN_TIMEOUT_MS = parseInt(process.env.VETLOCK_SCAN_TIMEOUT ?? '60000', 10);

/**
 * Default backend — calls straight into @vetlock/core's runDiff with
 * @vetlock/detectors' runAll, the same pairing the CLI uses. No process
 * spawn, no dynamic require of scanned content (ADR 0005): runDiff only
 * ever reads the lockfile text handed to it and fetches package tarballs
 * for static analysis.
 */
export class DefaultScanBackend implements ScanBackend {
  // DefaultScanBackend is for local development only. Production deployments MUST use SandboxedBackend.
  async run(input: ScanInput): Promise<ScanResultOk> {
    let timeoutHandle: ReturnType<typeof setTimeout> | undefined;
    const timeoutPromise = new Promise<never>((_, reject) => {
      timeoutHandle = setTimeout(() => reject(new Error(`Scan timed out after ${SCAN_TIMEOUT_MS}ms`)), SCAN_TIMEOUT_MS);
      timeoutHandle.unref?.();
    });

    try {
      return await Promise.race([this.runInternal(input), timeoutPromise]);
    } finally {
      if (timeoutHandle) clearTimeout(timeoutHandle);
    }
  }

  private async runInternal(input: ScanInput): Promise<ScanResultOk> {
    // requirements.txt/poetry.lock/uv.lock content is self-describing enough
    // for parseLockfileText's content-sniff in most cases; the filename hint
    // just disambiguates when a caller has told us the ecosystem explicitly.
    const filenameHint = input.ecosystem === 'pypi' ? 'requirements.txt' : undefined;
    const result = await runDiff(input.lockfileBefore, input.lockfileAfter, {
      runDetectors: (pair) => runAll(pair),
      oldLockfilePath: filenameHint,
      newLockfilePath: filenameHint,
    });
    return { verdict: result.verdict, findings: result.findings };
  }
}

/** Results persist for 24h after completion (ADR 0008 persistence window). */
const RESULT_TTL_MS = 24 * 60 * 60 * 1000;
const MAX_QUEUE_JOBS = parseInt(process.env.VETLOCK_MAX_QUEUE_JOBS ?? '1000', 10);

interface Job {
  startedAt: number;
  stage: string;
  record: ScanRecord;
  expiresAt: number;
}

export class QueueFullError extends Error {
  constructor(message = `scan queue is full (max ${MAX_QUEUE_JOBS} jobs)`) {
    super(message);
    this.name = 'QueueFullError';
  }
}

export class ScanQueue {
  private readonly jobs = new Map<string, Job>();
  private readonly backend: ScanBackend;

  constructor(backend: ScanBackend = new DefaultScanBackend()) {
    this.backend = backend;
    this.startCleanupInterval();
  }

  /** Starts a scan asynchronously and immediately returns its id. */
  enqueue(input: ScanInput): string {
    this.sweepExpiredJobs(Date.now());
    if (this.jobs.size >= MAX_QUEUE_JOBS) {
      throw new QueueFullError();
    }

    const scanId = crypto.randomUUID();
    const startedAt = Date.now();
    const job: Job = {
      startedAt,
      stage: 'queued',
      record: { status: 'pending', stage: 'queued', elapsedMs: 0 },
      expiresAt: startedAt + RESULT_TTL_MS,
    };
    this.jobs.set(scanId, job);

    job.stage = 'analyzing';
    // Fire-and-forget: failures are captured on the job, never thrown as an
    // unhandled rejection.
    this.backend
      .run(input)
      .then((result) => {
        job.record = { status: 'done', elapsedMs: Date.now() - startedAt, ...result };
        job.expiresAt = Date.now() + RESULT_TTL_MS;
      })
      .catch((err: unknown) => {
        job.record = {
          status: 'error',
          error: err instanceof Error ? err.message : String(err),
          elapsedMs: Date.now() - startedAt,
        };
        job.expiresAt = Date.now() + RESULT_TTL_MS;
      });

    return scanId;
  }

  private startCleanupInterval(): void {
    setInterval(() => {
      this.sweepExpiredJobs(Date.now());
    }, 5 * 60 * 1000).unref();
  }

  private sweepExpiredJobs(now: number): void {
    for (const [id, job] of this.jobs.entries()) {
      if (now > job.expiresAt) {
        this.jobs.delete(id);
      }
    }
  }

  /** undefined = unknown scanId (404). `{status:'expired'}` = past the 24h TTL (410). */
  getResult(scanId: string): ScanRecord | undefined {
    const job = this.jobs.get(scanId);
    if (!job) return undefined;
    if (job.record.status !== 'pending' && Date.now() > job.expiresAt) {
      this.jobs.delete(scanId);
      return { status: 'expired' };
    }
    if (job.record.status === 'pending') {
      return { status: 'pending', stage: job.stage, elapsedMs: Date.now() - job.startedAt };
    }
    return job.record;
  }
}
