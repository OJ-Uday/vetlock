/**
 * Hosted API entrypoint — `POST /scan`, `GET /scan/:scanId`, `GET /health`.
 *
 * Zero-dependency by design: built on `node:http` only. This is a thin,
 * public-facing acceptance layer — every extra runtime dependency here is
 * supply-chain surface for a tool whose whole job is auditing supply-chain
 * surface, so we don't add express/fastify/hono for routing sugar we can
 * write in ~200 lines ourselves.
 *
 * NEVER-EXECUTE (ADR 0005): this file only ever receives lockfile TEXT over
 * HTTP and hands it to ScanQueue#enqueue. It never spawns a process, never
 * resolves a module path from request input, and never calls require()/
 * import() with anything derived from a request at request time. The actual
 * static analysis (still exec-free — see ADR 0005) happens inside
 * @vetlock/core's runDiff, invoked by ScanQueue.
 */

import * as http from 'node:http';
import { z } from 'zod';
import { VETLOCK_VERSION } from '@vetlock/core';
import { ScanQueue, type ScanBackend } from './scan-queue.js';

const PORT = Number(process.env.PORT) || 8080;

/** Hard cap enforced before we even attempt to parse the body. */
const MAX_BODY_BYTES = 1024 * 1024; // 1 MB
const MAX_LOCKFILE_BYTES = 500 * 1024; // 500 KB per lockfile

const ScanRequestSchema = z.object({
  lockfile_before: z.string().max(MAX_LOCKFILE_BYTES, 'lockfile_before exceeds 500 KB'),
  lockfile_after: z.string().max(MAX_LOCKFILE_BYTES, 'lockfile_after exceeds 500 KB'),
  ecosystem: z.enum(['npm', 'pypi']).optional(),
});

// ---------------------------------------------------------------------------
// Rate limiting — 5 scans / 60s / IP, in-memory, bounded by eviction.
// ---------------------------------------------------------------------------

const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX = 5;

/**
 * Per-server-instance rate limiter (ip -> timestamps (ms) of recent scan
 * attempts within the current window). Scoped to a `createServer()` call
 * rather than module-level so that multiple servers in the same process
 * (e.g. one per test) never share rate-limit state.
 */
class RateLimiter {
  private readonly hits = new Map<string, number[]>();

  /**
   * Evicts timestamps older than the window for `ip` on every call, so the
   * map never grows unbounded — stale IPs fall out once their entry becomes
   * empty.
   */
  check(ip: string, now: number): { allowed: boolean; retryAfterSec: number } {
    const existing = this.hits.get(ip) ?? [];
    const fresh = existing.filter((t) => now - t < RATE_LIMIT_WINDOW_MS);

    if (fresh.length >= RATE_LIMIT_MAX) {
      if (fresh.length === 0) {
        this.hits.delete(ip);
      } else {
        this.hits.set(ip, fresh);
      }
      const oldest = fresh[0];
      const retryAfterSec = Math.max(1, Math.ceil((RATE_LIMIT_WINDOW_MS - (now - oldest)) / 1000));
      return { allowed: false, retryAfterSec };
    }

    fresh.push(now);
    this.hits.set(ip, fresh);
    return { allowed: true, retryAfterSec: 0 };
  }
}

function clientIp(req: http.IncomingMessage): string {
  // Trust a single well-formed X-Forwarded-For hop if present (typical
  // behind a reverse proxy / load balancer); fall back to the socket.
  const xff = req.headers['x-forwarded-for'];
  if (typeof xff === 'string' && xff.length > 0) {
    return xff.split(',')[0].trim();
  }
  return req.socket.remoteAddress ?? 'unknown';
}

// ---------------------------------------------------------------------------
// Response helpers
// ---------------------------------------------------------------------------

function sendJson(res: http.ServerResponse, status: number, body: unknown, extraHeaders?: Record<string, string>): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    ...extraHeaders,
  });
  res.end(payload);
}

function sendError(res: http.ServerResponse, status: number, error: string, code?: string, extraHeaders?: Record<string, string>): void {
  sendJson(res, status, code ? { error, code } : { error }, extraHeaders);
}

/**
 * Reads the request body up to MAX_BODY_BYTES. Rejects with a 413-flavored
 * error BEFORE any parsing occurs — we stop accumulating chunks the moment
 * the cap is crossed rather than reading the whole (possibly huge) payload
 * into memory first.
 */
function readBody(req: http.IncomingMessage): Promise<{ ok: true; text: string } | { ok: false; tooLarge: true }> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    let total = 0;
    let tooLarge = false;

    req.on('data', (chunk: Buffer) => {
      if (tooLarge) return;
      total += chunk.length;
      if (total > MAX_BODY_BYTES) {
        tooLarge = true;
        // Drain (not destroy) the socket: the client may still be mid-write
        // of the oversized body, and abruptly destroying the connection
        // races that write, surfacing as an ECONNRESET/EPIPE on the client
        // side instead of letting it read our 413 JSON response. `resume()`
        // discards further chunks without buffering them, so memory stays
        // bounded while the exchange still completes cleanly.
        req.resume();
        resolve({ ok: false, tooLarge: true });
        return;
      }
      chunks.push(chunk);
    });

    req.on('end', () => {
      if (tooLarge) return;
      resolve({ ok: true, text: Buffer.concat(chunks).toString('utf8') });
    });

    req.on('error', () => {
      if (!tooLarge) resolve({ ok: false, tooLarge: true });
    });
  });
}

// ---------------------------------------------------------------------------
// Route handlers
// ---------------------------------------------------------------------------

async function handleScanCreate(req: http.IncomingMessage, res: http.ServerResponse, queue: ScanQueue, limiter: RateLimiter): Promise<void> {
  const contentType = req.headers['content-type'] ?? '';
  if (!contentType.toLowerCase().includes('application/json')) {
    sendError(res, 415, 'Content-Type must be application/json', 'UNSUPPORTED_MEDIA_TYPE');
    req.resume();
    return;
  }

  const contentLength = Number(req.headers['content-length'] ?? 0);
  if (contentLength > MAX_BODY_BYTES) {
    sendError(res, 413, 'request body exceeds 1 MB limit', 'PAYLOAD_TOO_LARGE');
    req.resume();
    return;
  }

  const ip = clientIp(req);
  const now = Date.now();
  const rate = limiter.check(ip, now);
  if (!rate.allowed) {
    sendError(res, 429, 'rate limit exceeded: 5 scans per 60s per IP', 'RATE_LIMITED', {
      'Retry-After': String(rate.retryAfterSec),
    });
    req.resume();
    return;
  }

  const bodyResult = await readBody(req);
  if (!bodyResult.ok) {
    sendError(res, 413, 'request body exceeds 1 MB limit', 'PAYLOAD_TOO_LARGE');
    return;
  }

  let parsedJson: unknown;
  try {
    parsedJson = JSON.parse(bodyResult.text);
  } catch {
    sendError(res, 400, 'request body is not valid JSON', 'INVALID_JSON');
    return;
  }

  const parsed = ScanRequestSchema.safeParse(parsedJson);
  if (!parsed.success) {
    sendError(res, 400, parsed.error.issues.map((i) => i.message).join('; '), 'INVALID_REQUEST');
    return;
  }

  const scanId = queue.enqueue({
    lockfileBefore: parsed.data.lockfile_before,
    lockfileAfter: parsed.data.lockfile_after,
    ecosystem: parsed.data.ecosystem,
  });

  sendJson(res, 202, { scanId, statusUrl: `/scan/${scanId}` });
}

function handleScanStatus(res: http.ServerResponse, queue: ScanQueue, scanId: string): void {
  const record = queue.getResult(scanId);
  if (!record) {
    sendError(res, 404, `unknown scanId: ${scanId}`, 'NOT_FOUND');
    return;
  }

  switch (record.status) {
    case 'expired':
      sendError(res, 410, `scan results for ${scanId} have expired (24h retention)`, 'EXPIRED');
      return;
    case 'pending':
      sendJson(res, 202, { stage: record.stage, elapsedMs: record.elapsedMs });
      return;
    case 'error':
      sendJson(res, 200, { verdict: 'BLOCK', findings: [], error: record.error });
      return;
    case 'done':
      sendJson(res, 200, { verdict: record.verdict, findings: record.findings });
      return;
  }
}

function handleHealth(res: http.ServerResponse): void {
  sendJson(res, 200, { ok: true, version: VETLOCK_VERSION });
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

export interface CreateServerOptions {
  /** Injected for tests; production uses the real ScanQueue + DefaultScanBackend. */
  queue?: ScanQueue;
  backend?: ScanBackend;
}

const SCAN_STATUS_PATH = /^\/scan\/([^/]+)$/;

export function createServer(opts: CreateServerOptions = {}): http.Server {
  const queue = opts.queue ?? new ScanQueue(opts.backend);
  const limiter = new RateLimiter();

  return http.createServer((req, res) => {
    const method = req.method ?? 'GET';
    const url = new URL(req.url ?? '/', 'http://localhost');
    const pathname = url.pathname;

    if (method === 'OPTIONS') {
      sendJson(res, 204, {});
      return;
    }

    if (method === 'GET' && pathname === '/health') {
      handleHealth(res);
      return;
    }

    if (method === 'POST' && pathname === '/scan') {
      void handleScanCreate(req, res, queue, limiter);
      return;
    }

    const statusMatch = SCAN_STATUS_PATH.exec(pathname);
    if (method === 'GET' && statusMatch) {
      handleScanStatus(res, queue, decodeURIComponent(statusMatch[1]));
      return;
    }

    sendError(res, 404, `no route for ${method} ${pathname}`, 'NOT_FOUND');
  });
}

/* c8 ignore start -- entrypoint glue, exercised via `pnpm dev` / `pnpm start`, not unit tests */
const isDirectRun = process.argv[1] !== undefined && /server\.(js|ts)$/.test(process.argv[1]);
if (isDirectRun) {
  const server = createServer();
  server.listen(PORT, () => {
    // eslint-disable-next-line no-console
    console.log(`vetlock API listening on :${PORT}`);
  });
}
/* c8 ignore stop */
