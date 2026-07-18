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
import { QueueFullError, ScanQueue, type ScanBackend } from './scan-queue.js';

const PORT = Number(process.env.PORT) || 8080;
const allowedOrigins = (process.env.VETLOCK_CORS_ORIGINS ?? '').split(',').map((origin) => origin.trim()).filter(Boolean);
// TODO: Keep VETLOCK_API_KEY documented in README.md alongside the other deployment env vars.
const API_KEY = process.env.VETLOCK_API_KEY;

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
  // Fly.io injects Fly-Client-IP itself, so this branch prefers the platform's
  // trusted client IP over any caller-controlled forwarding headers.
  const flyClientIp = req.headers['fly-client-ip'];
  if (flyClientIp && typeof flyClientIp === 'string') {
    return flyClientIp.trim();
  }

  // X-Forwarded-For is only safe when an operator explicitly trusts the proxy
  // chain in front of this process; otherwise a direct client can spoof it.
  const trustProxy = process.env.VETLOCK_TRUST_PROXY === 'true';
  if (trustProxy) {
    const xff = req.headers['x-forwarded-for'];
    if (xff && typeof xff === 'string') {
      const hops = xff.split(',').map((s) => s.trim());
      // Use the last hop (closest trusted proxy) rather than the first hop,
      // which can be attacker-controlled when upstreams append to the header.
      return hops[hops.length - 1] ?? req.socket.remoteAddress ?? 'unknown';
    }
  }

  // Safe default: ignore untrusted forwarding headers and use the TCP peer.
  return req.socket.remoteAddress ?? 'unknown';
}

// ---------------------------------------------------------------------------
// Response helpers
// ---------------------------------------------------------------------------

function corsHeaders(req: http.IncomingMessage): Record<string, string> {
  const origin = req.headers.origin;
  if (origin && allowedOrigins.includes(origin)) {
    return {
      'Access-Control-Allow-Origin': origin,
      Vary: 'Origin',
      'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, X-API-Key, Authorization',
    };
  }
  return {};
}

function sendJson(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  status: number,
  body: unknown,
  extraHeaders?: Record<string, string>,
): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    ...corsHeaders(req),
    ...extraHeaders,
  });
  res.end(payload);
}

function sendError(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  status: number,
  error: string,
  code?: string,
  extraHeaders?: Record<string, string>,
): void {
  sendJson(req, res, status, code ? { error, code } : { error }, extraHeaders);
}

function requireApiKey(req: http.IncomingMessage, res: http.ServerResponse): boolean {
  // If no API_KEY is configured, skip auth (development mode).
  if (!API_KEY) return true;

  const headerApiKey = req.headers['x-api-key'];
  const authorization = req.headers.authorization;
  const bearerToken = typeof authorization === 'string' ? authorization.replace(/^Bearer\s+/, '') : undefined;
  const provided = typeof headerApiKey === 'string' ? headerApiKey : bearerToken;
  if (provided !== API_KEY) {
    sendJson(req, res, 401, { error: 'Unauthorized' });
    return false;
  }
  return true;
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
    sendError(req, res, 415, 'Content-Type must be application/json', 'UNSUPPORTED_MEDIA_TYPE');
    req.resume();
    return;
  }

  const contentLength = Number(req.headers['content-length'] ?? 0);
  if (contentLength > MAX_BODY_BYTES) {
    sendError(req, res, 413, 'request body exceeds 1 MB limit', 'PAYLOAD_TOO_LARGE');
    req.resume();
    return;
  }

  const ip = clientIp(req);
  const now = Date.now();
  const rate = limiter.check(ip, now);
  if (!rate.allowed) {
    sendError(req, res, 429, 'rate limit exceeded: 5 scans per 60s per IP', 'RATE_LIMITED', {
      'Retry-After': String(rate.retryAfterSec),
    });
    req.resume();
    return;
  }

  if (!requireApiKey(req, res)) {
    req.resume();
    return;
  }

  const bodyResult = await readBody(req);
  if (!bodyResult.ok) {
    sendError(req, res, 413, 'request body exceeds 1 MB limit', 'PAYLOAD_TOO_LARGE');
    return;
  }

  let parsedJson: unknown;
  try {
    parsedJson = JSON.parse(bodyResult.text);
  } catch {
    sendError(req, res, 400, 'request body is not valid JSON', 'INVALID_JSON');
    return;
  }

  const parsed = ScanRequestSchema.safeParse(parsedJson);
  if (!parsed.success) {
    sendError(req, res, 400, parsed.error.issues.map((i) => i.message).join('; '), 'INVALID_REQUEST');
    return;
  }

  let scanId: string;
  try {
    scanId = queue.enqueue({
      lockfileBefore: parsed.data.lockfile_before,
      lockfileAfter: parsed.data.lockfile_after,
      ecosystem: parsed.data.ecosystem,
    });
  } catch (err) {
    if (err instanceof QueueFullError) {
      sendError(req, res, 503, err.message, 'QUEUE_FULL');
      return;
    }
    throw err;
  }

  sendJson(req, res, 202, { scanId, statusUrl: `/scan/${scanId}` });
}

function handleScanStatus(req: http.IncomingMessage, res: http.ServerResponse, queue: ScanQueue, scanId: string): void {
  const record = queue.getResult(scanId);
  if (!record) {
    sendError(req, res, 404, `unknown scanId: ${scanId}`, 'NOT_FOUND');
    return;
  }

  switch (record.status) {
    case 'expired':
      sendError(req, res, 410, `scan results for ${scanId} have expired (24h retention)`, 'EXPIRED');
      return;
    case 'pending':
      sendJson(req, res, 202, { stage: record.stage, elapsedMs: record.elapsedMs });
      return;
    case 'error':
      sendJson(req, res, 200, { verdict: 'BLOCK', findings: [], error: record.error });
      return;
    case 'done':
      sendJson(req, res, 200, { verdict: record.verdict, findings: record.findings });
      return;
  }
}

function handleHealth(req: http.IncomingMessage, res: http.ServerResponse): void {
  sendJson(req, res, 200, {
    status: 'ok',
    ...(process.env.VETLOCK_DEBUG === 'true' ? { version: VETLOCK_VERSION } : {}),
  });
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
      sendJson(req, res, 204, {});
      return;
    }

    if (method === 'GET' && pathname === '/health') {
      handleHealth(req, res);
      return;
    }

    if (method === 'POST' && pathname === '/scan') {
      void handleScanCreate(req, res, queue, limiter);
      return;
    }

    const statusMatch = SCAN_STATUS_PATH.exec(pathname);
    if (method === 'GET' && statusMatch) {
      handleScanStatus(req, res, queue, decodeURIComponent(statusMatch[1]));
      return;
    }

    sendError(req, res, 404, `no route for ${method} ${pathname}`, 'NOT_FOUND');
  });
}

/* c8 ignore start -- entrypoint glue, exercised via `pnpm dev` / `pnpm start`, not unit tests */
const isDirectRun = process.argv[1] !== undefined && /server\.(js|ts)$/.test(process.argv[1]);
if (isDirectRun) {
  if (process.env.NODE_ENV === 'production' && process.env.VETLOCK_HTTPS_TERMINATOR !== 'true') {
    // eslint-disable-next-line no-console
    console.warn(
      '[vetlock-api] WARNING: Running in production without VETLOCK_HTTPS_TERMINATOR=true. ' +
        'Ensure a HTTPS reverse proxy (e.g. Fly.io, nginx) is terminating TLS before this server.',
    );
  }
  const server = createServer();
  server.listen(PORT, () => {
    // eslint-disable-next-line no-console
    console.log(`vetlock API listening on :${PORT}`);
  });
}
/* c8 ignore stop */
