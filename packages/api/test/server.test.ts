import { describe, it, expect, afterEach } from 'vitest';
import * as http from 'node:http';
import type { AddressInfo } from 'node:net';
import { createServer } from '../src/server.js';
import { ScanQueue, type ScanBackend, type ScanInput, type ScanResultOk } from '../src/scan-queue.js';

/**
 * Fake backend — never touches @vetlock/core's real engine. Resolves
 * immediately by default, or after a manually-triggered `release()` when a
 * test needs to observe the "still pending" (202) state before completion.
 */
class FakeScanBackend implements ScanBackend {
  private resolvers: Array<() => void> = [];
  public calls: ScanInput[] = [];
  public result: ScanResultOk = { verdict: 'CLEAN', findings: [] };
  public autoResolve = true;

  run(input: ScanInput): Promise<ScanResultOk> {
    this.calls.push(input);
    if (this.autoResolve) {
      return Promise.resolve(this.result);
    }
    return new Promise((resolve) => {
      this.resolvers.push(() => resolve(this.result));
    });
  }

  releaseAll(): void {
    const pending = this.resolvers;
    this.resolvers = [];
    for (const r of pending) r();
  }
}

interface TestServer {
  server: http.Server;
  baseUrl: string;
  backend: FakeScanBackend;
}

function startTestServer(): Promise<TestServer> {
  return new Promise((resolve) => {
    const backend = new FakeScanBackend();
    const queue = new ScanQueue(backend);
    const server = createServer({ queue });
    server.listen(0, () => {
      const { port } = server.address() as AddressInfo;
      resolve({ server, baseUrl: `http://127.0.0.1:${port}`, backend });
    });
  });
}

function request(
  baseUrl: string,
  method: string,
  path: string,
  options: { body?: string; contentType?: string | null; contentLength?: number } = {},
): Promise<{ status: number; headers: http.IncomingHttpHeaders; body: string }> {
  return new Promise((resolve, reject) => {
    const url = new URL(path, baseUrl);
    const headers: Record<string, string> = {};
    if (options.contentType !== null) {
      headers['content-type'] = options.contentType ?? 'application/json';
    }
    if (options.body !== undefined) {
      headers['content-length'] = String(
        options.contentLength ?? Buffer.byteLength(options.body),
      );
    }

    const req = http.request(url, { method, headers }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (c: Buffer) => chunks.push(c));
      res.on('end', () => {
        resolve({
          status: res.statusCode ?? 0,
          headers: res.headers,
          body: Buffer.concat(chunks).toString('utf8'),
        });
      });
    });
    req.on('error', reject);
    if (options.body !== undefined) req.write(options.body);
    req.end();
  });
}

let active: TestServer | undefined;

afterEach(() => {
  active?.server.close();
  active = undefined;
});

describe('POST /scan', () => {
  it('accepts a valid request and returns 202 + scanId', async () => {
    active = await startTestServer();
    const res = await request(active.baseUrl, 'POST', '/scan', {
      body: JSON.stringify({ lockfile_before: '{}', lockfile_after: '{}' }),
    });

    expect(res.status).toBe(202);
    const parsed = JSON.parse(res.body);
    expect(typeof parsed.scanId).toBe('string');
    expect(parsed.scanId.length).toBeGreaterThan(0);
    expect(parsed.statusUrl).toBe(`/scan/${parsed.scanId}`);
    expect(res.headers['content-type']).toContain('application/json');
  });

  it('rejects a body over 1MB with 413 before parsing', async () => {
    active = await startTestServer();
    const bigLockfile = 'a'.repeat(1024 * 1024 + 10);
    const res = await request(active.baseUrl, 'POST', '/scan', {
      body: JSON.stringify({ lockfile_before: bigLockfile, lockfile_after: '{}' }),
    });

    expect(res.status).toBe(413);
    const parsed = JSON.parse(res.body);
    expect(parsed.error).toBeDefined();
    // The oversize body must never have reached backend.run().
    expect(active.backend.calls.length).toBe(0);
  });

  it('rejects a non-JSON content-type with 415', async () => {
    active = await startTestServer();
    const res = await request(active.baseUrl, 'POST', '/scan', {
      body: JSON.stringify({ lockfile_before: '{}', lockfile_after: '{}' }),
      contentType: 'text/plain',
    });

    expect(res.status).toBe(415);
    const parsed = JSON.parse(res.body);
    expect(parsed.error).toBeDefined();
  });

  it('rate limits after 5 requests from the same IP within 60s', async () => {
    active = await startTestServer();
    const body = JSON.stringify({ lockfile_before: '{}', lockfile_after: '{}' });

    const statuses: number[] = [];
    for (let i = 0; i < 6; i++) {
      const res = await request(active.baseUrl, 'POST', '/scan', { body });
      statuses.push(res.status);
    }

    expect(statuses.slice(0, 5)).toEqual([202, 202, 202, 202, 202]);
    expect(statuses[5]).toBe(429);
  });

  it('sets Retry-After on a 429 response', async () => {
    active = await startTestServer();
    const body = JSON.stringify({ lockfile_before: '{}', lockfile_after: '{}' });
    for (let i = 0; i < 5; i++) {
      await request(active.baseUrl, 'POST', '/scan', { body });
    }
    const res = await request(active.baseUrl, 'POST', '/scan', { body });
    expect(res.status).toBe(429);
    expect(res.headers['retry-after']).toBeDefined();
  });
});

describe('GET /scan/:scanId', () => {
  it('returns 404 for an unknown scanId', async () => {
    active = await startTestServer();
    const res = await request(active.baseUrl, 'GET', '/scan/does-not-exist');
    expect(res.status).toBe(404);
    const parsed = JSON.parse(res.body);
    expect(parsed.error).toBeDefined();
  });

  it('polls 202 while pending, then 200 with verdict/findings once the backend resolves', async () => {
    active = await startTestServer();
    active.backend.autoResolve = false;
    active.backend.result = { verdict: 'WARN', findings: [] };

    const createRes = await request(active.baseUrl, 'POST', '/scan', {
      body: JSON.stringify({ lockfile_before: '{}', lockfile_after: '{}' }),
    });
    const { scanId } = JSON.parse(createRes.body);

    const pendingRes = await request(active.baseUrl, 'GET', `/scan/${scanId}`);
    expect(pendingRes.status).toBe(202);
    const pendingBody = JSON.parse(pendingRes.body);
    expect(typeof pendingBody.stage).toBe('string');
    expect(typeof pendingBody.elapsedMs).toBe('number');

    active.backend.releaseAll();
    // Allow the backend promise's .then() to run.
    await new Promise((r) => setTimeout(r, 20));

    const doneRes = await request(active.baseUrl, 'GET', `/scan/${scanId}`);
    expect(doneRes.status).toBe(200);
    const doneBody = JSON.parse(doneRes.body);
    expect(doneBody.verdict).toBe('WARN');
    expect(doneBody.findings).toEqual([]);
  });
});

describe('GET /health', () => {
  it('returns status only by default', async () => {
    active = await startTestServer();
    const res = await request(active.baseUrl, 'GET', '/health');
    expect(res.status).toBe(200);
    const parsed = JSON.parse(res.body);
    expect(parsed).toEqual({ status: 'ok' });
  });
});
