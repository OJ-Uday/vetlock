import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fetchPypiArtifact } from '../src/artifact-pypi.js';

describe('fetchPypiArtifact auth', () => {
  const originalFetch = global.fetch;

  beforeEach(() => {
    vi.restoreAllMocks();
    delete process.env.VETLOCK_PYPI_AUTH;
    delete process.env.JF_AUTH;
    delete process.env.VETLOCK_PYPI_JSON_URL;
    delete process.env.VETLOCK_PYPI_ARTIFACT_URL_REWRITE;
    global.fetch = originalFetch;
  });

  it('passes VETLOCK_PYPI_AUTH as token auth when no colon', async () => {
    const capturedHeaders: Record<string, string>[] = [];
    global.fetch = vi.fn(async (_url, init) => {
      capturedHeaders.push(Object.fromEntries(new Headers(init?.headers ?? {}).entries()));
      return new Response(JSON.stringify({ urls: [] }), { status: 200 });
    }) as typeof fetch;

    process.env.VETLOCK_PYPI_AUTH = 'my-token';

    await expect(fetchPypiArtifact({ name: 'requests', version: '2.31.0' })).rejects.toThrow(
      'contains no file URLs',
    );

    expect(capturedHeaders[0]?.authorization).toBe('Bearer ' + 'my-token');
  });

  it('passes VETLOCK_PYPI_AUTH as Basic when user:token format', async () => {
    const capturedHeaders: Record<string, string>[] = [];
    global.fetch = vi.fn(async (_url, init) => {
      capturedHeaders.push(Object.fromEntries(new Headers(init?.headers ?? {}).entries()));
      return new Response(JSON.stringify({ urls: [] }), { status: 200 });
    }) as typeof fetch;

    process.env.VETLOCK_PYPI_AUTH = 'user:secret-token';

    await expect(fetchPypiArtifact({ name: 'requests', version: '2.31.0' })).rejects.toThrow(
      'contains no file URLs',
    );

    expect(capturedHeaders[0]?.authorization).toBe(
      `Basic ${Buffer.from('user:secret-token').toString('base64')}`,
    );
  });

  it('falls back to JF_AUTH when VETLOCK_PYPI_AUTH is unset', async () => {
    const capturedHeaders: Record<string, string>[] = [];
    global.fetch = vi.fn(async (_url, init) => {
      capturedHeaders.push(Object.fromEntries(new Headers(init?.headers ?? {}).entries()));
      return new Response(JSON.stringify({ urls: [] }), { status: 200 });
    }) as typeof fetch;

    process.env.JF_AUTH = 'jf-token';

    await expect(fetchPypiArtifact({ name: 'requests', version: '2.31.0' })).rejects.toThrow(
      'contains no file URLs',
    );

    expect(capturedHeaders[0]?.authorization).toBe('Bearer ' + 'jf-token');
  });

  it('sends no auth when neither env var is set', async () => {
    const capturedHeaders: Record<string, string>[] = [];
    global.fetch = vi.fn(async (_url, init) => {
      capturedHeaders.push(Object.fromEntries(new Headers(init?.headers ?? {}).entries()));
      return new Response(JSON.stringify({ urls: [] }), { status: 200 });
    }) as typeof fetch;

    await expect(fetchPypiArtifact({ name: 'requests', version: '2.31.0' })).rejects.toThrow(
      'contains no file URLs',
    );

    expect(capturedHeaders[0]?.authorization).toBeUndefined();
  });

  it('rewrites pythonhosted downloads through a configured Artifactory registry', async () => {
    const seenUrls: string[] = [];
    let artifactPath: string | undefined;
    global.fetch = vi.fn(async (url, init) => {
      seenUrls.push(String(url));
      if (seenUrls.length === 1) {
        expect(Object.fromEntries(new Headers(init?.headers ?? {}).entries()).authorization).toBe(
          'Bearer ' + 'my-token',
        );
        return new Response(
          JSON.stringify({
            urls: [
              {
                filename: 'requests-2.31.0-py3-none-any.whl',
                url: 'https://files.pythonhosted.org/packages/ab/cd/requests-2.31.0-py3-none-any.whl',
                packagetype: 'bdist_wheel',
                digests: { sha256: 'abc123' },
              },
            ],
          }),
          { status: 200 },
        );
      }
      return new Response(new Uint8Array([0x50, 0x4b, 0x03, 0x04]), { status: 200 });
    }) as typeof fetch;

    process.env.VETLOCK_PYPI_AUTH = 'my-token';

    try {
      const artifact = await fetchPypiArtifact({
        name: 'requests',
        version: '2.31.0',
        registry: 'https://lilly.jfrog.io/artifactory/api/pypi/pypi-remote',
      });
      artifactPath = artifact.path;

      expect(seenUrls[1]).toBe(
        'https://lilly.jfrog.io/artifactory/api/pypi/pypi-remote/packages/ab/cd/requests-2.31.0-py3-none-any.whl',
      );
    } finally {
      if (artifactPath) {
        await import('node:fs/promises').then((fs) => fs.unlink(artifactPath!));
      }
    }
  });
});
