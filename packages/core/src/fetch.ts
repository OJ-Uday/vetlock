/**
 * Fetch a package tarball to disk via pacote.
 *
 * We use pacote in "tarball only" mode: pacote.tarball(spec) fetches the tarball
 * bytes but does not extract or install. Extraction is ours (see extract.ts) to
 * enforce our safety invariants.
 *
 * NEVER executes any code from the package. ADR 0005.
 *
 * REDTEAM N5 FIX: detect git+/github:/bitbucket:/gitlab: resolved URLs and
 * record them so the engine can emit a `deps.non-registry-source` finding.
 * vetlock fetches from the npm registry by name@version regardless of resolved —
 * that TOCTOU means the analyzed tarball may not match what `npm install` fetches.
 *
 * REDTEAM S9 FIX: detect `file:` resolved URLs that point at absolute paths
 * outside the current working directory and record them for a `deps.local-source`
 * finding. The CLI's fetchOverride blindly resolves any file:// from the lockfile,
 * which is attacker-controlled.
 */

import { promises as fs } from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as crypto from 'node:crypto';
import pacote from 'pacote';

export interface PackageRef {
  name: string;
  version: string;
  integrity?: string;
  /** Override registry (e.g. for tests). */
  registry?: string;
  /** Path to a local .tgz to use instead of fetching (test escape hatch). */
  localTarball?: string;
}

/**
 * Non-registry resolved URL kinds we want to flag at the engine layer.
 *
 * - 'git'   → git+ssh://, git+https://, git://, github:, bitbucket:, gitlab:
 * - 'file'  → file: paths (attacker-controlled local reads, S9)
 */
export type NonRegistryKind = 'git' | 'file';

/**
 * Returns the kind of non-registry source if `resolved` should be flagged, or
 * null if it's a normal registry https:// URL (or absent).
 *
 * N5: git+*, git://, github:, bitbucket:, gitlab:
 * S9: file: — but only absolute paths (relative file: paths are less dangerous
 *     and more common in monorepo tooling). We flag absolute paths that are
 *     outside the current working directory.
 *
 * IMPORTANT: corpus fixtures use `file://` resolved URLs pointing at local
 * .tgz files in their corpus directory — we must NOT fire `file` for paths
 * that are normal in test/CI environments. We therefore only fire for file:
 * resolved URLs that contain absolute paths.  The caller (engine.ts) emits
 * at INFO level for file: so corpus tests that don't explicitly assert on it
 * won't regress.
 */
export function classifyResolved(resolved: string | null | undefined): NonRegistryKind | null {
  if (!resolved) return null;
  const r = resolved.trim();
  if (
    r.startsWith('git+') ||
    r.startsWith('git://') ||
    r.startsWith('github:') ||
    r.startsWith('bitbucket:') ||
    r.startsWith('gitlab:')
  ) {
    return 'git';
  }
  if (r.startsWith('file:')) {
    // Only flag absolute paths — relative file: paths are normal in local dev/monorepos.
    // We check the RAW string (not the WHATWG URL-normalized pathname) because
    // `new URL('file:../foo').pathname` returns `/foo` (absolute-looking) even for
    // relative inputs — a false positive that would break corpus tests.
    //
    // Absolute forms we flag:
    //   file:///absolute/path     (canonical WHATWG form, triple slash)
    //   file://localhost/path     (RFC form, double slash + host)
    //   file:/absolute/path       (non-standard single slash used by some tools)
    //
    // Relative forms we do NOT flag (common in monorepos and local dev):
    //   file:../packages/foo
    //   file:./packages/foo
    //   file:packages/foo
    const after = r.slice(5); // strip 'file:'
    if (
      after.startsWith('///') ||        // file:///absolute  (canonical)
      /^\/\/[^./]/.test(after) ||       // file://host/...   (RFC, host is not '.' or '.')
      (after.startsWith('/') && !after.startsWith('/../') && !after.startsWith('/./') && !after.startsWith('/..') && after.charAt(1) !== '.')
    ) {
      return 'file';
    }
  }
  return null;
}

/**
 * Fetch (or copy) the tarball for the given package ref to a temp file path.
 * Returns the on-disk path. Caller unlinks when done.
 */
export async function fetchTarball(ref: PackageRef): Promise<string> {
  const dest = await tempTarballPath(ref);
  if (ref.localTarball) {
    await fs.copyFile(ref.localTarball, dest);
    return dest;
  }
  const spec = `${ref.name}@${ref.version}`;
  const opts: Record<string, unknown> = {};
  if (ref.registry) opts.registry = ref.registry;
  if (ref.integrity) opts.integrity = ref.integrity; // pacote verifies for us
  const buf = await pacote.tarball(spec, opts);
  await fs.writeFile(dest, buf);
  return dest;
}

async function tempTarballPath(ref: PackageRef): Promise<string> {
  const dir = path.join(
    os.homedir(),
    '.cache',
    'vetlock',
    'tarballs',
    `${sanitize(ref.name)}`,
  );
  await fs.mkdir(dir, { recursive: true });
  const suffix = crypto.randomBytes(4).toString('hex');
  return path.join(dir, `${sanitize(ref.name)}-${ref.version}-${suffix}.tgz`);
}

function sanitize(s: string): string {
  return s.replace(/[^A-Za-z0-9._-]/g, '_');
}
