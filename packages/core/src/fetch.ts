/**
 * Fetch a package tarball to disk via pacote.
 *
 * We use pacote in "tarball only" mode: pacote.tarball(spec) fetches the tarball
 * bytes but does not extract or install. Extraction is ours (see extract.ts) to
 * enforce our safety invariants.
 *
 * NEVER executes any code from the package. ADR 0005.
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
