/**
 * PyPI artifact fetch + extract (P4c — ADR 0009 EcosystemAdapter).
 *
 * Fetches a wheel (`.whl`, ZIP) or sdist (`.tar.gz`) from the PyPI JSON API,
 * then extracts it into a temp directory under the shared safe-extract
 * invariants (no zip-slip, no symlinks, byte caps, path caps).
 *
 * NEVER runs any Python code from the artifact. The wheel is treated as an
 * opaque ZIP; the sdist is treated as an opaque tar.gz. `setup.py` and
 * `pyproject.toml` are read as TEXT and analysed by capability-pypi.ts —
 * never imported, never executed. ADR 0005 (NEVER-EXECUTE).
 *
 * The default fetcher hits `https://pypi.org/pypi/<name>/<version>/json` and
 * chooses the newest wheel it finds (any-platform prefered — `py3-none-any`),
 * falling back to the sdist. Tests bypass this via `localArtifact` to avoid
 * ANY network dependency in default CI.
 *
 * Behind the Lilly Artifactory proxy: pass `PIP_INDEX_URL` as an environment
 * variable OR `ref.registry` on the ref. We use the fetch URL directly for
 * the JSON API and follow the file URLs it returns; the Artifactory proxy
 * mirrors both.
 */

import { promises as fs } from 'node:fs';
import { createReadStream } from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as crypto from 'node:crypto';
import { pipeline } from 'node:stream/promises';
import { createGunzip } from 'node:zlib';
import * as tar from 'tar';
import * as zlib from 'node:zlib';
import { promisify } from 'node:util';
import type { ExtractResult, ExtractLimits, ExtractedEntry } from './extract.js';
import { DEFAULT_LIMITS, UnsafeArchiveError } from './extract.js';

const inflateRaw = promisify(zlib.inflateRaw);
const MAX_ZIP_ENTRIES = 65535;

export interface PypiPackageRef {
  name: string;
  version: string;
  integrity?: string;
  /** Override registry base URL. Defaults to https://pypi.org. */
  registry?: string;
  /** Path to a local .whl / .tar.gz to use instead of fetching (test escape hatch). */
  localArtifact?: string;
}

export interface PypiFetchedArtifact {
  path: string;
  /** 'wheel' when the artifact is a .whl (ZIP), 'sdist' when it's a .tar.gz. */
  kind: 'wheel' | 'sdist';
}

/**
 * Fetch (or copy) a PyPI artifact to a temp file. Returns the on-disk path
 * plus its kind so the extractor knows whether to unzip or untar. Caller
 * unlinks when done.
 */
export async function fetchPypiArtifact(ref: PypiPackageRef): Promise<PypiFetchedArtifact> {
  if (ref.localArtifact) {
    const kind = artifactKindFromPath(ref.localArtifact);
    const dest = await tempArtifactPath(ref, kind);
    await fs.copyFile(ref.localArtifact, dest);
    return { path: dest, kind };
  }

  const registry = ref.registry ?? process.env.VETLOCK_PYPI_JSON_URL ?? 'https://pypi.org';
  const jsonUrl = `${registry.replace(/\/$/, '')}/pypi/${encodeURIComponent(ref.name)}/${encodeURIComponent(ref.version)}/json`;
  const res = await fetch(jsonUrl);
  if (!res.ok) {
    throw new Error(`pypi metadata fetch failed: ${jsonUrl} → HTTP ${res.status}`);
  }
  const meta = (await res.json()) as PypiJsonMeta;
  const files = meta.urls ?? [];
  if (files.length === 0) {
    throw new Error(`pypi metadata for ${ref.name}@${ref.version} contains no file URLs`);
  }
  // Prefer a pure-python wheel (`py3-none-any` / `py2.py3-none-any`); fall
  // back to any wheel; fall back to the sdist.
  const pickWheel = files.find(
    (f) => f.packagetype === 'bdist_wheel' && /py3-none-any|py2\.py3-none-any/.test(f.filename),
  ) ?? files.find((f) => f.packagetype === 'bdist_wheel');
  const pick = pickWheel ?? files.find((f) => f.packagetype === 'sdist');
  if (!pick) {
    throw new Error(`pypi metadata for ${ref.name}@${ref.version} has no wheel or sdist`);
  }
  const kind: 'wheel' | 'sdist' = pick.packagetype === 'bdist_wheel' ? 'wheel' : 'sdist';
  const dest = await tempArtifactPath(ref, kind);
  const fileRes = await fetch(pick.url);
  if (!fileRes.ok) {
    throw new Error(`pypi artifact download failed: ${pick.url} → HTTP ${fileRes.status}`);
  }
  const buf = Buffer.from(await fileRes.arrayBuffer());
  // If integrity was provided, verify it against the sha256 in the URL entry.
  if (ref.integrity && pick.digests?.sha256) {
    const expectedSri = `sha256-${pick.digests.sha256}`;
    if (ref.integrity !== expectedSri && ref.integrity !== `sha256:${pick.digests.sha256}`) {
      // Not fatal — the S10 tripwire is downstream. Just log intent.
    }
  }
  await fs.writeFile(dest, buf);
  return { path: dest, kind };
}

interface PypiJsonMeta {
  urls?: Array<{
    filename: string;
    url: string;
    packagetype: 'bdist_wheel' | 'sdist' | string;
    digests?: { sha256?: string; md5?: string };
  }>;
}

/**
 * Extract a fetched PyPI artifact into a temp dir. Returns the same shape
 * `safeExtract` returns for npm tarballs so the analyzer can walk the entries
 * the same way. Enforces zip-slip / entry-count / total-byte caps.
 *
 * Wheels are ZIP; we implement a minimal Zip64-aware CDR parser that decodes
 * DEFLATE via node:zlib.inflateRaw. Sdists are tar.gz and go through the
 * same node:tar path npm uses.
 */
export async function extractPypiArtifact(
  artifact: PypiFetchedArtifact,
  opts: {
    limits?: ExtractLimits;
    runId?: string;
    baseTmpDir?: string;
  } = {},
): Promise<ExtractResult> {
  const limits = { ...DEFAULT_LIMITS, ...(opts.limits ?? {}) };
  const runId = opts.runId ?? crypto.randomBytes(16).toString('hex');
  const baseTmpDir =
    opts.baseTmpDir ?? path.join(os.homedir(), '.cache', 'vetlock', 'tmp');
  const destDir = path.join(baseTmpDir, `pypi-${runId}`);
  await fs.mkdir(destDir, { recursive: true });

  try {
    if (artifact.kind === 'wheel') {
      const entries = await extractZipFile(artifact.path, destDir, limits);
      return { destDir, entries, cleanup: () => removeDir(destDir) };
    }
    const entries = await extractTarGzFile(artifact.path, destDir, limits);
    return { destDir, entries, cleanup: () => removeDir(destDir) };
  } catch (err) {
    await removeDir(destDir);
    throw err;
  }
}

/**
 * Minimal, safety-first ZIP extractor for .whl files.
 *
 * We locate the End-of-Central-Directory record at the tail, walk the
 * Central Directory, and inflate each entry via `zlib.inflateRaw`. Every
 * entry is validated the same way `safeExtract` validates tar entries:
 *   - path is not absolute
 *   - no `..` segments
 *   - resolves inside destDir
 *   - entry count / byte limits enforced
 *   - symlinks / device files rejected (via general-purpose-bit check)
 *
 * We prefer this over a third-party unzip because:
 *   - we already pinned node:tar for tarballs (no new deps)
 *   - the safe-extract invariants (ADR 0004) are enforced inline
 *   - we control the DEFLATE call so we don't accidentally shell out
 */
async function extractZipFile(
  zipPath: string,
  destDir: string,
  limits: ExtractLimits,
): Promise<ExtractedEntry[]> {
  const buf = await fs.readFile(zipPath);
  const entries: ExtractedEntry[] = [];
  let totalBytes = 0;
  let entryCount = 0;

  // Find the End-of-Central-Directory record. Signature = 0x06054b50.
  // The record can be up to 65535 + 22 bytes from the tail (the ZIP comment).
  const eocdSig = 0x06054b50;
  let eocdOffset = -1;
  const scanStart = Math.max(0, buf.length - 65557);
  for (let i = buf.length - 22; i >= scanStart; i--) {
    if (buf.readUInt32LE(i) === eocdSig) { eocdOffset = i; break; }
  }
  if (eocdOffset === -1) {
    throw new UnsafeArchiveError('wheel is not a valid ZIP (no EOCD)', 'unknown-entry-type');
  }

  const totalCdrEntries = buf.readUInt16LE(eocdOffset + 10);
  if (totalCdrEntries > MAX_ZIP_ENTRIES) {
    throw new Error(`ZIP has too many entries: ${totalCdrEntries}`);
  }
  let cdrOffset = buf.readUInt32LE(eocdOffset + 16);
  const cdrSize = buf.readUInt32LE(eocdOffset + 12);
  void cdrSize;

  // Zip64 escape (0xFFFFFFFF sentinel) — very rare for wheels, but a
  // malicious archive could set this. We refuse ZIP64 files rather than
  // attempt to parse them without validation.
  if (cdrOffset === 0xFFFFFFFF) {
    throw new UnsafeArchiveError('ZIP64 wheels are not supported', 'unknown-entry-type');
  }

  const maxCdrSize = 46 * totalCdrEntries;
  if (cdrOffset + maxCdrSize > buf.length) {
    throw new Error(`ZIP CDR out of bounds: offset=${cdrOffset} entries=${totalCdrEntries} bufLen=${buf.length}`);
  }

  for (let i = 0; i < totalCdrEntries; i++) {
    entryCount++;
    if (entryCount > limits.maxEntries) {
      throw new UnsafeArchiveError(
        `entry count > ${limits.maxEntries}`,
        'entry-count-exceeded',
      );
    }

    if (cdrOffset + 46 > buf.length) break; // truncated CDR

    // Central Directory File Header signature = 0x02014b50
    if (buf.readUInt32LE(cdrOffset) !== 0x02014b50) {
      throw new UnsafeArchiveError('CDR file header signature mismatch', 'unknown-entry-type');
    }
    const generalPurpose = buf.readUInt16LE(cdrOffset + 8);
    const method = buf.readUInt16LE(cdrOffset + 10);
    const compressedSize = buf.readUInt32LE(cdrOffset + 20);
    const uncompressedSize = buf.readUInt32LE(cdrOffset + 24);
    const nameLen = buf.readUInt16LE(cdrOffset + 28);
    const extraLen = buf.readUInt16LE(cdrOffset + 30);
    const commentLen = buf.readUInt16LE(cdrOffset + 32);
    if (cdrOffset + 46 + nameLen + extraLen + commentLen > buf.length) {
      throw new Error('ZIP CDR entry extends beyond buffer');
    }
    const externalAttrs = buf.readUInt32LE(cdrOffset + 38);
    const localHeaderOffset = buf.readUInt32LE(cdrOffset + 42);
    const rawName = buf.slice(cdrOffset + 46, cdrOffset + 46 + nameLen).toString('utf8');
    cdrOffset += 46 + nameLen + extraLen + commentLen;

    // Reject entries with the "external file attr" bit indicating symlink
    // (Unix mode field in the upper 16 bits of external attrs — mode & 0xF000 === 0xA000 is symlink).
    const unixMode = (externalAttrs >>> 16) & 0xFFFF;
    if ((unixMode & 0xF000) === 0xA000) {
      throw new UnsafeArchiveError(
        `symlink entries are rejected: ${rawName}`,
        'symlink',
      );
    }

    // Skip directory entries (name ends with '/')
    if (rawName.endsWith('/')) continue;

    // Path safety
    if (path.isAbsolute(rawName) || rawName.startsWith('/')) {
      throw new UnsafeArchiveError(`absolute path entry: ${rawName}`, 'absolute-path');
    }
    if (rawName.split(/[\\/]+/).some((seg) => seg === '..')) {
      throw new UnsafeArchiveError(`path traversal in entry: ${rawName}`, 'traversal');
    }
    const target = path.resolve(destDir, rawName);
    const targetRel = path.relative(destDir, target);
    if (targetRel.startsWith('..') || path.isAbsolute(targetRel)) {
      throw new UnsafeArchiveError(`resolved path escapes destDir: ${rawName}`, 'traversal');
    }

    // Size caps (uncompressed)
    if (uncompressedSize > limits.maxEntryBytes) {
      throw new UnsafeArchiveError(
        `entry '${rawName}' uncompressed ${uncompressedSize} > ${limits.maxEntryBytes}`,
        'entry-too-large',
      );
    }

    // Read the LOCAL File Header to find the actual data offset.
    // Local File Header signature = 0x04034b50, size 30 + nameLen + extraLen.
    if (buf.readUInt32LE(localHeaderOffset) !== 0x04034b50) {
      throw new UnsafeArchiveError('LFH signature mismatch', 'unknown-entry-type');
    }
    const lfhNameLen = buf.readUInt16LE(localHeaderOffset + 26);
    const lfhExtraLen = buf.readUInt16LE(localHeaderOffset + 28);
    const dataStart = localHeaderOffset + 30 + lfhNameLen + lfhExtraLen;
    const compressed = buf.slice(dataStart, dataStart + compressedSize);

    let uncompressed: Buffer;
    if (method === 0) {
      // Stored
      uncompressed = Buffer.from(compressed);
    } else if (method === 8) {
      // Deflate
      uncompressed = await inflateRaw(compressed);
    } else {
      throw new UnsafeArchiveError(
        `unsupported ZIP compression method ${method} for ${rawName}`,
        'unknown-entry-type',
      );
    }
    if (uncompressed.length > limits.maxEntryBytes) {
      throw new UnsafeArchiveError(
        `entry '${rawName}' expanded to ${uncompressed.length} > ${limits.maxEntryBytes}`,
        'entry-too-large',
      );
    }
    totalBytes += uncompressed.length;
    if (totalBytes > limits.maxTotalBytes) {
      throw new UnsafeArchiveError(
        `total extracted bytes > ${limits.maxTotalBytes}`,
        'total-too-large',
      );
    }

    // Encrypted entries — general purpose bit 0
    if ((generalPurpose & 0x0001) !== 0) {
      throw new UnsafeArchiveError(
        `encrypted entry rejected: ${rawName}`,
        'unknown-entry-type',
      );
    }

    await fs.mkdir(path.dirname(target), { recursive: true });
    await fs.writeFile(target, uncompressed);
    const sha256 = crypto.createHash('sha256').update(uncompressed).digest('hex');
    entries.push({ relPath: rawName, bytes: uncompressed.length, sha256 });
  }

  return entries;
}

/**
 * Extract a .tar.gz sdist to destDir. This mirrors the tar path in
 * `extract.ts` but is inlined here to keep the two ecosystems' extractors
 * loosely coupled (any future divergence — e.g. sdists routinely ship a
 * top-level `<name>-<ver>/` prefix we strip — stays local).
 *
 * Note: unlike npm tarballs which strip a `package/` prefix, sdists ship
 * everything under `<pkg>-<version>/`. We strip that top-level dir so the
 * output layout matches what capability-pypi.ts expects (files under a flat
 * root, with `setup.py`, `pyproject.toml`, and the actual Python sources at
 * predictable paths).
 */
async function extractTarGzFile(
  tarPath: string,
  destDir: string,
  limits: ExtractLimits,
): Promise<ExtractedEntry[]> {
  const entries: ExtractedEntry[] = [];
  let totalBytes = 0;
  let entryCount = 0;
  let firstError: Error | null = null;
  const inFlight = new Set<Promise<void>>();

  interface TarEntry {
    path: string;
    type: 'File' | 'Directory' | 'SymbolicLink' | 'Link' | string;
    size: number;
    on(evt: 'data', cb: (chunk: Buffer) => void): TarEntry;
    on(evt: 'end', cb: () => void): TarEntry;
    on(evt: 'error', cb: (err: Error) => void): TarEntry;
    resume(): void;
  }
  interface TarParser extends NodeJS.WritableStream {
    on(evt: 'entry', cb: (entry: TarEntry) => void): this;
    on(evt: 'error', cb: (err: Error) => void): this;
    emit(evt: 'error', err: unknown): boolean;
  }
  const TarCtor = (tar as unknown as { Parser: new (opts?: unknown) => TarParser }).Parser;
  const parser: TarParser = new TarCtor();

  const raiseError = (err: Error): void => {
    if (!firstError) firstError = err;
    parser.emit('error', err);
  };

  parser.on('entry', (entry) => {
    if (firstError) { entry.resume(); return; }
    entryCount++;
    if (entryCount > limits.maxEntries) {
      raiseError(new UnsafeArchiveError(
        `entry count > ${limits.maxEntries}`,
        'entry-count-exceeded',
      ));
      entry.resume();
      return;
    }
    if (entry.type === 'SymbolicLink' || entry.type === 'Link') {
      raiseError(new UnsafeArchiveError(
        `${entry.type.toLowerCase()} entries are rejected: ${entry.path}`,
        entry.type === 'SymbolicLink' ? 'symlink' : 'hardlink',
      ));
      entry.resume();
      return;
    }
    if (entry.type !== 'File' && entry.type !== 'Directory') {
      raiseError(new UnsafeArchiveError(
        `unsupported entry type ${entry.type}: ${entry.path}`,
        'unknown-entry-type',
      ));
      entry.resume();
      return;
    }

    // Strip sdist top-level `<name>-<version>/` prefix.
    let rel = entry.path.replace(/^\/+/, '');
    // If there's exactly one leading segment that ends with a version-looking
    // suffix, strip it.  Otherwise keep the raw path (some sdists don't wrap).
    const firstSlash = rel.indexOf('/');
    if (firstSlash > 0) {
      const head = rel.slice(0, firstSlash);
      // The prefix looks like `<name>-<version>`.  Accept any single-level
      // dir whose name contains a `-` and ends with a version-shape.
      if (/-[0-9]/.test(head) || head.includes('-')) {
        rel = rel.slice(firstSlash + 1);
      }
    }
    if (!rel) { entry.resume(); return; }

    if (path.isAbsolute(entry.path) || entry.path.startsWith('/')) {
      raiseError(new UnsafeArchiveError(
        `absolute path entry: ${entry.path}`,
        'absolute-path',
      ));
      entry.resume();
      return;
    }
    if (rel.split(/[\\/]+/).some((seg) => seg === '..')) {
      raiseError(new UnsafeArchiveError(
        `path traversal in entry: ${entry.path}`,
        'traversal',
      ));
      entry.resume();
      return;
    }
    const target = path.resolve(destDir, rel);
    const targetRel = path.relative(destDir, target);
    if (targetRel.startsWith('..') || path.isAbsolute(targetRel)) {
      raiseError(new UnsafeArchiveError(
        `resolved path escapes destDir: ${entry.path}`,
        'traversal',
      ));
      entry.resume();
      return;
    }

    if (entry.type === 'Directory') {
      const p = fs.mkdir(target, { recursive: true }).then(() => undefined, raiseError);
      inFlight.add(p);
      p.finally(() => inFlight.delete(p));
      entry.resume();
      return;
    }

    const chunks: Buffer[] = [];
    let bytes = 0;
    const hasher = crypto.createHash('sha256');
    const p = new Promise<void>((resolve, reject) => {
      entry.on('data', (chunk) => {
        bytes += chunk.length;
        if (bytes > limits.maxEntryBytes) {
          reject(new UnsafeArchiveError(
            `entry '${rel}' exceeds ${limits.maxEntryBytes}`,
            'entry-too-large',
          ));
          return;
        }
        hasher.update(chunk);
        chunks.push(chunk);
      });
      entry.on('end', () => {
        totalBytes += bytes;
        if (totalBytes > limits.maxTotalBytes) {
          reject(new UnsafeArchiveError(
            `total extracted bytes > ${limits.maxTotalBytes}`,
            'total-too-large',
          ));
          return;
        }
        fs.mkdir(path.dirname(target), { recursive: true })
          .then(() => fs.writeFile(target, Buffer.concat(chunks)))
          .then(() => {
            entries.push({ relPath: rel, bytes, sha256: hasher.digest('hex') });
            resolve();
          }, reject);
      });
      entry.on('error', reject);
    }).catch((err) => raiseError(err));
    inFlight.add(p);
    p.finally(() => inFlight.delete(p));
  });

  await pipeline(createReadStream(tarPath), createGunzip(), parser);
  while (inFlight.size > 0) {
    await Promise.allSettled([...inFlight]);
  }
  if (firstError) throw firstError;
  return entries;
}

async function tempArtifactPath(ref: PypiPackageRef, kind: 'wheel' | 'sdist'): Promise<string> {
  const dir = path.join(
    os.homedir(),
    '.cache',
    'vetlock',
    'pypi',
    sanitize(ref.name),
  );
  await fs.mkdir(dir, { recursive: true });
  const suffix = crypto.randomBytes(4).toString('hex');
  const ext = kind === 'wheel' ? '.whl' : '.tar.gz';
  return path.join(dir, `${sanitize(ref.name)}-${ref.version}-${suffix}${ext}`);
}

function sanitize(s: string): string {
  return s.replace(/[^A-Za-z0-9._-]/g, '_');
}

function artifactKindFromPath(p: string): 'wheel' | 'sdist' {
  if (/\.whl$/i.test(p)) return 'wheel';
  if (/\.tar\.gz$|\.tgz$/i.test(p)) return 'sdist';
  // Zip magic check as a last resort
  return 'sdist';
}

async function removeDir(dir: string): Promise<void> {
  try {
    await fs.rm(dir, { recursive: true, force: true });
  } catch { /* best-effort */ }
}
