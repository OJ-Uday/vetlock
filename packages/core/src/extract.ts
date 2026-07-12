/**
 * Safe tarball extraction. Enforces:
 *   - Absolute paths rejected (zip-slip class).
 *   - '..' path segments rejected (zip-slip class).
 *   - Symlinks / hardlinks rejected outright.
 *   - Per-entry byte cap (default 50 MiB).
 *   - Total extracted bytes cap (default 500 MiB) — tarbomb defense.
 *   - Entry count cap (default 10_000).
 *
 * Everything writes into a per-run temp directory that is removed in `finally`.
 * NEVER invokes any code from extracted content. See ADR 0005.
 */

import { promises as fs } from 'node:fs';
import { createReadStream } from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as crypto from 'node:crypto';
import { pipeline } from 'node:stream/promises';
import { createGunzip } from 'node:zlib';
import * as tar from 'tar';
import { Buffer } from 'node:buffer';

export class UnsafeArchiveError extends Error {
  constructor(
    message: string,
    public readonly kind:
      | 'absolute-path'
      | 'traversal'
      | 'symlink'
      | 'hardlink'
      | 'entry-too-large'
      | 'total-too-large'
      | 'entry-count-exceeded'
      | 'unknown-entry-type',
  ) {
    super(message);
    this.name = 'UnsafeArchiveError';
  }
}

export interface ExtractLimits {
  maxEntryBytes: number;
  maxTotalBytes: number;
  maxEntries: number;
}

export const DEFAULT_LIMITS: ExtractLimits = {
  maxEntryBytes: 50 * 1024 * 1024,
  maxTotalBytes: 500 * 1024 * 1024,
  maxEntries: 10_000,
};

export interface ExtractedEntry {
  relPath: string;
  bytes: number;
  sha256: string;
}

export interface ExtractResult {
  destDir: string;
  entries: ExtractedEntry[];
  cleanup: () => Promise<void>;
}

interface TarEntry {
  path: string;
  type: 'File' | 'Directory' | 'SymbolicLink' | 'Link' | string;
  size: number;
  on(evt: 'data', cb: (chunk: Buffer) => void): TarEntry;
  on(evt: 'end', cb: () => void): TarEntry;
  on(evt: 'error', cb: (err: Error) => void): TarEntry;
  resume(): void;
  pause(): void;
}

interface TarParserLike extends NodeJS.WritableStream {
  on(evt: 'entry', cb: (entry: TarEntry) => void): this;
  on(evt: 'error', cb: (err: Error) => void): this;
  emit(evt: 'error', err: unknown): boolean;
}

/**
 * Extract a .tgz into an isolated temp dir. Returns an object whose
 * `cleanup()` deletes that directory. ALWAYS call cleanup in a `finally`.
 * On any safety violation, throws UnsafeArchiveError and cleans up first.
 */
export async function safeExtract(
  tarballPath: string,
  opts: {
    limits?: ExtractLimits;
    runId?: string;
    baseTmpDir?: string;
  } = {},
): Promise<ExtractResult> {
  const limits = { ...DEFAULT_LIMITS, ...(opts.limits ?? {}) };
  const runId = opts.runId ?? crypto.randomBytes(8).toString('hex');
  const baseTmpDir =
    opts.baseTmpDir ?? path.join(os.homedir(), '.cache', 'vetlock', 'tmp');
  const destDir = path.join(baseTmpDir, runId);

  const entries: ExtractedEntry[] = [];
  let totalBytes = 0;
  let entryCount = 0;
  let firstError: Error | null = null;
  const inFlight = new Set<Promise<void>>();

  await fs.mkdir(destDir, { recursive: true });

  const TarCtor = (tar as unknown as { Parser: new (opts?: unknown) => TarParserLike }).Parser;
  const parser: TarParserLike = new TarCtor();

  const raiseError = (err: Error): void => {
    if (!firstError) firstError = err;
    parser.emit('error', err);
  };

  parser.on('entry', (entry) => {
    // Once an error has been raised, drain remaining entries without doing any work.
    if (firstError) {
      entry.resume();
      return;
    }
    entryCount++;
    if (entryCount > limits.maxEntries) {
      raiseError(
        new UnsafeArchiveError(
          `entry count > ${limits.maxEntries}`,
          'entry-count-exceeded',
        ),
      );
      entry.resume();
      return;
    }

    if (entry.type === 'SymbolicLink' || entry.type === 'Link') {
      raiseError(
        new UnsafeArchiveError(
          `${entry.type.toLowerCase()} entries are rejected: ${entry.path}`,
          entry.type === 'SymbolicLink' ? 'symlink' : 'hardlink',
        ),
      );
      entry.resume();
      return;
    }
    if (entry.type !== 'File' && entry.type !== 'Directory') {
      raiseError(
        new UnsafeArchiveError(
          `unsupported entry type ${entry.type}: ${entry.path}`,
          'unknown-entry-type',
        ),
      );
      entry.resume();
      return;
    }

    // npm tarballs consistently prefix everything with 'package/'. Strip that.
    let rel = entry.path.replace(/^\/+/, '');
    if (rel.startsWith('package/')) rel = rel.slice('package/'.length);

    if (path.isAbsolute(entry.path) || entry.path.startsWith('/')) {
      raiseError(
        new UnsafeArchiveError(
          `absolute path entry: ${entry.path}`,
          'absolute-path',
        ),
      );
      entry.resume();
      return;
    }
    if (rel.split(/[\\/]+/).some((seg) => seg === '..')) {
      raiseError(new UnsafeArchiveError(`path traversal in entry: ${entry.path}`, 'traversal'));
      entry.resume();
      return;
    }
    const target = path.resolve(destDir, rel);
    const targetRel = path.relative(destDir, target);
    if (targetRel.startsWith('..') || path.isAbsolute(targetRel)) {
      raiseError(
        new UnsafeArchiveError(
          `resolved path escapes destDir: ${entry.path}`,
          'traversal',
        ),
      );
      entry.resume();
      return;
    }

    if (entry.type === 'Directory') {
      const p = fs
        .mkdir(target, { recursive: true })
        .then(() => undefined, (err) => raiseError(err));
      inFlight.add(p);
      p.finally(() => inFlight.delete(p));
      entry.resume();
      return;
    }

    // File
    const p = writeFileEntry(entry, target, rel, limits, {
      addTotal(n: number) {
        totalBytes += n;
        if (totalBytes > limits.maxTotalBytes) {
          raiseError(
            new UnsafeArchiveError(
              `total extracted bytes > ${limits.maxTotalBytes}`,
              'total-too-large',
            ),
          );
        }
      },
      addEntry(e: ExtractedEntry) {
        entries.push(e);
      },
    }).catch((err) => raiseError(err));
    inFlight.add(p);
    p.finally(() => inFlight.delete(p));
  });

  try {
    await pipeline(createReadStream(tarballPath), createGunzip(), parser);
    // Drain any pending file writes AFTER the parser has finished.
    await settleAll(inFlight);
    if (firstError) throw firstError;
    return { destDir, entries, cleanup: () => removeDir(destDir) };
  } catch (err) {
    await settleAll(inFlight);
    await removeDir(destDir);
    throw firstError ?? err;
  }
}

async function settleAll(set: Set<Promise<void>>): Promise<void> {
  // Snapshot then await; new arrivals during await are gathered too.
  while (set.size > 0) {
    const snap = [...set];
    await Promise.allSettled(snap);
  }
}

async function writeFileEntry(
  entry: TarEntry,
  targetPath: string,
  relPath: string,
  limits: ExtractLimits,
  hooks: {
    addTotal(n: number): void;
    addEntry(e: ExtractedEntry): void;
  },
): Promise<void> {
  await fs.mkdir(path.dirname(targetPath), { recursive: true });
  const chunks: Buffer[] = [];
  let bytes = 0;
  const hasher = crypto.createHash('sha256');
  await new Promise<void>((resolve, reject) => {
    entry.on('data', (chunk) => {
      bytes += chunk.length;
      if (bytes > limits.maxEntryBytes) {
        reject(
          new UnsafeArchiveError(
            `entry '${relPath}' exceeds ${limits.maxEntryBytes} bytes`,
            'entry-too-large',
          ),
        );
        return;
      }
      hasher.update(chunk);
      chunks.push(chunk);
    });
    entry.on('end', () => resolve());
    entry.on('error', (err) => reject(err));
  });
  hooks.addTotal(bytes);
  await fs.writeFile(targetPath, Buffer.concat(chunks));
  hooks.addEntry({
    relPath,
    bytes,
    sha256: hasher.digest('hex'),
  });
}

async function removeDir(dir: string): Promise<void> {
  try {
    await fs.rm(dir, { recursive: true, force: true });
  } catch {
    /* best-effort */
  }
}
