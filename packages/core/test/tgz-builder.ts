/**
 * Test helper: build tarballs in memory / on disk with arbitrary layouts,
 * including malicious shapes (absolute paths, symlinks, tarbombs) that we
 * cannot construct with the normal high-level tar API.
 *
 * This is TEST INFRASTRUCTURE — it lives in packages/core/test/, is
 * never shipped to users, and only exists to prove our extractor rejects
 * these shapes.
 */

import { promises as fs } from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as zlib from 'node:zlib';
import { Buffer } from 'node:buffer';
import * as crypto from 'node:crypto';

export interface TarEntrySpec {
  name: string;
  content?: Buffer;
  /** 'file'|'dir'|'symlink'|'hardlink' */
  type?: 'file' | 'dir' | 'symlink' | 'hardlink';
  /** target for symlinks/hardlinks */
  linkName?: string;
  /** Override mode bits (default 0o644 for files, 0o755 for dirs) */
  mode?: number;
  /** Override entry size (for tarbomb tests — huge apparent size). */
  claimedSize?: number;
}

const TYPE_FLAGS = {
  file: '0',
  dir: '5',
  symlink: '2',
  hardlink: '1',
} as const;

/** Build a POSIX ustar tarball from the given specs, gzip-wrap, return bytes. */
export function makeTgz(entries: TarEntrySpec[]): Buffer {
  const parts: Buffer[] = [];
  for (const e of entries) {
    parts.push(buildEntry(e));
  }
  parts.push(Buffer.alloc(1024)); // two 512-byte end blocks
  const tar = Buffer.concat(parts);
  return zlib.gzipSync(tar);
}

function buildEntry(e: TarEntrySpec): Buffer {
  const type: 'file' | 'dir' | 'symlink' | 'hardlink' = e.type ?? 'file';
  const content = type === 'file' ? e.content ?? Buffer.alloc(0) : Buffer.alloc(0);
  const size = e.claimedSize ?? content.length;
  const mode = e.mode ?? (type === 'dir' ? 0o755 : 0o644);

  const header = Buffer.alloc(512);
  writeStr(header, e.name.slice(0, 100), 0, 100);
  writeOct(header, mode, 100, 8);
  writeOct(header, 0, 108, 8); // uid
  writeOct(header, 0, 116, 8); // gid
  writeOct(header, size, 124, 12);
  writeOct(header, Math.floor(Date.now() / 1000), 136, 12);
  writeStr(header, '        ', 148, 8); // checksum placeholder
  writeStr(header, TYPE_FLAGS[type], 156, 1);
  if (e.linkName) {
    writeStr(header, e.linkName.slice(0, 100), 157, 100);
  }
  writeStr(header, 'ustar', 257, 6);
  writeStr(header, '00', 263, 2);
  // recompute checksum: sum of all bytes, treating checksum field as 8 spaces
  let cksum = 0;
  for (let i = 0; i < 512; i++) cksum += header[i]!;
  writeOct(header, cksum, 148, 8);

  const contentPadded = pad512(content);
  return Buffer.concat([header, contentPadded]);
}

function pad512(buf: Buffer): Buffer {
  const rem = buf.length % 512;
  if (rem === 0) return buf;
  return Buffer.concat([buf, Buffer.alloc(512 - rem)]);
}

function writeStr(buf: Buffer, s: string, off: number, len: number): void {
  buf.write(s, off, len, 'utf8');
}

function writeOct(buf: Buffer, n: number, off: number, len: number): void {
  const octal = n.toString(8);
  // ustar convention: <7 octal digits><NUL>
  const padded = octal.padStart(len - 1, '0');
  buf.write(padded, off, len - 1, 'ascii');
  buf.writeUInt8(0, off + len - 1);
}

/**
 * Write a tgz built from specs to a real tmp file, return its path.
 * Caller is responsible for cleanup via the tmp dir (or ignore — /tmp).
 */
export async function writeTempTgz(entries: TarEntrySpec[]): Promise<string> {
  const tgz = makeTgz(entries);
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'vetlock-test-'));
  const p = path.join(dir, `${crypto.randomBytes(4).toString('hex')}.tgz`);
  await fs.writeFile(p, tgz);
  return p;
}
