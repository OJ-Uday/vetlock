/**
 * gzip-bomb — assurance generators for gzip-stream safety.
 *
 * A gzip stream can attack the scanner two ways:
 *   1. High compression ratio — a small (<1 KB) gzip that decompresses to many MB. If the
 *      scanner reads the decompressed stream into memory without a safe cap, the attacker
 *      trades ~1 KB of input for hundreds of MB of RAM. The safe cap is enforced by the
 *      extractor (packages/core/src/extract.ts: DEFAULT_LIMITS.maxTotalBytes = 500 MiB).
 *   2. Invalid gzip header — malformed magic bytes or a truncated stream. A resilient
 *      parser reports a clean error; a fragile one crashes with a native `Error` that
 *      escapes any surrounding try-catch (zlib errors are notoriously verbose).
 *
 * PACKET §2.1: the scanner's decompression path is a first-class target. This generator
 * ships hostile gzips the scanner must handle without: (a) unbounded memory growth,
 * (b) native aborts, (c) silent success on truncated input.
 *
 * BOUNDEDNESS: every produced fixture is <250 KB on disk (well under the packet's
 * <1 MB requirement). High-ratio inputs decompress against the extractor's cap, not
 * against unlimited memory — the extractor's job is to stop early. Invalid-header inputs
 * are already tiny.
 *
 * Deterministic. Same (seed, mode, scale) → identical bytes.
 */

import { Buffer } from 'node:buffer';
import * as zlib from 'node:zlib';

/** Which pathology this fixture embodies. */
export type GzipBombMode = 'high-ratio' | 'invalid-header';

/** Scale controls the aggressiveness of the pathology. */
export type GzipBombScale = 'baseline' | 'stress';

export interface GzipBombParams {
  readonly mode: GzipBombMode;
  readonly scale?: GzipBombScale;
}

export interface GzipBombInput {
  /** The .tgz-shaped bytes to write to disk before feeding to analyzeTarball. */
  readonly bytes: Buffer;
  /** Suggested filename hint. */
  readonly filename: string;
  /** Human-readable label. */
  readonly description: string;
  /** Echo of the params. */
  readonly mode: GzipBombMode;
  readonly scale: GzipBombScale;
  /** For 'high-ratio' inputs: how large the decompressed inner tar would be. Purely
   *  descriptive — the fixture on disk is small; this is what a naive extractor would
   *  attempt to hold in RAM. */
  readonly decompressedBytesClaim?: number;
}

export interface GzipBombGenerator {
  readonly id: string;
  readonly description: string;
  generate(seed: number, params: GzipBombParams): GzipBombInput;
}

// ------------------------------------------------------------------------------------------
// Minimal tar helper — we need to build a REAL tar payload (a stream of null bytes
// compresses to almost nothing) for high-ratio; we don't need the full ustar-builder
// surface from tar-bomb.ts, and cross-file re-use in .ts would drag a shared header file
// this branch shouldn't grow.  A single "big-nulls" file with a bogus ustar header suffices.
// ------------------------------------------------------------------------------------------

function makeInnerTarPayload(sizeBytes: number): Buffer {
  // Build a fake tar with one 'File' entry of `sizeBytes` all-NUL content. The gzip DEFLATE
  // algorithm reduces runs of identical bytes to a tiny back-reference, so this compresses
  // to ~100 bytes regardless of `sizeBytes` — exactly the pathology we want to reproduce.
  const header = Buffer.alloc(512);
  writeStr(header, 'package/big.bin'.slice(0, 100), 0, 100);
  writeOct(header, 0o644, 100, 8);
  writeOct(header, 0, 108, 8);
  writeOct(header, 0, 116, 8);
  writeOct(header, sizeBytes, 124, 12);
  writeOct(header, 0, 136, 12);
  writeStr(header, '        ', 148, 8);
  writeStr(header, '0', 156, 1);
  writeStr(header, 'ustar', 257, 6);
  writeStr(header, '00', 263, 2);
  let cksum = 0;
  for (let i = 0; i < 512; i++) cksum += header[i]!;
  writeOct(header, cksum, 148, 8);

  const content = Buffer.alloc(sizeBytes); // all zeros — huge compression ratio
  const contentPadded = pad512(content);
  const terminator = Buffer.alloc(1024); // two 512-byte end blocks
  return Buffer.concat([header, contentPadded, terminator]);
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
  const padded = octal.padStart(len - 1, '0');
  buf.write(padded, off, len - 1, 'ascii');
  buf.writeUInt8(0, off + len - 1);
}

// ------------------------------------------------------------------------------------------
// mode builders
// ------------------------------------------------------------------------------------------

/** High-ratio: a small gzip whose decompressed inner tar is very large. */
function buildHighRatio(scale: GzipBombScale): { bytes: Buffer; decompressedBytes: number } {
  // baseline: 5 MiB decompressed — well under the extractor's 500 MiB total-cap, so the
  // extractor should handle it (but the per-entry cap of 50 MiB is still safe).
  // stress: 100 MiB decompressed — still under the 500 MiB total cap on defaults, but
  // above the 50 MiB per-entry cap → tests that per-entry cap fires.
  const decompressedBytes = scale === 'stress' ? 100 * 1024 * 1024 : 5 * 1024 * 1024;
  const innerTar = makeInnerTarPayload(decompressedBytes);
  // Best-compression → highest ratio (all-zeros → ~100 B output for any input size).
  const gzipped = zlib.gzipSync(innerTar, { level: zlib.constants.Z_BEST_COMPRESSION });
  return { bytes: gzipped, decompressedBytes };
}

/** Invalid-header: bytes that CANNOT be a gzip stream. Parser should fail cleanly. */
function buildInvalidHeader(scale: GzipBombScale): Buffer {
  if (scale === 'stress') {
    // Truncated valid gzip — parser sees a legitimate magic + method byte, then hits EOF
    // mid-stream. Distinguishes "malformed magic" (rejected immediately) from "truncated
    // legit stream" (rejected further in — a different code path in zlib).
    const goodStart = zlib.gzipSync(Buffer.from('legitimate-content'));
    // Keep only the first 5 bytes: magic (1f 8b) + method (08) + flags (00) + first
    // mtime byte. The rest is amputated.
    return goodStart.subarray(0, 5);
  }
  // baseline: entirely bogus header — NOT the gzip magic bytes (1f 8b).
  // Prefix with a "PK" sig (ZIP magic) so the parser can't confuse it with anything
  // else that's legitimately gzip-shaped.
  const junk = Buffer.from('PK\x03\x04not-a-gzip-stream-but-shaped-like-a-file-header');
  return junk;
}

// ------------------------------------------------------------------------------------------
// Public generator.
// ------------------------------------------------------------------------------------------

export const gzipBomb: GzipBombGenerator = {
  id: 'gzip-bomb',
  description:
    'Hostile gzip streams: high-ratio (compression bomb) and invalid-header (malformed). Every fixture <100 KB; high-ratio decompresses against the scanner\'s safe caps, not against unlimited memory.',
  generate(seed, params): GzipBombInput {
    if (!Number.isFinite(seed)) {
      throw new Error(`gzip-bomb: seed must be finite; got ${seed}`);
    }
    const mode = params.mode;
    const scale = params.scale ?? 'baseline';

    switch (mode) {
      case 'high-ratio': {
        const { bytes, decompressedBytes } = buildHighRatio(scale);
        if (bytes.length > 250_000) {
          throw new Error(
            `gzip-bomb high-ratio/${scale}: fixture size ${bytes.length} exceeds 250 KB boundedness invariant`,
          );
        }
        return {
          bytes,
          filename: `gzip-bomb-high-ratio-${scale}.tgz`,
          description: `gzip that decompresses to ${(decompressedBytes / 1024 / 1024).toFixed(0)} MiB (fixture on disk: ${bytes.length} B).`,
          mode,
          scale,
          decompressedBytesClaim: decompressedBytes,
        };
      }
      case 'invalid-header': {
        const bytes = buildInvalidHeader(scale);
        return {
          bytes,
          filename: `gzip-bomb-invalid-header-${scale}.bin`,
          description:
            scale === 'stress'
              ? 'truncated gzip stream (valid magic, EOF mid-stream)'
              : 'bogus gzip header (ZIP magic bytes, not gzip)',
          mode,
          scale,
        };
      }
      default: {
        const _exhaustive: never = mode;
        throw new Error(`gzip-bomb: unknown mode ${JSON.stringify(_exhaustive)}`);
      }
    }
  },
};
