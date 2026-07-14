/**
 * tar-bomb — assurance generators for archive-decompression safety.
 *
 * Real npm tarballs are POSIX ustar streams gzip-wrapped. A malicious tarball can attack
 * the SCANNER (not the runtime host) via:
 *   1. Oversized size claims in the tar header (attacker says "this entry is 10 GB" while
 *      shipping 100 bytes) — parsers that pre-allocate on the header claim OOM instantly.
 *   2. Pathologically deep path nesting (100+ slash-separated segments) — exercises the
 *      filesystem-mkdir path + any path-length guards.
 *   3. Zip-slip: entry paths containing '../../..' — the classic tar-extract vulnerability
 *      that writes files outside the destination directory.
 *   4. Entry-count explosion (100k entries per archive) — starves iteration limits and
 *      any per-entry accounting the extractor performs.
 *
 * PACKET §2.1: "decompression bombs" — the scanner MUST bound its own resource use no
 * matter what the input claims. This generator ships hostile inputs the scanner must
 * refuse to fully expand.
 *
 * BOUNDEDNESS: every generated fixture is <1 MB on disk. The pathology is in the METADATA
 * (headers, paths), not the actual expanded size — the scanner's decompression logic is
 * what's under test.
 *
 * Deterministic. Same (seed, mode, scale) → identical bytes.
 */

import { Buffer } from 'node:buffer';
import * as zlib from 'node:zlib';

/** Which pathology this fixture embodies. */
export type TarBombMode = 'oversized-claim' | 'nested-paths' | 'zip-slip' | 'many-entries';

/** Scale controls magnitude — baseline is the small "must be handled safely" case; stress
 *  pushes past the extractor's default caps to prove the caps fire cleanly. */
export type TarBombScale = 'baseline' | 'stress';

export interface TarBombParams {
  readonly mode: TarBombMode;
  readonly scale?: TarBombScale;
}

export interface TarBombInput {
  /** The gzipped-tar bytes to write to a .tgz on disk before feeding to analyzeTarball. */
  readonly bytes: Buffer;
  /** Suggested filename hint (e.g. 'hostile.tgz'). */
  readonly filename: string;
  /** Human-readable label for test names and the corpus README. */
  readonly description: string;
  /** Echo of the params so downstream test logs are unambiguous. */
  readonly mode: TarBombMode;
  readonly scale: TarBombScale;
}

export interface TarBombGenerator {
  readonly id: string;
  readonly description: string;
  generate(seed: number, params: TarBombParams): TarBombInput;
}

// ------------------------------------------------------------------------------------------
// tar / ustar header construction (self-contained — the assurance harness must not depend on
// packages/core/test/ helpers).
// ------------------------------------------------------------------------------------------

interface TarEntrySpec {
  readonly name: string;
  readonly content?: Buffer;
  /** Override entry size (for oversized-claim). */
  readonly claimedSize?: number;
  /** Type flag byte — '0' file, '5' dir. Others (symlinks/hardlinks) not needed here. */
  readonly typeFlag?: '0' | '5';
}

function makeTgz(entries: readonly TarEntrySpec[]): Buffer {
  const parts: Buffer[] = [];
  for (const e of entries) {
    parts.push(buildEntry(e));
  }
  parts.push(Buffer.alloc(1024)); // two 512-byte end blocks (POSIX ustar terminator)
  const tar = Buffer.concat(parts);
  return zlib.gzipSync(tar);
}

function buildEntry(e: TarEntrySpec): Buffer {
  const typeFlag = e.typeFlag ?? '0';
  const content = typeFlag === '0' ? e.content ?? Buffer.alloc(0) : Buffer.alloc(0);
  const size = e.claimedSize ?? content.length;
  const mode = typeFlag === '5' ? 0o755 : 0o644;

  const header = Buffer.alloc(512);
  writeStr(header, e.name.slice(0, 100), 0, 100);
  writeOct(header, mode, 100, 8);
  writeOct(header, 0, 108, 8); // uid
  writeOct(header, 0, 116, 8); // gid
  writeOct(header, size, 124, 12);
  // Fixed mtime — determinism across runs (seed doesn't drive time; test replays must be
  // byte-identical for corpus regression stability).
  writeOct(header, 0, 136, 12);
  writeStr(header, '        ', 148, 8); // checksum placeholder (8 spaces before recompute)
  writeStr(header, typeFlag, 156, 1);
  writeStr(header, 'ustar', 257, 6);
  writeStr(header, '00', 263, 2);
  // Recompute checksum: sum of all bytes with checksum field as 8 spaces.
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
  // ustar convention: <(len-1) octal digits><NUL>
  const padded = octal.padStart(len - 1, '0');
  buf.write(padded, off, len - 1, 'ascii');
  buf.writeUInt8(0, off + len - 1);
}

// ------------------------------------------------------------------------------------------
// mode builders — each returns a list of TarEntrySpecs that embody the pathology.
// ------------------------------------------------------------------------------------------

/** Oversized-claim: N entries whose header claims a huge size but content is tiny. */
function buildOversizedClaim(scale: TarBombScale): readonly TarEntrySpec[] {
  const count = scale === 'stress' ? 10 : 3;
  // Header size field is 12 octal bytes = 11 octal digits. Max is 8^11 - 1 = ~8 GB.
  // We claim 4 GiB per entry — parsers that pre-allocate on the claim would OOM.
  const CLAIMED = 4 * 1024 * 1024 * 1024;
  const entries: TarEntrySpec[] = [];
  for (let i = 0; i < count; i++) {
    entries.push({
      name: `package/oversized-${i}.bin`,
      content: Buffer.from(`tiny-${i}`),
      claimedSize: CLAIMED,
    });
  }
  return entries;
}

/** Nested-paths: one entry with a path of N slash-separated segments. */
function buildNestedPaths(scale: TarBombScale): readonly TarEntrySpec[] {
  const depth = scale === 'stress' ? 200 : 50;
  // ustar name field is 100 bytes. We keep segments short (1 char) so the whole path fits.
  // depth=200 → 200 chars ≈ over the field limit → the header write truncates, which itself
  // is a documented ustar limitation. The pathology being tested is what happens when a
  // hostile publisher engineers extreme path shapes; how the parser handles truncation is
  // part of what the scanner is under test for.
  const segments: string[] = ['package'];
  for (let d = 0; d < depth; d++) {
    // Cycle through a-z to make each segment distinct enough to not collapse (but 1 char
    // each keeps the header claim within legitimacy).
    segments.push(String.fromCharCode(97 + (d % 26)));
  }
  const name = segments.join('/') + '/leaf.js';
  return [{ name, content: Buffer.from("// leaf\nconst x = 1;\n") }];
}

/** Zip-slip: entries whose paths escape the destination via '..'. */
function buildZipSlip(scale: TarBombScale): readonly TarEntrySpec[] {
  const variants: readonly string[] =
    scale === 'stress'
      ? [
          '../../../etc/passwd',
          '../../../../root/.ssh/authorized_keys',
          'package/../../../evil.js',
          'package/legit.js/../../../../evil.js',
          '/absolute/path/etc/passwd',
        ]
      : ['../../../etc/passwd', 'package/../../../evil.js'];
  return variants.map((name) => ({
    name,
    content: Buffer.from('/* zip-slip payload — never executed by the scanner */'),
  }));
}

/** Many-entries: N distinct entries — starves iteration bounds. */
function buildManyEntries(scale: TarBombScale): readonly TarEntrySpec[] {
  // Baseline: 20 entries (below the default extractor cap of 10_000 — must be handled
  // as ordinary success). Stress: 15_000 entries — above the cap; must trip
  // 'entry-count-exceeded'. We stay well below 100k to keep the fixture under 1 MB
  // gzipped (each empty file's 512-byte header compresses well but ~15k unique names
  // still produce a bounded fixture on disk — measured empirically < 200 KB).
  const count = scale === 'stress' ? 15_000 : 20;
  const entries: TarEntrySpec[] = [];
  for (let i = 0; i < count; i++) {
    entries.push({
      name: `package/f${i.toString(16).padStart(6, '0')}.txt`,
      content: Buffer.from('x'),
    });
  }
  return entries;
}

// ------------------------------------------------------------------------------------------
// Public generator.
// ------------------------------------------------------------------------------------------

export const tarBomb: TarBombGenerator = {
  id: 'tar-bomb',
  description:
    'Hostile tarball shapes: oversized-claim, nested-paths, zip-slip, many-entries. Every fixture <1 MB on disk; the pathology is in the metadata, not the expanded size.',
  generate(seed, params): TarBombInput {
    // Seed reserved for future variants (name randomization, header noise). Currently the
    // fixture is fully determined by (mode, scale); we validate seed only for API stability.
    if (!Number.isFinite(seed)) {
      throw new Error(`tar-bomb: seed must be finite; got ${seed}`);
    }
    const mode = params.mode;
    const scale = params.scale ?? 'baseline';

    let entries: readonly TarEntrySpec[];
    let description: string;
    switch (mode) {
      case 'oversized-claim':
        entries = buildOversizedClaim(scale);
        description = `tar with ${entries.length} entry(ies) each claiming 4 GiB in the header; on-disk content <100 B.`;
        break;
      case 'nested-paths':
        entries = buildNestedPaths(scale);
        description = `tar with a single entry whose path nests ${scale === 'stress' ? 200 : 50}+ segments deep.`;
        break;
      case 'zip-slip':
        entries = buildZipSlip(scale);
        description = `tar with ${entries.length} zip-slip path(s) (traversal + absolute).`;
        break;
      case 'many-entries':
        entries = buildManyEntries(scale);
        description = `tar with ${entries.length.toLocaleString()} distinct entries — exercises entry-count cap.`;
        break;
      default: {
        const _exhaustive: never = mode;
        throw new Error(`tar-bomb: unknown mode ${JSON.stringify(_exhaustive)}`);
      }
    }

    const bytes = makeTgz(entries);
    // Sanity: enforce the <1 MB fixture invariant.  We prefer to fail loudly at generate
    // time than to ship a fixture that violates the harness's own boundedness guarantee.
    if (bytes.length > 1_000_000) {
      throw new Error(
        `tar-bomb ${mode}/${scale}: fixture size ${bytes.length} exceeds 1 MB boundedness invariant`,
      );
    }
    return {
      bytes,
      filename: `tar-bomb-${mode}-${scale}.tgz`,
      description,
      mode,
      scale,
    };
  },
};
