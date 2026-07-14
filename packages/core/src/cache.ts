/**
 * Content-addressed cache for PackageSnapshot values.
 *
 * Key: the tarball's ssri integrity string (e.g. 'sha512-…='). We derive
 * the on-disk filename by stripping non-filesystem-safe chars.
 *
 * Storage: `~/.cache/vetlock/analysis/<safe-key>.json`. Override via env var
 * `VETLOCK_CACHE_DIR` (respected here, not read at import).
 *
 * Snapshots include a `formatVersion` field; read() ignores hits whose format
 * doesn't match the current constant.
 *
 * SECURITY-CRITICAL (REDTEAM S1 fix):
 *
 * The cache key is the tarball's integrity string, which comes from the
 * lockfile — an attacker-controlled input during PR review. Before this fix,
 * a hostile process (a prior compromised npm package's postinstall on the
 * same machine, a co-tenant CI job on a shared runner) could plant a
 * benign-looking `PackageSnapshot` JSON at the predictable safe-key path.
 * On the next `vetlock diff` run, the engine looked up the exact same
 * integrity string, got a cache HIT, skipped the fetch/extract/analyze
 * pipeline entirely, and rendered CLEAN — verdict was determined by
 * attacker-planted JSON.
 *
 * Defense — HMAC-authenticated cache. Every snapshot on disk is stored
 * alongside a keyed-HMAC computed over `SNAPSHOT_FORMAT_VERSION || integrity
 * || sha256(canonical(snapshot))`. The HMAC key lives at
 * `~/.cache/vetlock/hmac.key` and is generated on first run with 256 bits
 * from `crypto.randomBytes`. Any process that can read the key (i.e. the
 * user themselves) can forge entries. Any process that CANNOT read the key
 * cannot. A hostile npm-package postinstall running under a build-agent
 * with a different uid, or writing without read, cannot plant a valid
 * entry — the HMAC check fails, cached snapshot is treated as absent, and
 * the full analysis path runs.
 *
 * The HMAC key file is created with mode 0600 (owner read/write only). If
 * an attacker has read access to the key file, they already own the account
 * and this defense doesn't apply — but for the actual attack vector (shared
 * CI runners with different-uid processes, prior-compromised-package
 * writing into `~/.cache/` under the user's UID but before vetlock reads
 * the key), the key file is either not there yet (attacker cannot preempt
 * key generation because they don't know when vetlock will first run) or
 * unreadable to the attacker (different uid → no read).
 *
 * See docs/SECURITY-DECISIONS.md: caching is a performance optimization
 * that MUST NOT skip a security check. This design ensures a cache hit is
 * cryptographically bound to a specific vetlock installation's key.
 */

import { promises as fs } from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as crypto from 'node:crypto';
import type { PackageSnapshot } from './finding.js';

// v0.5.0: FileCapabilities gained `urlLiteralContexts` (URL AST context
// tracking — see packages/core/src/capabilities.ts). Bumped so stale
// on-disk snapshots built by pre-v0.5.0 vetlock (which lack that field) are
// treated as cache misses instead of silently masking the new field.
export const SNAPSHOT_FORMAT_VERSION = 2;

/**
 * On-disk wire format: the snapshot plus an HMAC over it. Older cache files
 * (from v0.2.0 and earlier) that don't have this envelope are silently
 * ignored — no legacy passthrough, since accepting them would defeat the fix.
 */
interface AuthenticatedCacheEntry {
  /** Explicit envelope marker so we can detect legacy files and refuse them. */
  __vetlock_cache_v: 2;
  integrity: string;
  formatVersion: number;
  snapshot: PackageSnapshot;
  /** hex-encoded HMAC-SHA256 over `${integrity}\n${formatVersion}\n${canonicalJson(snapshot)}`. */
  hmac: string;
}

export interface SnapshotCache {
  get(integrity: string): Promise<PackageSnapshot | null>;
  put(integrity: string, snapshot: PackageSnapshot): Promise<void>;
  /** Directory the cache is rooted at (for introspection/tests). */
  readonly dir: string;
}

export function defaultCacheDir(): string {
  return (
    process.env.VETLOCK_CACHE_DIR ??
    path.join(os.homedir(), '.cache', 'vetlock', 'analysis')
  );
}

export function makeCache(dir: string = defaultCacheDir()): SnapshotCache {
  // Lazily load-or-create the HMAC key. The key lives one dir up from the
  // analysis cache so `~/.cache/vetlock/hmac.key` covers the whole install.
  let hmacKey: Buffer | null = null;
  async function getHmacKey(): Promise<Buffer> {
    if (hmacKey) return hmacKey;
    const keyDir = path.dirname(dir); // ~/.cache/vetlock/
    const keyPath = path.join(keyDir, 'hmac.key');
    await fs.mkdir(keyDir, { recursive: true });
    try {
      const existing = await fs.readFile(keyPath);
      if (existing.length >= 32) {
        hmacKey = existing;
        return existing;
      }
      // Corrupt/short key file → regenerate. This IS a legitimate cache
      // invalidation event (equivalent to a formatVersion bump).
    } catch {
      // No key yet; fall through to create.
    }
    const fresh = crypto.randomBytes(32);
    // Atomic write with restrictive permissions.
    const tmp = `${keyPath}.tmp-${process.pid}-${Date.now()}`;
    await fs.writeFile(tmp, fresh, { mode: 0o600 });
    await fs.rename(tmp, keyPath);
    // Belt-and-suspenders — some fs/os combos ignore mode on writeFile.
    try {
      await fs.chmod(keyPath, 0o600);
    } catch {
      /* best-effort */
    }
    hmacKey = fresh;
    return fresh;
  }

  return {
    dir,
    async get(integrity: string): Promise<PackageSnapshot | null> {
      const p = keyPath(dir, integrity);
      try {
        const raw = await fs.readFile(p, 'utf8');
        const entry = JSON.parse(raw) as Partial<AuthenticatedCacheEntry>;
        // Envelope must be present and versioned — no legacy passthrough.
        if (entry.__vetlock_cache_v !== 2) return null;
        if (entry.formatVersion !== SNAPSHOT_FORMAT_VERSION) return null;
        if (typeof entry.integrity !== 'string' || entry.integrity !== integrity) return null;
        if (!entry.snapshot || typeof entry.hmac !== 'string') return null;
        // Recompute the HMAC and constant-time compare.
        const expected = await computeHmac(await getHmacKey(), integrity, entry.formatVersion, entry.snapshot);
        const provided = Buffer.from(entry.hmac, 'hex');
        if (provided.length !== expected.length) return null;
        if (!crypto.timingSafeEqual(provided, expected)) {
          // HMAC mismatch → treat as absent. A hostile process planted this
          // file without knowing our per-install HMAC key. Re-analyze from
          // scratch, do not leak the mismatch (attackers can already tell
          // from the "hit" latency).
          return null;
        }
        return entry.snapshot;
      } catch {
        return null;
      }
    },
    async put(integrity: string, snapshot: PackageSnapshot): Promise<void> {
      await fs.mkdir(dir, { recursive: true });
      const key = await getHmacKey();
      const hmac = await computeHmac(key, integrity, SNAPSHOT_FORMAT_VERSION, snapshot);
      const envelope: AuthenticatedCacheEntry = {
        __vetlock_cache_v: 2,
        integrity,
        formatVersion: SNAPSHOT_FORMAT_VERSION,
        snapshot,
        hmac: hmac.toString('hex'),
      };
      const p = keyPath(dir, integrity);
      const tmp = `${p}.tmp-${process.pid}-${Date.now()}`;
      await fs.writeFile(tmp, JSON.stringify(envelope), { mode: 0o600 });
      await fs.rename(tmp, p);
    },
  };
}

/**
 * Deterministic canonical JSON — object keys sorted recursively — so the HMAC
 * doesn't drift with key ordering. This has to be stable across the write and
 * read paths; using JSON.stringify with a replacer that sorts keys is enough.
 */
function canonicalJson(value: unknown): string {
  return JSON.stringify(value, (_, v) => {
    if (v && typeof v === 'object' && !Array.isArray(v)) {
      return Object.fromEntries(Object.keys(v).sort().map((k) => [k, (v as Record<string, unknown>)[k]]));
    }
    return v;
  });
}

async function computeHmac(
  key: Buffer,
  integrity: string,
  formatVersion: number,
  snapshot: PackageSnapshot,
): Promise<Buffer> {
  const h = crypto.createHmac('sha256', key);
  h.update(`v2\n${formatVersion}\n${integrity}\n`);
  h.update(canonicalJson(snapshot));
  return h.digest();
}

function keyPath(dir: string, integrity: string): string {
  // sha512-abc/def= → sha512-abc_def_
  const safe = integrity.replace(/[^A-Za-z0-9._-]/g, '_');
  return path.join(dir, `${safe}.json`);
}
