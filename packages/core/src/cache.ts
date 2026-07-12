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
 */

import { promises as fs } from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import type { PackageSnapshot } from './finding.js';

export const SNAPSHOT_FORMAT_VERSION = 1;

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
  return {
    dir,
    async get(integrity: string): Promise<PackageSnapshot | null> {
      const p = keyPath(dir, integrity);
      try {
        const raw = await fs.readFile(p, 'utf8');
        const snap = JSON.parse(raw) as PackageSnapshot;
        if (snap.formatVersion !== SNAPSHOT_FORMAT_VERSION) return null;
        return snap;
      } catch {
        return null;
      }
    },
    async put(integrity: string, snapshot: PackageSnapshot): Promise<void> {
      await fs.mkdir(dir, { recursive: true });
      const p = keyPath(dir, integrity);
      const tmp = `${p}.tmp-${process.pid}-${Date.now()}`;
      await fs.writeFile(tmp, JSON.stringify(snapshot));
      await fs.rename(tmp, p); // atomic write
    },
  };
}

function keyPath(dir: string, integrity: string): string {
  // sha512-abc/def= → sha512-abc_def_
  const safe = integrity.replace(/[^A-Za-z0-9._-]/g, '_');
  return path.join(dir, `${safe}.json`);
}
