/**
 * Analyze a package tarball → PackageSnapshot.
 *
 * PRIME DIRECTIVE (ADR 0005): NEVER runs any code from the tarball. Everything
 * is static: read bytes, parse AST, compute hashes. This module is where the
 * fetch/extract/parse pipeline glues together.
 *
 * The `never-execute-canary.test.ts` guards this invariant by construction —
 * the fixture tarball is designed to leave a sentinel file if any code from it
 * ran, and the test asserts the sentinel does not exist.
 */

import { promises as fs } from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { safeExtract, ExtractLimits } from './extract.js';
import {
  PackageSnapshot,
  PackageManifest,
  FileCapabilities,
  NativeArtifact,
  EnvAccess,
  DynamicCodeSite,
  SuspiciousLiteral,
} from './finding.js';
import { SNAPSHOT_FORMAT_VERSION } from './cache.js';
import { extractCapabilities } from './capabilities.js';

export interface AnalyzeOptions {
  integrity?: string;
  limits?: ExtractLimits;
  baseTmpDir?: string;
}

/**
 * Analyze a tarball at rest. Returns the snapshot and cleans up temp files
 * before returning (even on throw).
 */
export async function analyzeTarball(
  tarballPath: string,
  opts: AnalyzeOptions = {},
): Promise<PackageSnapshot> {
  const extracted = await safeExtract(tarballPath, {
    limits: opts.limits,
    baseTmpDir: opts.baseTmpDir,
  });
  try {
    const manifest = await readManifest(extracted.destDir);
    const files: FileCapabilities[] = [];
    const nativeArtifacts: NativeArtifact[] = [];
    for (const entry of extracted.entries) {
      const rel = entry.relPath;
      const nativeKind = binaryKind(rel);
      if (nativeKind) {
        nativeArtifacts.push({
          path: rel,
          bytes: entry.bytes,
          sha256: entry.sha256,
          kind: nativeKind,
        });
        continue;
      }
      if (isMediaPath(rel)) continue;
      if (!isAnalyzableSource(rel)) continue;
      const abs = path.join(extracted.destDir, rel);
      const buf = await fs.readFile(abs);
      const text = buf.toString('utf8');
      const cap = extractCapabilities(rel, text, entry.sha256, buf.byteLength);
      files.push(cap);
    }
    return {
      name: manifest.name ?? 'unknown',
      version: manifest.version ?? '0.0.0',
      integrity: opts.integrity ?? '',
      manifest,
      files,
      nativeArtifacts,
      formatVersion: SNAPSHOT_FORMAT_VERSION,
      builtAt: new Date().toISOString(),
    };
  } finally {
    await extracted.cleanup();
  }
}

async function readManifest(destDir: string): Promise<PackageManifest> {
  const p = path.join(destDir, 'package.json');
  try {
    const raw = await fs.readFile(p, 'utf8');
    return JSON.parse(raw) as PackageManifest;
  } catch {
    return {};
  }
}

function isAnalyzableSource(rel: string): boolean {
  return /\.(m?js|cjs|jsx|ts|tsx|json)$/i.test(rel) && !rel.startsWith('node_modules/');
}

/** Media/font files we don't analyze but also don't flag. */
function isMediaPath(rel: string): boolean {
  return /\.(jpg|jpeg|png|gif|webp|ttf|woff|woff2|svg|ico)$/i.test(rel);
}

/** Native binary artifacts we DO flag — return the artifact kind if any. */
function binaryKind(rel: string): NativeArtifact['kind'] | null {
  const m = rel.match(/\.(node|so|dylib|dll|exe|wasm|bin)$/i);
  if (!m) return null;
  return m[1]!.toLowerCase() as NativeArtifact['kind'];
}

// Placeholder used only if capabilities.ts hasn't been built yet. Real
// implementation lives in ./capabilities.ts.
export function _hashBytes(bytes: Buffer): string {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

// Re-export for downstream imports
export type { FileCapabilities, EnvAccess, DynamicCodeSite, SuspiciousLiteral };
