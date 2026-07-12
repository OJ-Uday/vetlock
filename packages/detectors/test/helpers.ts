/**
 * Test helpers for detectors — build valid PackageSnapshot values from partial
 * overrides. Reused across every detector test file.
 */

import type {
  PackageSnapshot,
  FileCapabilities,
  PackageManifest,
} from '@vetlock/core';
import { SNAPSHOT_FORMAT_VERSION } from '@vetlock/core';

export function mkFile(over: Partial<FileCapabilities> & { path: string }): FileCapabilities {
  return {
    path: over.path,
    bytes: over.bytes ?? 0,
    sha256: over.sha256 ?? 'sha256-fake',
    entropy: over.entropy ?? 0,
    minified: over.minified ?? false,
    networkModules: over.networkModules ?? [],
    execModules: over.execModules ?? [],
    fsModules: over.fsModules ?? [],
    urlLiterals: over.urlLiterals ?? [],
    envAccesses: over.envAccesses ?? [],
    dynamicCode: over.dynamicCode ?? [],
    fsWriteTargets: over.fsWriteTargets ?? [],
    suspiciousLiterals: over.suspiciousLiterals ?? [],
    ...(over.parseError ? { parseError: over.parseError } : {}),
  };
}

export function mkSnap(over: {
  name: string;
  version: string;
  integrity?: string;
  manifest?: PackageManifest;
  files?: FileCapabilities[];
}): PackageSnapshot {
  return {
    name: over.name,
    version: over.version,
    integrity: over.integrity ?? `sha512-${over.name}@${over.version}=`,
    manifest: over.manifest ?? { name: over.name, version: over.version },
    files: over.files ?? [],
    formatVersion: SNAPSHOT_FORMAT_VERSION,
    builtAt: '2026-07-12T00:00:00.000Z',
  };
}
