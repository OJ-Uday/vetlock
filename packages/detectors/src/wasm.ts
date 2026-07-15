/**
 * WASM detector — flags suspicious imports in WebAssembly binaries.
 *
 * Two paths:
 *   1. Diff mode: an existing WASM path gained a NEW import between versions.
 *   2. First-appearance mode: a package that never shipped WASM before now does.
 *      Combined with the bin.new-native-artifact detector, this gives us
 *      layered signal on the "attacker started shipping compiled payloads" shape.
 *
 * SUSPICIOUS_IMPORT_MODULES: WASM imports whose module name suggests network
 * exfil, filesystem access, or dynamic code loading beyond what the WASM
 * spec's stdlib provides. WASI modules that expose fs / clock / random are
 * legitimate; env.<function> imports that name JS globals like `eval` or
 * `fetch` are highly suspect.
 *
 * BLOCK, high — matches the severity of the JS-side eval detector.
 */

import type { Detector, Finding, NativeArtifact, PackageSnapshot, SnapshotPair } from '@vetlock/core';
import { directionFor } from './direction.js';

/**
 * WASM import module patterns that suggest an attacker-controlled ability
 * to talk to the outside world. Not exhaustive; matched by prefix + regex.
 * Keep this list defensively broad — false positives here are legitimate WASM
 * libraries that we want a human to check.
 */
const SUSPICIOUS_IMPORT_NAMES =
  /^(?:[\w$-]+\.)?(?:eval|Function|fetch|XMLHttpRequest|open|write|read|spawn|exec|system|popen|shell|curl|wget|connect|send|recv|download|upload|readFile|writeFile)$/i;
const SUSPICIOUS_IMPORT_MODULES = /^(env|imports|host)$/i;
/** WASI capability namespaces that provide fs, clock, sock, proc access. */
const WASI_SENSITIVE_MODULES = /^wasi_snapshot_preview[12]$/i;
const WASI_SENSITIVE_NAMES = /^(fd_write|fd_read|path_open|proc_exec|sock_send|sock_recv)$/i;

interface ImportKey {
  module: string;
  name: string;
}

function collectImports(snap: PackageSnapshot | null): Map<string, ImportKey> {
  const out = new Map<string, ImportKey>();
  if (!snap) return out;
  for (const a of snap.nativeArtifacts) {
    if (a.kind !== 'wasm' || !a.wasmImports) continue;
    for (const imp of a.wasmImports) {
      const key = `${a.path}|${imp.module}|${imp.name}`;
      out.set(key, { module: imp.module, name: imp.name });
    }
  }
  return out;
}

function isSuspiciousImport(module: string, name: string): boolean {
  const normalizedName = name.replace(/\s+as\s+[\w$.-]+$/i, '').trim();
  const qualifiedName = `${module}.${normalizedName}`;
  // WASI file/net/exec capabilities — always suspect.
  if (WASI_SENSITIVE_MODULES.test(module) && WASI_SENSITIVE_NAMES.test(normalizedName)) return true;
  // env-module imports of dynamic-code names.
  if (
    SUSPICIOUS_IMPORT_MODULES.test(module) &&
    (SUSPICIOUS_IMPORT_NAMES.test(normalizedName) || SUSPICIOUS_IMPORT_NAMES.test(qualifiedName))
  ) {
    return true;
  }
  return false;
}

export const wasmDetector: Detector = {
  id: 'wasm',
  category: 'CODE',
  run(pair: SnapshotPair): Finding[] {
    if (!pair.new) return [];
    const dir = directionFor(pair.old);
    const oldImports = collectImports(pair.old);
    const newImports = collectImports(pair.new);

    const out: Finding[] = [];

    // Path A: NEW imports appearing in the new snapshot
    for (const [key, imp] of newImports) {
      if (oldImports.has(key)) continue;
      if (!isSuspiciousImport(imp.module, imp.name)) continue;
      const [wasmPath] = key.split('|');
      out.push({
        detector: 'wasm.suspicious-import',
        category: 'CODE',
        package: pair.new.name,
        from: dir.from,
        to: pair.new.version,
        direction: dir.direction,
        severity: 'BLOCK',
        confidence: 'high',
        message: `WASM binary declares suspicious import "${imp.module}.${imp.name}" — this exposes host-side ${imp.name} to the WASM sandbox.`,
        evidence: [
          {
            file: wasmPath ?? 'unknown.wasm',
            line: 1,
            snippet: `import ${imp.module}.${imp.name}`,
          },
        ],
        provenance: [],
      });
    }

    // Path B: NEW WASM binary that failed to parse — treat as an obfuscation signal
    for (const a of pair.new.nativeArtifacts) {
      if (a.kind !== 'wasm' || !a.wasmParseError) continue;
      // Was this path also unparseable before? Then skip.
      const wasBadBefore = pair.old?.nativeArtifacts.some(
        (o: NativeArtifact) => o.path === a.path && o.wasmParseError,
      );
      if (wasBadBefore) continue;
      out.push({
        detector: 'wasm.unparseable',
        category: 'OBF',
        package: pair.new.name,
        from: dir.from,
        to: pair.new.version,
        direction: dir.direction,
        severity: 'WARN',
        confidence: 'medium',
        message: `WASM binary ${a.path} could not be parsed as valid WASM (${a.wasmParseError}). Malformed or intentionally-obfuscated binaries can smuggle payloads past static analysis.`,
        evidence: [
          {
            file: a.path,
            line: 1,
            snippet: `parse error: ${a.wasmParseError}`,
          },
        ],
        provenance: [],
      });
    }

    return out;
  },
};

// Re-exports for tests
export { isSuspiciousImport, collectImports };
