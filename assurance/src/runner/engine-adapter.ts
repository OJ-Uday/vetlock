/**
 * Adapter: engine `Finding` (packages/core/src/finding.ts) → assurance `Finding`
 * (assurance/src/oracles/types.ts).
 *
 * The two shapes differ because they serve different audiences:
 *   - The engine's Finding is the product API. Every field matters to reporting, config, and
 *     downstream tooling: dotted detector id, coarse DetectorCategory, evidence array,
 *     provenance chains.
 *   - The assurance Finding is the oracle input. It only cares about (a) the capability
 *     class (what did the malicious code do?), (b) the severity, (c) enough locator data to
 *     tell two findings apart under normalization.
 *
 * Mapping (engine DetectorCategory → assurance capabilityClass):
 *   NET     → net-egress
 *   EXEC    → code-execution
 *   CODE    → code-execution         (dynamic loading / eval / new Function classes)
 *   FS      → fs-write
 *   ENV     → env/secret-read
 *   OBF     → obfuscation/decode
 *   INSTALL → persistence            (lifecycle scripts, install hooks)
 *   META    → analysis-failed        (engine's fail-safe channel)
 *   DEPS    → dep-graph              (extension: not in the original taxonomy but common
 *                                     in the engine; the oracle taxonomy stays open)
 *   INTEG   → integrity              (extension; ditto)
 *
 * Mapping (engine severity BLOCK|WARN|INFO → assurance severity BLOCK|FLAG|INFO):
 *   BLOCK → BLOCK
 *   WARN  → FLAG
 *   INFO  → INFO
 *
 * The engine's evidence array is mandatory; the first entry becomes the assurance
 * location. If the engine ever emits a finding with an empty evidence array, the schema
 * validator in the engine will already have caught it — the adapter treats that as a
 * defensive assertion, not a runtime path.
 *
 * The adapter is a PURE function of the engine finding; deterministic; no I/O.
 */

import type {
  Finding as EngineFinding,
  DetectorCategory,
  Severity as EngineSeverity,
  FileCapabilities,
  PackageSnapshot,
} from '@vetlock/core';
import type { Finding as AssuranceFinding, Findings as AssuranceFindings } from '../oracles/types.js';

const CATEGORY_TO_CLASS: Record<DetectorCategory, string> = {
  NET: 'net-egress',
  EXEC: 'code-execution',
  CODE: 'code-execution',
  FS: 'fs-write',
  ENV: 'env/secret-read',
  OBF: 'obfuscation/decode',
  INSTALL: 'persistence',
  META: 'analysis-failed',
  DEPS: 'dep-graph',
  INTEG: 'integrity',
};

const SEVERITY_MAP: Record<EngineSeverity, 'INFO' | 'FLAG' | 'BLOCK'> = {
  BLOCK: 'BLOCK',
  WARN: 'FLAG',
  INFO: 'INFO',
};

export function adaptFinding(engine: EngineFinding): AssuranceFinding {
  const capabilityClass = CATEGORY_TO_CLASS[engine.category];
  const severity = SEVERITY_MAP[engine.severity];
  const evidence = engine.evidence[0]; // validateFinding ensures non-empty
  return {
    capabilityClass,
    severity,
    reason: engine.message,
    location: evidence
      ? {
          file: evidence.file,
          line: evidence.line,
        }
      : undefined,
    meta: {
      detector: engine.detector,
      package: engine.package,
      direction: engine.direction,
      confidence: engine.confidence,
    },
  };
}

export function adaptFindings(engine: readonly EngineFinding[]): AssuranceFindings {
  return engine.map(adaptFinding);
}

/**
 * Detect whether the engine's fail-safe channel fired. A run is "fail-safe" (in assurance
 * terminology) if any finding has detector 'analysis.failed' — the engine's convention for
 * "a detector errored on this package; block it conservatively" (packages/core/src/engine.ts).
 */
export function findingsSignalFailSafe(engine: readonly EngineFinding[]): boolean {
  return engine.some((f) => f.detector === 'analysis.failed');
}

/** Extract the first fail-safe finding's message (for the RunOutcome `reason` field). */
export function extractFailSafeReason(engine: readonly EngineFinding[]): string {
  const f = engine.find((x) => x.detector === 'analysis.failed');
  return f?.message ?? 'analysis.failed';
}

// ---------------------------------------------------------------------------------------------
// Wave 3-O additions: capability → capabilityClass adapters.
//
// The engine's extractCapabilities emits a FileCapabilities (flat data — arrays of module
// names, URL literals, dynamic-code sites, etc.); analyzeTarball emits a PackageSnapshot
// (that FileCapabilities array plus a manifest and native-artifact list). Neither shape is
// a Finding by itself — the engine's DETECTORS are what turn capabilities into findings by
// diffing two snapshots.
//
// For assurance purposes we don't have two snapshots. We DO have "the engine saw capability
// X in this file"; the harness treats every observed capability as an assurance Finding so
// the oracles / robustness generators can assert on the capability set the engine surfaced.
// This intentionally overreports (a mere `require('fs')` becomes a fs-write class Finding —
// there's no severity gradient without a diff) but keeps the pipeline uniform: everything
// downstream consumes assurance Findings, not raw capability data.
//
// Mapping (capability → capabilityClass, packet §3.5 taxonomy):
//   networkModules[]      → net-egress
//   execModules[]         → code-execution
//   fsModules[]           → fs-write     (fs is bidirectional; class name preserved per §3.5)
//   urlLiterals[]         → net-egress
//   encodedUrls[]         → obfuscation/decode  (structurally suspect encoded net-egress)
//   envAccesses[]         → env/secret-read
//   dynamicCode[]         → code-execution
//   fsWriteTargets[]      → fs-write
//   fsReadTargets[]       → env/secret-read     (hot-path reads are secret-file reads)
//   suspiciousLiterals[]  → obfuscation/decode
//   parseError            → analysis-failed
//   manifest.scripts[hook]→ persistence         (lifecycle scripts fire at install)
// ---------------------------------------------------------------------------------------------

/**
 * Lifecycle hook names. Any script under manifest.scripts with one of these keys is a
 * persistence Finding (npm runs them at install / publish time).
 */
const LIFECYCLE_HOOKS = new Set([
  'preinstall', 'install', 'postinstall',
  'prepare', 'preprepare', 'postprepare',
  'prepublish', 'prepublishOnly', 'publish', 'postpublish',
  'prepack', 'pack', 'postpack',
]);

function pushInfo(
  findings: AssuranceFinding[],
  capabilityClass: string,
  reason: string,
  file: string,
  line?: number,
  meta?: Record<string, unknown>,
): void {
  findings.push({
    capabilityClass,
    severity: 'INFO',
    reason,
    location: line !== undefined ? { file, line } : { file },
    ...(meta ? { meta } : {}),
  });
}

/**
 * Translate one FileCapabilities into a series of assurance Findings — one per observed
 * capability. Order is deterministic and mirrors the field order in FileCapabilities so
 * downstream normalization can rely on it.
 */
export function adaptFileCapabilities(cap: FileCapabilities): AssuranceFindings {
  const out: AssuranceFinding[] = [];
  if (cap.parseError) {
    out.push({
      capabilityClass: 'analysis-failed',
      severity: 'BLOCK',
      reason: cap.parseError,
      location: { file: cap.path },
    });
    return out;
  }
  for (const mod of cap.networkModules) {
    pushInfo(out, 'net-egress', `network module: ${mod}`, cap.path, undefined, { module: mod });
  }
  for (const mod of cap.execModules) {
    pushInfo(out, 'code-execution', `exec module: ${mod}`, cap.path, undefined, { module: mod });
  }
  for (const mod of cap.fsModules) {
    pushInfo(out, 'fs-write', `fs module: ${mod}`, cap.path, undefined, { module: mod });
  }
  for (const url of cap.urlLiterals) {
    pushInfo(out, 'net-egress', `URL literal: ${url}`, cap.path, undefined, { url });
  }
  for (const enc of cap.encodedUrls) {
    pushInfo(
      out,
      'obfuscation/decode',
      `encoded URL (${enc.encoding}): ${enc.url}`,
      cap.path,
      enc.line,
      { encoding: enc.encoding, url: enc.url },
    );
  }
  for (const env of cap.envAccesses) {
    const keys = env.keys === null ? '<enumeration>' : env.keys.join(',');
    pushInfo(out, 'env/secret-read', `env access: ${keys}`, cap.path, env.line, { keys: env.keys });
  }
  for (const dyn of cap.dynamicCode) {
    pushInfo(out, 'code-execution', `dynamic code: ${dyn.kind}`, cap.path, dyn.line, { kind: dyn.kind });
  }
  for (const target of cap.fsWriteTargets) {
    pushInfo(out, 'fs-write', `fs write target: ${target}`, cap.path, undefined, { target });
  }
  for (const target of cap.fsReadTargets) {
    pushInfo(out, 'env/secret-read', `fs read target: ${target}`, cap.path, undefined, { target });
  }
  for (const susp of cap.suspiciousLiterals) {
    pushInfo(
      out,
      'obfuscation/decode',
      `suspicious literal (len=${susp.length}, entropy=${susp.entropy.toFixed(2)})`,
      cap.path,
      susp.line,
      { length: susp.length, entropy: susp.entropy },
    );
  }
  return out;
}

/**
 * Translate a PackageSnapshot into assurance Findings:
 *   - one Finding per capability observed in each file (via adaptFileCapabilities)
 *   - one Finding per lifecycle script observed in manifest.scripts
 *   - one Finding per native artifact (persistence — binaries ship with the package)
 *
 * Also inspects manifest._bundledLifecycle (populated by analyze.ts for bundled deps) so
 * that inner-package lifecycle hooks surface even when the outer manifest declares none.
 */
export function adaptPackageSnapshot(snap: PackageSnapshot): AssuranceFindings {
  const out: AssuranceFinding[] = [];
  // Outer manifest lifecycle scripts.
  const scripts = snap.manifest.scripts ?? {};
  for (const [hook, script] of Object.entries(scripts)) {
    if (LIFECYCLE_HOOKS.has(hook) && typeof script === 'string') {
      out.push({
        capabilityClass: 'persistence',
        severity: 'FLAG',
        reason: `lifecycle script: ${hook}`,
        location: { file: 'package.json' },
        meta: { hook, script },
      });
    }
  }
  // Bundled dep lifecycle scripts (analyze.ts stores them under _bundledLifecycle).
  const bundled = snap.manifest['_bundledLifecycle'] as
    | Record<string, Record<string, string>>
    | undefined;
  if (bundled && typeof bundled === 'object') {
    for (const [depName, hooks] of Object.entries(bundled)) {
      for (const [hook, script] of Object.entries(hooks ?? {})) {
        if (LIFECYCLE_HOOKS.has(hook) && typeof script === 'string') {
          out.push({
            capabilityClass: 'persistence',
            severity: 'FLAG',
            reason: `bundled dep '${depName}' lifecycle script: ${hook}`,
            location: { file: `node_modules/${depName}/package.json` },
            meta: { hook, script, bundledDep: depName },
          });
        }
      }
    }
  }
  // Native artifacts — shipped binaries with a persistence capability by construction.
  for (const art of snap.nativeArtifacts) {
    out.push({
      capabilityClass: 'persistence',
      severity: 'INFO',
      reason: `native artifact: ${art.kind}`,
      location: { file: art.path },
      meta: { kind: art.kind, bytes: art.bytes, sha256: art.sha256 },
    });
  }
  // Per-file capabilities.
  for (const file of snap.files) {
    out.push(...adaptFileCapabilities(file));
  }
  return out;
}
