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

import type { Finding as EngineFinding, DetectorCategory, Severity as EngineSeverity } from '@vetlock/core';
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
