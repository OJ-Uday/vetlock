/**
 * oracleIdentityInvariant — semantically-identical inputs produce identical findings.
 *
 * Normalization: sort findings deterministically by (file, line, capabilityClass, severity,
 * reason); strip non-deterministic metadata (wallMs, peakRssBytes, seed). The kind of the
 * outcome must match (both ok, or both fail-safe with matching findings). Any other kind
 * (crash / timeout / oom) fails the oracle — those are not "invariant" outcomes; they are
 * robustness failures.
 *
 * This is the "metamorphic" invariant: for any two programs P1 and P2 that behave identically
 * under any input, the analyzer must produce the same capability findings on both.
 */

import type { Finding, Findings, OracleResult, RunOutcome } from './types.js';

interface NormalizedFinding {
  readonly capabilityClass: string;
  readonly severity: string;
  readonly file: string;
  readonly line: number;
  readonly column: number;
  readonly reason: string;
  readonly meta: string; // stably-stringified for equality
}

function stableStringifyMeta(meta: Finding['meta']): string {
  if (!meta) return '';
  const keys = Object.keys(meta).sort();
  const parts: string[] = [];
  for (const k of keys) {
    const v = (meta as Record<string, unknown>)[k];
    parts.push(`${k}=${JSON.stringify(v)}`);
  }
  return parts.join('|');
}

function normalize(findings: Findings): readonly NormalizedFinding[] {
  const normalized = findings.map<NormalizedFinding>((f) => ({
    capabilityClass: f.capabilityClass,
    severity: f.severity,
    file: f.location?.file ?? '',
    line: f.location?.line ?? 0,
    column: f.location?.column ?? 0,
    reason: f.reason,
    meta: stableStringifyMeta(f.meta),
  }));
  normalized.sort((a, b) => {
    if (a.file !== b.file) return a.file < b.file ? -1 : 1;
    if (a.line !== b.line) return a.line - b.line;
    if (a.column !== b.column) return a.column - b.column;
    if (a.capabilityClass !== b.capabilityClass) return a.capabilityClass < b.capabilityClass ? -1 : 1;
    if (a.severity !== b.severity) return a.severity < b.severity ? -1 : 1;
    if (a.reason !== b.reason) return a.reason < b.reason ? -1 : 1;
    return a.meta < b.meta ? -1 : a.meta > b.meta ? 1 : 0;
  });
  return normalized;
}

function verdictShape(o: RunOutcome): { kind: string; findings: Findings } | null {
  if (o.kind === 'ok') return { kind: 'ok', findings: o.findings };
  if (o.kind === 'fail-safe') return { kind: 'fail-safe', findings: o.findings };
  return null;
}

export function oracleIdentityInvariant(a: RunOutcome, b: RunOutcome): OracleResult {
  const va = verdictShape(a);
  const vb = verdictShape(b);

  if (!va || !vb) {
    return {
      oracle: 'identity-invariant',
      pass: false,
      reason: `invariant does not apply: at least one outcome is not a verdict (a=${a.kind}, b=${b.kind})`,
      evidence: { aKind: a.kind, bKind: b.kind },
    };
  }

  if (va.kind !== vb.kind) {
    return {
      oracle: 'identity-invariant',
      pass: false,
      reason: `verdict kinds differ (${va.kind} vs ${vb.kind}) despite semantically-identical inputs`,
      evidence: { aKind: va.kind, bKind: vb.kind },
    };
  }

  const na = normalize(va.findings);
  const nb = normalize(vb.findings);

  if (na.length !== nb.length) {
    return {
      oracle: 'identity-invariant',
      pass: false,
      reason: `findings count differs (${na.length} vs ${nb.length}); invariant violated`,
      evidence: { aCount: na.length, bCount: nb.length },
    };
  }

  for (let i = 0; i < na.length; i++) {
    const fa = na[i];
    const fb = nb[i];
    if (
      fa.capabilityClass !== fb.capabilityClass ||
      fa.severity !== fb.severity ||
      fa.file !== fb.file ||
      fa.line !== fb.line ||
      fa.column !== fb.column ||
      fa.reason !== fb.reason ||
      fa.meta !== fb.meta
    ) {
      return {
        oracle: 'identity-invariant',
        pass: false,
        reason: `normalized finding [${i}] differs between semantically-identical inputs`,
        evidence: { a: fa, b: fb },
      };
    }
  }

  return { oracle: 'identity-invariant', pass: true };
}
