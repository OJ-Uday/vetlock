/**
 * CODE detector — new dynamic loading sinks.
 *
 * Fires when any dynamicCode entry is present in new but not old
 * (by file+kind+line — different lines count as different).
 *
 * v0.4.1 FP-STUDY §3c — sink kinds split by "danger tier":
 *   - eval / new-function / char-arithmetic-decoder → WARN, medium (retained).
 *     These have low legit base rates. `char-arithmetic-decoder` is included
 *     here even though bundlers sometimes generate the pattern, because it's
 *     specifically the shape used by rot13 / xor / base64 decoder loops that
 *     unpack obfuscated payloads (REDTEAM L11).
 *   - dynamic-import / dynamic-require → INFO, low (down from WARN, medium).
 *     Modern module-loading idiom. A bundler adds them at rates uncorrelated
 *     with malice. Legitimate to observe, not enough signal to WARN on its own.
 *     Attackers using dynamic-require to load a decoded payload are already
 *     covered by the NEIGHBORING evidence: the payload itself will trigger
 *     obf.new-obfuscated-file or char-arithmetic-decoder.
 *   - vm → BLOCK, high. Direct sandbox-escape target; the vm.runIn*Context()
 *     APIs are the shape of "hidden second-stage code execution."
 *
 * The suppress-dynamic-import-to-INFO change was measured on
 * `studies/top-100.txt`: dropped the escalation-driven BLOCK verdict from
 * prettier, sharp, vite (which had NO other real signal beyond a bundler
 * shipping dynamic-import sites).
 */

import type { Detector, Finding, PackageSnapshot, SnapshotPair, DynamicCodeSite } from '@vetlock/core';
import { directionFor } from './direction.js';

function key(f: string, d: DynamicCodeSite): string {
  return `${f}:${d.line}:${d.kind}`;
}

function collectSites(snap: PackageSnapshot | null): Set<string> {
  const s = new Set<string>();
  if (!snap) return s;
  for (const f of snap.files) for (const d of f.dynamicCode) s.add(key(f.path, d));
  return s;
}

// Danger tier per sink kind. See file-header comment.
function severityFor(kind: DynamicCodeSite['kind']): { severity: 'INFO' | 'WARN' | 'BLOCK'; confidence: 'low' | 'medium' | 'high' } {
  switch (kind) {
    case 'vm':
      return { severity: 'BLOCK', confidence: 'high' };
    case 'eval':
    case 'new-function':
    case 'char-arithmetic-decoder':
      return { severity: 'WARN', confidence: 'medium' };
    case 'dynamic-import':
    case 'dynamic-require':
    default:
      return { severity: 'INFO', confidence: 'low' };
  }
}

export const codeDetector: Detector = {
  id: 'code',
  category: 'CODE',
  run(pair: SnapshotPair): Finding[] {
    if (!pair.new) return [];
    const dir = directionFor(pair.old);
    const oldSet = collectSites(pair.old);
    const out: Finding[] = [];
    for (const f of pair.new.files) {
      for (const d of f.dynamicCode) {
        if (oldSet.has(key(f.path, d))) continue;
        const { severity, confidence } = severityFor(d.kind);
        out.push({
          detector: 'code.dynamic-loading-added',
          category: 'CODE',
          package: pair.new.name,
          from: dir.from,
          to: pair.new.version,
          direction: dir.direction,
          severity,
          confidence,
          message: `Dynamic code sink introduced (${d.kind}).`,
          evidence: [{ file: f.path, line: d.line, snippet: d.snippet.slice(0, 240) }],
          provenance: [],
        });
      }
    }
    return out;
  },
};
