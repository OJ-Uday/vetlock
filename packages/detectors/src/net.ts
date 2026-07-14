/**
 * NET detector — new network capability.
 *
 * Two sub-findings:
 *   - net.new-module    (WARN, medium) — a network module now imported that wasn't before
 *   - net.new-endpoint  (WARN/INFO, medium)  — a URL literal now present that wasn't before
 *
 * v0.4.1 FP-STUDY §3b — `net.new-endpoint` downgraded from BLOCK to WARN.
 * Rationale: on the 27-bump routine-upgrade study, a single new URL literal
 * fired BLOCK on 33% of legitimate bumps — including docs URLs in error
 * messages (prettier's typescript-eslint.io link) and install-help URLs in
 * comments (sharp's pixelplumbing.com link). Any single URL delta shouldn't
 * BLOCK on its own; a package adding a docs URL is not the same as one adding
 * an exfil endpoint. Co-occurrence with INSTALL/EXEC/ENV/FS via the compound-
 * suspicion escalator in index.ts promotes it back to BLOCK when the shape
 * looks actually malicious.
 *
 * v0.5.0 — URL AST context tracking. `net.new-endpoint` severity is now
 * calibrated by *how* the URL literal is used, per `FileCapabilities.
 * urlLiteralContexts` (packages/core/src/capabilities.ts):
 *   - 'network-arg' (passed straight to fetch/axios/request/...) or
 *     'config-value' (assigned to a url/endpoint/baseURL/... key) → WARN,
 *     unchanged from pre-v0.5.0 behavior — this is where a real exfil
 *     endpoint would actually be used.
 *   - 'literal' (a bare string, not consumed as a network target) or
 *     'comment' (only appears in a source comment) → downgraded to INFO —
 *     these are the `Cursor.app` / docs-link / changelog-URL shapes that
 *     don't represent an actual outbound call.
 * When `urlLiteralContexts` is absent (non-JS/JSON files, or files that
 * failed to parse) we keep the pre-v0.5.0 default of WARN — no context
 * information means no basis for downgrading.
 *
 * URL literals dedup across files; first-seen evidence is used.
 *
 * On ADDED packages (pair.old === null), we still emit findings — a newly-
 * installed package that ships network calls to specific endpoints is signal.
 * We downgrade confidence in that mode to reflect the higher noise floor.
 */

import type { Detector, Finding, PackageSnapshot, SnapshotPair, Severity } from '@vetlock/core';
import { directionFor } from './direction.js';

export const netDetector: Detector = {
  id: 'net',
  category: 'NET',
  run(pair: SnapshotPair): Finding[] {
    if (!pair.new) return [];
    const dir = directionFor(pair.old);
    const isAdded = pair.old === null;

    const out: Finding[] = [];
    const oldMods = pair.old ? collectModules(pair.old, (f) => f.networkModules) : new Map();
    const newMods = collectModules(pair.new, (f) => f.networkModules);
    for (const [mod, evidence] of newMods.entries()) {
      if (oldMods.has(mod)) continue;
      out.push({
        detector: 'net.new-module',
        category: 'NET',
        package: pair.new.name,
        from: dir.from,
        to: pair.new.version,
        direction: dir.direction,
        severity: 'WARN',
        confidence: isAdded ? 'low' : 'medium',
        message: isAdded
          ? `Newly-installed package imports network module "${mod}".`
          : `Package started using network module "${mod}".`,
        evidence: [evidence],
        provenance: [],
      });
    }

    const oldUrls = pair.old ? collectUrls(pair.old) : new Map();
    const newUrls = collectUrls(pair.new);
    for (const [url, evidence] of newUrls.entries()) {
      if (oldUrls.has(url)) continue;
      out.push({
        detector: 'net.new-endpoint',
        category: 'NET',
        package: pair.new.name,
        from: dir.from,
        to: pair.new.version,
        direction: dir.direction,
        severity: severityForContext(evidence.context),
        confidence: isAdded ? 'low' : 'medium',
        message: isAdded
          ? `Newly-installed package contacts network endpoint: ${url}`
          : `New network endpoint appeared: ${url}`,
        evidence: [{ file: evidence.file, line: evidence.line, snippet: evidence.snippet }],
        provenance: [],
      });
    }

    return out;
  },
};

/** Map a URL's AST usage context to the finding severity. See module docstring. */
function severityForContext(context: string | undefined): Severity {
  if (context === 'literal' || context === 'comment') return 'INFO';
  return 'WARN';
}

function collectModules(
  snap: PackageSnapshot,
  pick: (f: PackageSnapshot['files'][number]) => string[],
): Map<string, { file: string; line: number; snippet: string }> {
  const map = new Map<string, { file: string; line: number; snippet: string }>();
  for (const f of snap.files) {
    for (const m of pick(f)) {
      if (!map.has(m)) map.set(m, { file: f.path, line: 1, snippet: `imports ${m}` });
    }
  }
  return map;
}

function collectUrls(
  snap: PackageSnapshot,
): Map<string, { file: string; line: number; snippet: string; context?: string }> {
  const map = new Map<string, { file: string; line: number; snippet: string; context?: string }>();
  for (const f of snap.files) {
    for (const u of f.urlLiterals) {
      if (!map.has(u)) {
        map.set(u, {
          file: f.path,
          line: 1,
          snippet: u.slice(0, 240),
          context: f.urlLiteralContexts?.[u],
        });
      }
    }
  }
  return map;
}
