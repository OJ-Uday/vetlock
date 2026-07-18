/**
 * MANIFEST-DEPS http-resolved-url — package.json dependency value is a plain
 * HTTP URL (unencrypted) OR points at a non-registry HTTPS tarball URL for a
 * newly-added dep.
 *
 * Port from guarddog:threat-npm-http-dependency — audit §4 row 8.
 *
 * The guarddog rule targets the lock-file `resolved:` field. The engine
 * (packages/core/src/engine.ts) already emits deps.non-registry-source WARN
 * for git+/github:/bitbucket:/gitlab: resolveds. What is NOT covered today:
 *
 *   1. `dependencies: { "foo": "http://attacker.example/foo.tgz" }` — a
 *      plain-http URL as the VERSION SPEC in the manifest. npm will fetch
 *      that URL directly at install time, no registry indirection, no
 *      integrity check. Attacker on any hop of the network can substitute
 *      the tarball.
 *   2. `dependencies: { "foo": "https://non-registry.example/foo.tgz" }` —
 *      an https URL not on registry.npmjs.org / npmjs.com. Integrity is
 *      preserved but the identity assumption of "this came from the npm
 *      registry" is broken.
 *
 * Shape:
 *   - Only fires for dep entries whose SPEC (the map value) is a URL.
 *   - Plain-http URL: BLOCK (unencrypted install-time fetch).
 *   - Non-registry HTTPS URL: WARN.
 *   - Registry URLs (registry.npmjs.org / registry.yarnpkg.com) do not fire.
 *   - Fires on ADDED direct-deps AND on CHANGED entries where the URL is
 *     newly present or newly different.
 *
 * NEVER-EXECUTE (ADR 0005): reads only manifest.dependencies, no runtime.
 */

import type { Detector, Finding, SnapshotPair, Severity } from '@vetlock/core';

const REGISTRY_HOSTS = new Set([
  'registry.npmjs.org',
  'registry.yarnpkg.com',
  'registry.npmmirror.com',
  'npm.pkg.github.com',
]);

interface Classified {
  kind: 'plain-http' | 'non-registry-https';
  host: string;
}

/** Classify a dep spec string. Returns null when it's not a URL (semver, path, etc.). */
export function classifyDepSpec(spec: string): Classified | null {
  const s = spec.trim();
  if (s.startsWith('http://')) {
    let host = '';
    try {
      host = new URL(s).host;
    } catch { /* malformed URL — still flag as plain-http */ }
    return { kind: 'plain-http', host };
  }
  if (s.startsWith('https://')) {
    let host = '';
    try {
      host = new URL(s).host;
    } catch { return null; /* not a real URL — fall through */ }
    if (REGISTRY_HOSTS.has(host)) return null;
    return { kind: 'non-registry-https', host };
  }
  return null;
}

interface Finding0 {
  depName: string;
  spec: string;
  cls: Classified;
}

function scan(deps: Record<string, string> | undefined, oldDeps: Record<string, string> | undefined): Finding0[] {
  const out: Finding0[] = [];
  if (!deps) return out;
  for (const [name, spec] of Object.entries(deps)) {
    // Diff discipline: only NEWLY-http or CHANGED-http entries.
    const oldSpec = oldDeps?.[name];
    if (oldSpec === spec) continue;
    const cls = classifyDepSpec(spec);
    if (!cls) continue;
    out.push({ depName: name, spec, cls });
  }
  return out;
}

export const httpResolvedUrlDetector: Detector = {
  id: 'manifest-deps-http-resolved-url',
  category: 'DEPS',
  run(pair: SnapshotPair): Finding[] {
    if (!pair.new) return [];
    const oldDeps = pair.old?.manifest.dependencies;
    // Also check optional/dev/peer — an attacker can plant an http URL in any of them.
    const combined: Record<string, string> = {};
    for (const bucket of [
      pair.new.manifest.dependencies,
      pair.new.manifest.optionalDependencies,
      pair.new.manifest.peerDependencies,
    ]) {
      if (bucket) Object.assign(combined, bucket);
    }
    const oldCombined: Record<string, string> = {};
    if (pair.old) {
      for (const bucket of [
        pair.old.manifest.dependencies,
        pair.old.manifest.optionalDependencies,
        pair.old.manifest.peerDependencies,
      ]) {
        if (bucket) Object.assign(oldCombined, bucket);
      }
    }
    const hits = scan(combined, pair.old ? oldCombined : undefined);
    // If pair.old === null (new package), oldDeps is undefined by intent — every
    // matching entry is a fresh signal.
    if (hits.length === 0 && !pair.old && oldDeps === undefined) return [];
    const out: Finding[] = [];
    const isAdd = pair.old === null;
    for (const h of hits) {
      const isPlainHttp = h.cls.kind === 'plain-http';
      const severity: Severity = isPlainHttp ? 'BLOCK' : 'WARN';
      const confidence: 'high' | 'medium' = isPlainHttp ? 'high' : 'medium';
      const note = isPlainHttp
        ? 'plain-HTTP dep URL — install-time fetch is unencrypted, MITM can substitute the tarball'
        : `non-registry HTTPS dep URL (host ${h.cls.host || 'unknown'}) — bypasses npm registry integrity + publisher-trust checks`;
      out.push({
        detector: 'manifest-deps.http-resolved-url',
        category: 'DEPS',
        package: pair.new.name,
        from: pair.old?.version ?? null,
        to: pair.new.version,
        direction: isAdd ? 'added' : 'changed',
        severity,
        confidence,
        message:
          `Dependency "${h.depName}" is declared with a ${h.cls.kind} URL spec ("${h.spec}"). ${note}. ` +
          'Ported from guarddog:threat-npm-http-dependency.',
        evidence: [
          {
            file: 'package.json',
            line: 1,
            snippet: `"${h.depName}": "${h.spec}"`.slice(0, 240),
          },
        ],
        provenance: [],
      });
    }
    return out;
  },
};
