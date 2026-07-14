/**
 * Defang guard (PACKET-VETLOCK-ASSURANCE rule #2 — non-negotiable).
 *
 * Scans strings (typically the contents of an adversarial fixture or a generator's output)
 * for patterns that would make the input runnable end-to-end. The harness manufactures
 * hostile-looking inputs to test the detector, but nothing it emits may be functional
 * malware. A defanged input hits the ANALYZER; a live input hits the WORLD.
 *
 * Categories of ban:
 *
 *   NETWORK — real domains or IPs that would resolve. Allowed replacements:
 *     • *.invalid                (RFC 2606; guaranteed non-resolvable)
 *     • *.test / *.example / *.localhost   (RFC 2606)
 *     • example.com / example.org / example.net  (RFC 2606)
 *     • 127.0.0.1 / 0.0.0.0 / ::1
 *
 *   EXEC — command-line invocations that would actually do harm. Allowed:
 *     • echo, printf, true, false, `:` (bash no-op)
 *
 *   ENCODED-EXEC — base64 or long hex payloads. Longer than a small threshold and
 *     paired with a decode call → flag.
 *
 *   CRED-EXFIL — literal credential-file references paired with a network endpoint.
 *
 * The guard is intentionally over-eager on the safe side: false positives (a benign
 * fixture flagged for review) are cheap; a false negative (a live payload committed to the
 * corpus) is exactly the failure mode the rule exists to prevent.
 */

/** A single ban hit. */
export interface DefangViolation {
  readonly category: 'network' | 'exec' | 'encoded-exec' | 'cred-exfil';
  /** The matched substring (bounded — long payloads are truncated for the report). */
  readonly match: string;
  /** 1-based line number where the match starts, if line info is derivable. */
  readonly line: number;
  /** Human-readable reason for the flag. */
  readonly reason: string;
}

/** Result of scanning one string. */
export interface DefangScan {
  readonly clean: boolean;
  readonly violations: readonly DefangViolation[];
}

// ---------------------------------------------------------------------------------------------
// Allow-lists

const RESERVED_TLDS = new Set(['invalid', 'test', 'example', 'localhost']);
const RESERVED_DOMAINS = new Set(['example.com', 'example.org', 'example.net']);
const LOOPBACK_IPS = new Set(['127.0.0.1', '0.0.0.0', '::1']);
const ALLOWED_EXEC_TARGETS = new Set(['echo', 'printf', 'true', 'false', ':', 'noop']);

// ---------------------------------------------------------------------------------------------
// Detectors — pure functions from string → violations. Line numbers computed once per scan.

// URL-scheme-anchored domain detection. Purely-syntactic domain-shape matching triggers on
// JS identifiers like `fs.readFileSync` — the point of a defanged fixture is exfiltration,
// which requires a scheme, so we require the scheme too. Bare-host detection remains for
// IPs (very few false positives) and for a small set of scheme-less shell-command targets
// caught by the exec detector.
const URL_DOMAIN_RE =
  /(?:https?|ftp|ftps|ws|wss|file|smtp|smtps|imap|imaps|pop3|pop3s|ldap|ldaps|ssh|git):\/\/((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})\b/gi;
const IPV4_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;

function isDomainAllowed(domain: string): boolean {
  const lower = domain.toLowerCase();
  if (RESERVED_DOMAINS.has(lower)) return true;
  const parts = lower.split('.');
  const tld = parts[parts.length - 1];
  if (RESERVED_TLDS.has(tld)) return true;
  return false;
}

function isIpAllowed(ip: string): boolean {
  if (LOOPBACK_IPS.has(ip)) return true;
  // Any address in 127.0.0.0/8 or the unspecified 0.0.0.0/8 is loopback-ish.
  if (ip.startsWith('127.') || ip.startsWith('0.')) return true;
  // Anything not IPv4-shaped falls through (won't match).
  const parts = ip.split('.');
  if (parts.length !== 4) return false;
  for (const p of parts) {
    const n = Number(p);
    if (!Number.isInteger(n) || n < 0 || n > 255) return false; // malformed — not our concern
  }
  return false; // real routable IP
}

/** Cheap context check: if the string index sits inside a `"version": "X.Y.Z.W"` or a
 *  semver-y neighborhood, don't flag the IP-shaped substring. */
function ipLooksLikeVersion(content: string, matchIndex: number, match: string): boolean {
  // Look backwards up to 40 chars for a "version" key or a `@` (npm-alias / semver context).
  const startCtx = Math.max(0, matchIndex - 40);
  const before = content.slice(startCtx, matchIndex).toLowerCase();
  if (/"?version"?\s*[:=]\s*"?$/.test(before)) return true;
  if (/@\s*$/.test(before)) return true;
  // Look forward up to 6 chars for a semver suffix like `.16` or `-alpha`.
  const endCtx = Math.min(content.length, matchIndex + match.length + 12);
  const after = content.slice(matchIndex + match.length, endCtx);
  if (/^["'\s,)}\]]/.test(after)) return false;
  return false;
}

function detectNetwork(content: string, lineOf: (idx: number) => number): DefangViolation[] {
  const violations: DefangViolation[] = [];
  for (const match of content.matchAll(URL_DOMAIN_RE)) {
    const domain = match[1];
    if (!isDomainAllowed(domain)) {
      violations.push({
        category: 'network',
        match: domain,
        line: lineOf(match.index ?? 0),
        reason: `real-looking URL host "${domain}" — use *.invalid, *.test, *.example, or example.{com,org,net}`,
      });
    }
  }
  for (const match of content.matchAll(IPV4_RE)) {
    const ip = match[0];
    if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) continue;
    if (isIpAllowed(ip)) continue;
    if (ipLooksLikeVersion(content, match.index ?? 0, ip)) continue;
    violations.push({
      category: 'network',
      match: ip,
      line: lineOf(match.index ?? 0),
      reason: `real-looking IPv4 "${ip}" — use 127.0.0.1, 0.0.0.0, or ::1`,
    });
  }
  return violations;
}

/** Matches shell-y patterns like `curl <thing>`, `wget <thing>`, `bash -c "<thing>"`, etc.
 *  Each pattern captures the whole invocation up to a shell separator or line break so the
 *  target/body is available for allow-list inspection. */
const EXEC_PATTERNS: readonly { readonly re: RegExp; readonly label: string }[] = [
  // curl / wget: capture up to the next whitespace boundary followed by shell separator or EOL.
  { re: /\bcurl\s+[^\r\n;|&]{3,}/gi, label: 'curl' },
  { re: /\bwget\s+[^\r\n;|&]{3,}/gi, label: 'wget' },
  // nc / netcat: capture host + port. Loopback allowed — checked below.
  { re: /\bnc\s+[\w.:]+\s+\d+/gi, label: 'nc' },
  { re: /\bnetcat\s+[\w.:]+\s+\d+/gi, label: 'netcat' },
  { re: /\bpowershell(?:\.exe)?\s+[^\r\n;|&]{2,}/gi, label: 'powershell' },
  // bash/sh/python/node -c/-e: capture the quoted body (single or double).
  { re: /\bbash\s+-c\s+(?:"[^"]*"|'[^']*'|[^\r\n;|&]+)/gi, label: 'bash -c' },
  { re: /\bsh\s+-c\s+(?:"[^"]*"|'[^']*'|[^\r\n;|&]+)/gi, label: 'sh -c' },
  { re: /\bpython[23]?\s+-c\s+(?:"[^"]*"|'[^']*'|[^\r\n;|&]+)/gi, label: 'python -c' },
  { re: /\bnode\s+-e\s+(?:"[^"]*"|'[^']*'|[^\r\n;|&]+)/gi, label: 'node -e' },
];

/** Does the invocation only touch allow-listed commands? Best-effort tokeniser: strip
 *  quotes, split on shell separators, look at each command-position token. */
function bodyIsAllowListed(body: string): boolean {
  // Strip a leading/trailing pair of matching quotes.
  const unquoted = body.replace(/^\s*["']|["']\s*$/g, '').trim();
  if (unquoted === '') return true; // empty body → nothing to worry about
  // Split into command chunks by `;`, `|`, `&&`, `||`, or newline. Each chunk's first token is
  // a command. If every command is in the allow-list, we clear it.
  const chunks = unquoted.split(/;|&&|\|\||\||\n/);
  for (const chunk of chunks) {
    const trimmed = chunk.trim();
    if (trimmed === '') continue;
    const firstToken = trimmed.split(/\s+/)[0];
    if (!ALLOWED_EXEC_TARGETS.has(firstToken)) return false;
  }
  return true;
}

/** Is a text a plain URL like https://foo, or targets solely a loopback / reserved endpoint? */
function targetIsLoopbackOrReserved(text: string): boolean {
  // Extract any host-looking substrings (a URL host or a bare host token).
  const urlHosts = [...text.matchAll(/https?:\/\/([\w.-]+)/gi)].map((m) => m[1]);
  const bareHosts = [...text.matchAll(/(?<![\w.-])((?:\d{1,3}\.){3}\d{1,3})(?![\w.-])/g)].map(
    (m) => m[1],
  );
  const hosts = [...urlHosts, ...bareHosts];
  if (hosts.length === 0) return false; // nothing to whitelist — caller should still flag
  return hosts.every((h) => {
    if (isIpAllowed(h)) return true;
    if (RESERVED_DOMAINS.has(h.toLowerCase())) return true;
    const parts = h.toLowerCase().split('.');
    return RESERVED_TLDS.has(parts[parts.length - 1]);
  });
}

function detectExec(content: string, lineOf: (idx: number) => number): DefangViolation[] {
  const violations: DefangViolation[] = [];
  for (const { re, label } of EXEC_PATTERNS) {
    for (const match of content.matchAll(re)) {
      const text = match[0];

      // bash/sh/python/node -c/-e: allow when the body only invokes echo/true/false/etc.
      if (label === 'bash -c' || label === 'sh -c' || label === 'python -c' || label === 'node -e') {
        const bodyMatch = text.match(/-[ce]\s+(.+)$/s);
        const body = bodyMatch ? bodyMatch[1] : '';
        if (bodyIsAllowListed(body)) continue;
      }

      // nc / netcat / curl / wget: allow when the target is loopback or a reserved domain.
      if (label === 'nc' || label === 'netcat' || label === 'curl' || label === 'wget') {
        if (targetIsLoopbackOrReserved(text)) continue;
      }

      violations.push({
        category: 'exec',
        match: text.slice(0, 120),
        line: lineOf(match.index ?? 0),
        reason: `runnable ${label} invocation — replace with echo/true/false or a defanged marker`,
      });
    }
  }
  return violations;
}

/** base64 / hex string that looks big enough to hold something meaningful (~ ≥ 80 chars). */
const B64_RE = /[A-Za-z0-9+/]{80,}={0,2}/g;
const HEX_RE = /\b[0-9a-fA-F]{80,}\b/g;
/** Nearby decode-and-run patterns. Suggests the string is meant to be executed. */
const DECODE_EXEC_RE = /\b(atob|Buffer\.from|base64_decode|hex2bin|new\s+Function|eval)\s*\(/g;

function detectEncodedExec(content: string, lineOf: (idx: number) => number): DefangViolation[] {
  const violations: DefangViolation[] = [];
  const hasDecoder = DECODE_EXEC_RE.test(content);
  if (!hasDecoder) return violations; // large base64 blobs alone (e.g. images) are fine
  DECODE_EXEC_RE.lastIndex = 0; // reset from the .test() above
  for (const match of content.matchAll(B64_RE)) {
    const blob = match[0];
    // Skip anything that looks like a git-tree-ish or hash-ish fixed size (32/40/64/128 hex chars).
    // Not perfect but catches the "commit SHA" false positive.
    if (/^[0-9a-fA-F]+$/.test(blob) && [32, 40, 64, 128].includes(blob.length)) continue;
    violations.push({
      category: 'encoded-exec',
      match: `${blob.slice(0, 40)}…(${blob.length} chars)`,
      line: lineOf(match.index ?? 0),
      reason: 'large base64 payload found alongside a decode-and-run call (atob/Buffer.from/eval/new Function)',
    });
  }
  for (const match of content.matchAll(HEX_RE)) {
    const blob = match[0];
    if ([32, 40, 64, 128].includes(blob.length)) continue;
    violations.push({
      category: 'encoded-exec',
      match: `${blob.slice(0, 40)}…(${blob.length} chars)`,
      line: lineOf(match.index ?? 0),
      reason: 'large hex payload found alongside a decode-and-run call',
    });
  }
  return violations;
}

const CRED_PATH_RE = /~?\/[.\w-]*(?:\.ssh\/id_[rd]sa|\.aws\/credentials|\.npmrc|\.docker\/config\.json|\.gitconfig|\.env)/gi;

function detectCredExfil(content: string, lineOf: (idx: number) => number): DefangViolation[] {
  const violations: DefangViolation[] = [];
  const credMatches = [...content.matchAll(CRED_PATH_RE)];
  if (credMatches.length === 0) return violations;
  // Only flag if a network endpoint appears in the same content. A credential path alone in
  // a fixture is fine (the detector needs to see it to detect it); a credential path paired
  // with a live-looking network destination is the exfil shape.
  const networkishHits = detectNetwork(content, lineOf).length;
  if (networkishHits === 0) return violations;
  for (const match of credMatches) {
    violations.push({
      category: 'cred-exfil',
      match: match[0],
      line: lineOf(match.index ?? 0),
      reason: `credential path "${match[0]}" appears alongside a real-looking network endpoint — exfil shape`,
    });
  }
  return violations;
}

// ---------------------------------------------------------------------------------------------
// Public API

/**
 * Scan one string for defang violations. Pure — no I/O. Callers scan files by reading them
 * and passing content in; that keeps the scanner testable without a filesystem.
 */
export function scanForDefangViolations(content: string): DefangScan {
  // Precompute the line-start offset table so we can map any index → 1-based line.
  const lineStarts: number[] = [0];
  for (let i = 0; i < content.length; i++) {
    if (content.charCodeAt(i) === 10 /* '\n' */) lineStarts.push(i + 1);
  }
  const lineOf = (idx: number): number => {
    // Binary search for the greatest lineStart ≤ idx.
    let lo = 0;
    let hi = lineStarts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >>> 1;
      if (lineStarts[mid] <= idx) lo = mid;
      else hi = mid - 1;
    }
    return lo + 1;
  };

  const violations: DefangViolation[] = [
    ...detectNetwork(content, lineOf),
    ...detectExec(content, lineOf),
    ...detectEncodedExec(content, lineOf),
    ...detectCredExfil(content, lineOf),
  ];

  return { clean: violations.length === 0, violations };
}
