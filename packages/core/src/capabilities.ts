/**
 * Extract per-file capabilities from source text.
 *
 * Uses @babel/parser with error recovery. Files that fail to parse become
 * FileCapabilities with parseError set (fail-soft — never crash the run).
 *
 * NEVER executes any code from `text` — this module is called with strings.
 */

import * as parser from '@babel/parser';
// eslint-disable-next-line @typescript-eslint/consistent-type-imports
import * as babelTraverseNs from '@babel/traverse';
import type { NodePath } from '@babel/traverse';
import * as t from '@babel/types';
import type {
  FileCapabilities,
  EnvAccess,
  DynamicCodeSite,
  SuspiciousLiteral,
} from './finding.js';
import { foldConstants } from './fold.js';

// @babel/traverse's default export shape depends on module system. Under
// NodeNext resolution the namespace object itself is opaque; we probe both
// possible shapes at runtime.
type BabelTraverseCallable = (ast: t.Node, opts: unknown) => void;
const traverse: BabelTraverseCallable = (() => {
  const anyNs = babelTraverseNs as unknown as Record<string, unknown>;
  if (typeof anyNs === 'function') return anyNs as unknown as BabelTraverseCallable;
  if (typeof anyNs.default === 'function') return anyNs.default as BabelTraverseCallable;
  const nested = (anyNs.default as Record<string, unknown> | undefined)?.default;
  if (typeof nested === 'function') return nested as BabelTraverseCallable;
  throw new Error('Unable to resolve @babel/traverse callable export');
})();

const NETWORK_MODULES = new Set([
  // HTTP / TCP / UDP / TLS
  'http', 'https', 'net', 'dgram', 'tls', 'undici', 'axios', 'node-fetch',
  'got', 'request', 'superagent', 'ws',
  'node:http', 'node:https', 'node:net', 'node:dgram', 'node:tls',
  // REDTEAM N3 FIX: dns is a covert exfil channel. Encode data as a subdomain
  // and dns.lookup() / dns.resolve() send it to the attacker's DNS server.
  // Ignored by the network detectors until this addition.
  'dns', 'dns/promises', 'node:dns', 'node:dns/promises',
]);
const EXEC_MODULES = new Set([
  'child_process', 'worker_threads', 'vm',
  'node:child_process', 'node:worker_threads', 'node:vm',
  // REDTEAM N2 FIX: inspector.open() starts a V8 debug server that lets any
  // reachable client eval arbitrary JS in the running process — that's an
  // RCE primitive equivalent to child_process. async_hooks lets an attacker
  // monkeypatch every Promise/timer callback. trace_events and perf_hooks
  // expose Chrome trace format host callbacks with historical CVEs.
  'inspector', 'async_hooks', 'trace_events', 'perf_hooks',
  'node:inspector', 'node:async_hooks', 'node:trace_events', 'node:perf_hooks',
]);
const FS_MODULES = new Set([
  'fs', 'fs/promises', 'node:fs', 'node:fs/promises', 'graceful-fs',
]);

// Sensitive keys under process.env — used by ENV detector (packages/detectors).
// Exported so the detector layer has one source of truth.
//
// Expanded in v0.2: covers Stripe, Heroku, Supabase, DigitalOcean, wallet seeds,
// and other API credentials commonly targeted by supply-chain attacks.
export const SENSITIVE_ENV_KEYS: readonly string[] = [
  // npm ecosystem
  'NPM_TOKEN', 'NPM_AUTH_TOKEN', 'NPM_CONFIG_TOKEN',
  // GitHub
  'GITHUB_TOKEN', 'GH_TOKEN', 'GH_PAT', 'GITHUB_PAT',
  // AWS
  'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN',
  'AWS_PROFILE', 'AWS_DEFAULT_REGION',
  // GCP
  'GOOGLE_APPLICATION_CREDENTIALS', 'GCP_TOKEN', 'GOOGLE_API_KEY',
  // Azure
  'AZURE_CLIENT_ID', 'AZURE_CLIENT_SECRET', 'AZURE_TENANT_ID', 'AZURE_STORAGE_KEY',
  // Docker
  'DOCKER_AUTH_CONFIG', 'DOCKER_PASSWORD', 'DOCKER_USERNAME',
  // Stripe / payments
  'STRIPE_SECRET_KEY', 'STRIPE_API_KEY', 'STRIPE_WEBHOOK_SECRET',
  'PAYPAL_CLIENT_SECRET', 'SQUARE_ACCESS_TOKEN',
  // Heroku / Netlify / Vercel
  'HEROKU_API_KEY', 'NETLIFY_AUTH_TOKEN', 'VERCEL_TOKEN',
  // Supabase / PlanetScale / Firebase
  'SUPABASE_KEY', 'SUPABASE_SERVICE_ROLE_KEY', 'SUPABASE_JWT_SECRET',
  'PLANETSCALE_TOKEN', 'FIREBASE_TOKEN', 'FIREBASE_API_KEY',
  // Cloudflare / DigitalOcean
  'CLOUDFLARE_API_TOKEN', 'CLOUDFLARE_ACCOUNT_ID',
  'DIGITALOCEAN_TOKEN', 'DIGITALOCEAN_ACCESS_TOKEN',
  // Slack / Discord / Telegram
  'SLACK_TOKEN', 'SLACK_WEBHOOK_URL', 'DISCORD_TOKEN', 'DISCORD_WEBHOOK',
  'TELEGRAM_BOT_TOKEN',
  // Sentry / Datadog / New Relic
  'SENTRY_AUTH_TOKEN', 'DATADOG_API_KEY', 'NEW_RELIC_LICENSE_KEY',
  // OpenAI / Anthropic / other AI
  'OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'HUGGINGFACEHUB_API_TOKEN', 'CO_API_KEY',
  // Crypto / wallets — seed phrases, private keys, mnemonics
  'MNEMONIC', 'PRIVATE_KEY', 'WALLET_PRIVATE_KEY', 'ETH_PRIVATE_KEY',
  'BTC_PRIVATE_KEY', 'SOLANA_PRIVATE_KEY', 'SEED_PHRASE',
  'METAMASK_SEED', 'PHANTOM_PRIVATE_KEY',
  // JWT / auth generic
  'JWT_SECRET', 'AUTH_SECRET', 'SESSION_SECRET', 'COOKIE_SECRET',
  // Database URLs — full connect strings usually contain creds
  'DATABASE_URL', 'MONGO_URL', 'REDIS_URL', 'POSTGRES_URL',
  // MailGun / SendGrid / Postmark
  'MAILGUN_API_KEY', 'SENDGRID_API_KEY', 'POSTMARK_API_TOKEN',
  // Generic environment identity — attackers use these to fingerprint hosts
  'CI', 'HOME', 'USER', 'USERNAME',
  'SSH_AUTH_SOCK', 'GPG_AGENT_INFO',
];

/** Very rough Shannon entropy in bits/byte. */
export function shannonEntropy(bytes: Buffer | string): number {
  const buf = typeof bytes === 'string' ? Buffer.from(bytes, 'utf8') : bytes;
  if (buf.length === 0) return 0;
  const counts = new Uint32Array(256);
  for (let i = 0; i < buf.length; i++) counts[buf[i]!]++;
  let h = 0;
  for (const c of counts) {
    if (c === 0) continue;
    const p = c / buf.length;
    h -= p * Math.log2(p);
  }
  return h;
}

export function isMinified(text: string): boolean {
  // Two signals — either alone doesn't fire, together they do:
  //  1) At least one line > 400 chars (packed one-liner attack shape), OR
  //  2) mean line length > 120 with very few short lines (bundler output).
  if (text.length < 200) return false;
  const lines = text.split('\n');
  if (lines.length === 0) return false;
  const maxLen = lines.reduce((m, l) => (l.length > m ? l.length : m), 0);
  const shortLines = lines.filter((l) => l.length < 60).length;
  const avgLen = text.length / lines.length;
  if (maxLen > 400 && shortLines / lines.length < 0.3) return true;
  if (avgLen > 120 && shortLines / lines.length < 0.1) return true;
  return false;
}

// REDTEAM L4 FIX: the old regex only accepted 15 hardcoded TLDs. Attackers
// routinely use `.top`, `.pw`, `.zip`, `.click`, `.info`, `.icu`, `.site`,
// etc. — Spamhaus & abuseIPDB rank these as top-abused TLDs. Also expanded to
// include RFC-2606 reserved TLDs (.example / .test / .localhost) because
// vetlock's own defanged fixtures use those; they should be flagged in real
// packages as suspicious placeholders.
//
// Structure: alternative 1 (unchanged) — full https?:// URL.
// Alternative 2 — bare `sub.domain.tld` with any of the below TLDs.
// Alternative 3 — bare host on any 2-4 letter TLD that isn't a hardcoded
// "safe" TLD. Any random 2-4 letter TLD that isn't in ALLOWED_BENIGN_TLDS
// (com/net/org/io/dev/co/etc — the widely-legitimate ones we tolerate as
// baseline) is treated as suspect.
// v0.4.1 FP-STUDY §3b — Schemeless URL matches now split into TWO branches:
//   (i) "ambiguous TLDs" that overload with common JS/config meanings — `.app`,
//       `.dev`, `.io`, `.co`, `.name`, `.pro`, `.tech` — REQUIRE a path suffix
//       (`/`, `:`, `?`, `#`) to be counted. Rationale: vite's config code
//       references identifiers like `Cursor.app` and `Edition.app` that end in a
//       real TLD but are not URLs. Sass/PostCSS files reference `.dev` classnames.
//       AWS package names include `.co` fragments. Requiring a path suffix filters
//       these while preserving attack strings like `curl attacker.app/exfil`.
//  (ii) all other TLDs — `.com`, `.net`, `.org`, `.cloud`, `.site`, plus the
//       abused-TLD set (`.top`, `.pw`, `.zip`, `.click`, `.info`, `.us`, `.biz`,
//       `.mobi`, `.icu`, `.host`, `.online`, `.club`, `.stream`, `.party`,
//       `.science`, `.today`, `.link`, `.work`, `.xyz`, `.tk`, `.ml`, `.ga`,
//       `.cf`, `.ru`, `.cn`) and RFC-2606 reserved TLDs (`.example`, `.test`,
//       `.invalid`, `.localhost`) — keep the bare-word.tld match with no path
//       required. `.com/.net/.org` retained bare-match because a bare
//       `attacker.com` is a common attack payload shape. `.cloud/.site` retained
//       because redteam-remaining-8 L4 pins them as abused-TLD attack surface.
//
// The first `https?://` alternation catches every scheme-ful URL unchanged.
//
// Impact tracked in docs/FP-STUDY.md. Coverage preserved via:
//   test/redteam-remaining-8.test.ts REDTEAM L4 (bare abused-TLD hosts)
//   test/capabilities.test.ts URL_REGEX unit block
const URL_REGEX = /\b(https?:\/\/[^\s'"`<>]+|(?:[a-z0-9-]+\.){1,}(?:app|dev|io|co|name|pro|tech)[:/?#][^\s'"`<>]*|(?:[a-z0-9-]+\.){1,}(?:com|net|org|cloud|site|xyz|ru|cn|tk|ml|ga|cf|invalid|top|pw|zip|click|info|us|biz|mobi|icu|host|online|club|work|stream|party|science|today|link|fit|men|rest|space|store|shop|world|life|guru|example|test|localhost))\b/gi;

/** Heuristic: does this string LOOK like a filesystem path? */
const LOOKS_LIKE_PATH = /^([~./]|[A-Z]:\\|\/[a-zA-Z._-]|\.\.\/|\.\/|[a-zA-Z_-]+[/\\])/;

/**
 * Extract a string-shaped target from a Babel node representing an fs API
 * argument. Handles:
 *   - "foo/bar"                            → "foo/bar"
 *   - `foo/${x}/bar`                        → "foo//bar"  (dynamic slots blanked)
 *   - path.join(os.homedir(), '.npmrc')     → "~/.npmrc"
 *   - path.join(os.homedir(), 'Desktop', 'X') → "~/Desktop/X"
 *   - foo + '/bar'                          → concat of best-effort parts
 *
 * Returns null when we can't infer anything useful.
 */
function extractPathTarget(node: t.Node | undefined): string | null {
  if (!node) return null;
  if (t.isStringLiteral(node)) return node.value;

  if (t.isTemplateLiteral(node)) {
    const parts: string[] = [];
    for (let i = 0; i < node.quasis.length; i++) {
      parts.push(node.quasis[i]!.value.cooked ?? '');
      if (i < node.expressions.length) parts.push(''); // dynamic slot — leave blank
    }
    return parts.join('');
  }

  // path.join(...) or path.resolve(...)
  if (t.isCallExpression(node) && t.isMemberExpression(node.callee)) {
    const callObj = node.callee.object;
    const callProp = node.callee.property;
    if (
      t.isIdentifier(callObj, { name: 'path' }) &&
      t.isIdentifier(callProp) &&
      (callProp.name === 'join' || callProp.name === 'resolve')
    ) {
      const parts: string[] = [];
      for (const arg of node.arguments) {
        if (t.isStringLiteral(arg)) {
          parts.push(arg.value);
        } else if (isHomedirCall(arg)) {
          parts.push('~');
        } else {
          // Unknown dynamic value — mark with '?' so the hot-path list can still
          // match something like ~/*/.npmrc etc.
          parts.push('?');
        }
      }
      return parts.join('/');
    }
  }

  // BinaryExpression: 'foo' + '/' + 'bar' or os.homedir() + '/.npmrc'
  if (t.isBinaryExpression(node) && node.operator === '+') {
    const left = extractPathTarget(node.left as t.Node);
    const right = extractPathTarget(node.right as t.Node);
    if (left !== null && right !== null) return left + right;
    // Left side could be an os.homedir() call
    if (isHomedirCall(node.left as t.Node) && right !== null) return '~' + right;
    if (left !== null && isHomedirCall(node.right as t.Node)) return left + '~';
    return null;
  }

  return null;
}

function isHomedirCall(node: t.Node): boolean {
  if (!t.isCallExpression(node)) return false;
  const c = node.callee;
  return (
    t.isMemberExpression(c) &&
    t.isIdentifier(c.object, { name: 'os' }) &&
    t.isIdentifier(c.property, { name: 'homedir' })
  );
}

/**
 * Try to decode a long high-entropy string as either base64 or hex; if the
 * decoded bytes look like text that contains a URL, return it. Otherwise
 * return null.
 *
 * We ONLY probe literals ≥ 24 chars whose char histogram matches base64
 * (A-Za-z0-9+/= or A-Za-z0-9\-_= for URL-safe variant) or hex (0-9a-fA-F).
 */
export function tryDecodeUrl(literal: string): { url: string; encoding: 'base64' | 'hex' } | null {
  if (literal.length < 24 || literal.length > 4096) return null;
  const isBase64 = /^[A-Za-z0-9+/=_-]+$/.test(literal) && literal.length % 4 <= 1;
  const isHex = /^[0-9a-fA-F]+$/.test(literal) && literal.length % 2 === 0;
  const decode = (enc: 'base64' | 'hex'): string | null => {
    try {
      const buf = Buffer.from(
        literal,
        enc === 'base64' ? 'base64' : 'hex',
      );
      const decoded = buf.toString('utf8');
      // Reject if decoded is mostly non-printable
      let printable = 0;
      for (let i = 0; i < decoded.length; i++) {
        const c = decoded.charCodeAt(i);
        if ((c >= 32 && c < 127) || c === 9 || c === 10 || c === 13) printable++;
      }
      if (printable / decoded.length < 0.9) return null;
      return decoded;
    } catch {
      return null;
    }
  };
  if (isBase64) {
    const dec = decode('base64');
    if (dec) {
      const m = URL_REGEX.exec(dec);
      URL_REGEX.lastIndex = 0;
      if (m) return { url: m[0], encoding: 'base64' };
    }
  }
  if (isHex) {
    const dec = decode('hex');
    if (dec) {
      const m = URL_REGEX.exec(dec);
      URL_REGEX.lastIndex = 0;
      if (m) return { url: m[0], encoding: 'hex' };
    }
  }
  return null;
}

export function extractCapabilities(
  filePath: string,
  text: string,
  sha256: string,
  bytes: number,
): FileCapabilities {
  const base: FileCapabilities = {
    path: filePath,
    bytes,
    sha256,
    entropy: shannonEntropy(text),
    minified: isMinified(text),
    networkModules: [],
    execModules: [],
    fsModules: [],
    urlLiterals: [],
    encodedUrls: [],
    envAccesses: [],
    dynamicCode: [],
    fsWriteTargets: [],
    fsReadTargets: [],
    suspiciousLiterals: [],
  };

  // .json isn't parseable as JS. For package.json specifically, URL literals in
  // known metadata fields (repository, homepage, bugs, funding) are NOT signal —
  // they're benign advertising. Skip package.json entirely for URL extraction;
  // real network endpoints live in code, not manifest metadata. For other JSON
  // files, still extract URL literals (some config files legitimately contain
  // endpoints that change matters).
  if (filePath.endsWith('.json')) {
    if (filePath === 'package.json' || filePath.endsWith('/package.json')) {
      return base;
    }
    const urls = new Set<string>();
    for (const m of text.matchAll(URL_REGEX)) urls.add(m[0]);
    base.urlLiterals = [...urls];
    return base;
  }

  let ast: parser.ParseResult<t.File>;
  try {
    ast = parser.parse(text, {
      sourceType: 'unambiguous',
      allowReturnOutsideFunction: true,
      allowImportExportEverywhere: true,
      allowAwaitOutsideFunction: true,
      allowSuperOutsideMethod: true,
      allowUndeclaredExports: true,
      errorRecovery: true,
      plugins: [
        'jsx',
        'typescript',
        ['decorators', { decoratorsBeforeExport: false }],
        'classProperties',
        'optionalChaining',
        'nullishCoalescingOperator',
        'topLevelAwait',
      ],
    });
  } catch (err) {
    return {
      ...base,
      parseError: err instanceof Error ? err.message.slice(0, 240) : String(err),
    };
  }

  const netMods = new Set<string>();
  const execMods = new Set<string>();
  const fsMods = new Set<string>();
  const urls = new Set<string>();
  const encodedUrls: import('./finding.js').EncodedUrl[] = [];
  const envAccesses: EnvAccess[] = [];
  const dynamicCode: DynamicCodeSite[] = [];
  const fsWriteTargets = new Set<string>();
  const fsReadTargets = new Set<string>();
  // REDTEAM L11 FIX: detect rot13 / XOR / custom-substitution decoders by
  // co-occurrence of `String.fromCharCode` and `charCodeAt` in the same file.
  // Both are the primitives used by every per-char decoder loop — legitimate
  // packages rarely use both together outside of hash/encoding libraries.
  let hasFromCharCodeCall = false;
  let hasCharCodeAtRef = false;
  /** Set of hot-path-shaped string literals seen anywhere in the file. */
  const pathLiterals = new Set<string>();
  /** Whether the file references fs.<read*|write*> at all. */
  let hasFsWriteRef = false;
  let hasFsReadRef = false;
  /**
   * Local-variable → extracted-path map: `var x = path.join(...)` or
   * `const y = '/some/path'`. Used to resolve fs.<op>(x) calls where the target
   * is a local variable rather than an inline expression.
   */
  const localPaths = new Map<string, string>();
  /**
   * Module-alias map: `const cp = require('child_process')` → cp → child_process.
   * Also: `const e = process` and `const en = process.env` for env access.
   * Second-level: `const spawn = cp.spawn` → spawn → child_process (still).
   */
  const moduleAliases = new Map<string, string>();
  /**
   * process-related aliases:
   *   'process' aliases: value 'process' — means the identifier IS process
   *   'process.env' aliases: value 'process.env' — means the identifier IS process.env
   */
  const processAliases = new Map<string, 'process' | 'process.env'>();
  const suspiciousLiterals: SuspiciousLiteral[] = [];

  // ---- CONSTANT-FOLDING PASS (v0.2) ----
  // Resolve as many strings as possible so subsequent detector logic can
  // treat charCode/base64/hex-encoded values the same as literals.
  //
  // REDTEAM L6 FIX: wrap foldConstants in try/catch. A file with deeply
  // nested AST structures (e.g. 15000 backticks → ~7500-deep TemplateLiteral
  // chain) parses fine under errorRecovery but then overflows @babel/traverse's
  // recursive descent, raising a RangeError.  Fail-soft into a parseError
  // result so the run continues and the file is flagged, not crashed.
  let folds: ReturnType<typeof foldConstants>;
  try {
    folds = foldConstants(ast, traverse as unknown as (n: t.Node, opts: unknown) => void);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return {
      ...base,
      parseError: `traverse failed: ${msg.slice(0, 200)}`,
    };
  }

  /** Prefer the folded value of a node; fall back to `.value` for direct literals. */
  function nodeValue(node: t.Node | undefined | null): string | null {
    if (!node) return null;
    const f = folds.get(node);
    if (f !== undefined) return f;
    if (t.isStringLiteral(node)) return node.value;
    return null;
  }

  function noteModuleImport(name: string): void {
    if (NETWORK_MODULES.has(name)) netMods.add(name);
    if (EXEC_MODULES.has(name)) execMods.add(name);
    if (FS_MODULES.has(name)) fsMods.add(name);
  }

  /**
   * REDTEAM L10 helper: reparse a string as JS and route its module-imports
   * through noteModuleImport. Used for `eval("require('x')")` and
   * `new Function("return require('x')")()`. Fail-soft — a string that
   * doesn't parse is not signal, just quiet.
   *
   * Depth-limited to prevent runaway recursion. The nested pass is a fresh
   * `parser.parse` with error-recovery and no traversal — we walk manually
   * and extract only CallExpression whose callee is 'require' (or
   * require.call / require.apply / etc via the same rules as the outer
   * visitor). No fold, no aliases inside the nested source — this is a
   * best-effort recovery pass, not a full re-analysis.
   */
  function scanNestedSource(source: string, forwardImport: (name: string) => void): void {
    if (!source || source.length < 4 || source.length > 8192) return;
    let nestedAst: parser.ParseResult<t.File>;
    try {
      nestedAst = parser.parse(source, {
        sourceType: 'unambiguous',
        errorRecovery: true,
        allowReturnOutsideFunction: true,
        allowAwaitOutsideFunction: true,
        allowImportExportEverywhere: true,
      });
    } catch {
      return;
    }
    // Manual walk — depth-first, node.type-driven, no @babel/traverse cost.
    const stack: unknown[] = [nestedAst];
    let visited = 0;
    while (stack.length > 0 && visited < 5000) {
      const cur = stack.pop();
      visited++;
      if (!cur || typeof cur !== 'object') continue;
      const n = cur as t.Node;
      // Check CallExpression variants
      if (n.type === 'CallExpression') {
        const ce = n as t.CallExpression;
        const callee = ce.callee;
        const args = ce.arguments;
        // Bare require('x')
        if (t.isIdentifier(callee, { name: 'require' })) {
          const a = args[0];
          if (t.isStringLiteral(a)) forwardImport(a.value);
        }
        // require.call(null, 'x')
        if (
          t.isMemberExpression(callee) &&
          t.isIdentifier(callee.object, { name: 'require' }) &&
          t.isIdentifier(callee.property, { name: 'call' })
        ) {
          const modArg = args[1];
          if (t.isStringLiteral(modArg)) forwardImport(modArg.value);
        }
        // require.apply(null, ['x'])
        if (
          t.isMemberExpression(callee) &&
          t.isIdentifier(callee.object, { name: 'require' }) &&
          t.isIdentifier(callee.property, { name: 'apply' })
        ) {
          const arr = args[1];
          if (t.isArrayExpression(arr) && t.isStringLiteral(arr.elements[0])) {
            forwardImport(arr.elements[0].value);
          }
        }
        // process.mainModule.require('x')
        if (
          t.isMemberExpression(callee) &&
          t.isIdentifier(callee.property, { name: 'require' }) &&
          t.isMemberExpression(callee.object) &&
          t.isIdentifier(callee.object.object, { name: 'process' }) &&
          t.isIdentifier(callee.object.property, { name: 'mainModule' })
        ) {
          const a = args[0];
          if (t.isStringLiteral(a)) forwardImport(a.value);
        }
        // module.constructor._load / Module._load
        if (
          t.isMemberExpression(callee) &&
          t.isIdentifier(callee.property, { name: '_load' })
        ) {
          const a = args[0];
          if (t.isStringLiteral(a)) forwardImport(a.value);
        }
      }
      // Descend into all fields of the current node — brute-force AST walk
      for (const k of Object.keys(n)) {
        if (k === 'loc' || k === 'start' || k === 'end') continue;
        const v = (n as unknown as Record<string, unknown>)[k];
        if (Array.isArray(v)) {
          for (const child of v) if (child && typeof child === 'object') stack.push(child);
        } else if (v && typeof v === 'object') {
          stack.push(v);
        }
      }
    }
  }

  function lineOf(node: t.Node): number {
    return node.loc?.start.line ?? 0;
  }
  function snippetOf(node: t.Node): string {
    const start = node.loc?.start ?? { line: 1, column: 0 };
    const end = node.loc?.end ?? start;
    const lines = text.split('\n');
    if (start.line === end.line) {
      const line = lines[start.line - 1] ?? '';
      return line.slice(0, 240).trim();
    }
    return (lines[start.line - 1] ?? '').slice(0, 240).trim();
  }

  // REDTEAM L6 FIX: wrap the main traverse visitor in try/catch. Any traversal
  // crash (stack overflow, unexpected node shape, etc.) that slips through the
  // foldConstants guard above is caught here and fails-soft so vetlock never
  // re-throws from extractCapabilities.
  try {
  traverse(ast, {
    // Static ES module imports
    ImportDeclaration(path: NodePath<t.ImportDeclaration>) {
      noteModuleImport(path.node.source.value);
      // Alias-track default and namespace imports.
      const mod = path.node.source.value;
      for (const spec of path.node.specifiers) {
        if (t.isImportDefaultSpecifier(spec) || t.isImportNamespaceSpecifier(spec)) {
          moduleAliases.set(spec.local.name, mod);
        } else if (t.isImportSpecifier(spec)) {
          // `import { spawn } from 'child_process'` — spawn is an alias of child_process
          moduleAliases.set(spec.local.name, mod);
        }
      }
    },
    // CommonJS require(...) — plus require.call, require.apply,
    // process.mainModule.require, module.constructor._load, Module._load.
    // REDTEAM L3 FIX: attackers use `require.call(null, 'child_process')` and
    // friends to load modules via callee shapes the naive `require` visitor
    // never fired on. We now match every documented equivalent form.
    CallExpression(path: NodePath<t.CallExpression>) {
      const callee = path.node.callee;
      const args = path.node.arguments;

      // REDTEAM L11: track String.fromCharCode calls (part of the rot13
      // co-occurrence signal — see the post-pass below).
      if (
        t.isMemberExpression(callee) &&
        t.isIdentifier(callee.object, { name: 'String' }) &&
        t.isIdentifier(callee.property, { name: 'fromCharCode' })
      ) {
        hasFromCharCodeCall = true;
      }

      // Direct: `require('x')`
      if (t.isIdentifier(callee, { name: 'require' })) {
        const a = args[0];
        const asString = nodeValue(a ?? null);
        if (asString !== null) {
          noteModuleImport(asString);
        } else if (a) {
          dynamicCode.push({
            line: lineOf(path.node),
            kind: 'dynamic-require',
            snippet: snippetOf(path.node),
          });
        }
      }

      // REDTEAM L3: require.call(null, 'x') and require.apply(null, ['x']).
      // Callee is a MemberExpression whose object is Identifier 'require' and
      // property is 'call' or 'apply'. For .call the module name is arg[1];
      // for .apply it's the first element of the array in arg[1].
      if (
        t.isMemberExpression(callee) &&
        t.isIdentifier(callee.object, { name: 'require' }) &&
        t.isIdentifier(callee.property) &&
        (callee.property.name === 'call' || callee.property.name === 'apply')
      ) {
        if (callee.property.name === 'call') {
          const modArg = args[1];
          const asString = nodeValue(modArg ?? null);
          if (asString !== null) noteModuleImport(asString);
          else if (modArg) {
            dynamicCode.push({ line: lineOf(path.node), kind: 'dynamic-require', snippet: snippetOf(path.node) });
          }
        } else {
          // .apply — arg[1] is an ArrayExpression whose first element is the module name
          const arr = args[1];
          if (t.isArrayExpression(arr)) {
            const first = arr.elements[0];
            if (first) {
              const asString = nodeValue(first as t.Node);
              if (asString !== null) noteModuleImport(asString);
            }
          }
        }
      }

      // REDTEAM L3: process.mainModule.require('x') — callee is a nested
      // MemberExpression whose innermost object is 'process' and innermost
      // property is 'mainModule', with outer property 'require'.
      if (
        t.isMemberExpression(callee) &&
        t.isIdentifier(callee.property, { name: 'require' }) &&
        t.isMemberExpression(callee.object) &&
        t.isIdentifier(callee.object.object, { name: 'process' }) &&
        t.isIdentifier(callee.object.property, { name: 'mainModule' })
      ) {
        const a = args[0];
        const asString = nodeValue(a ?? null);
        if (asString !== null) noteModuleImport(asString);
      }

      // REDTEAM L3: module.constructor._load('x') and Module._load('x').
      // Both use ._load as the effective require. Callee: MemberExpression
      // with property '_load' (any object).
      if (
        t.isMemberExpression(callee) &&
        t.isIdentifier(callee.property, { name: '_load' })
      ) {
        const a = args[0];
        const asString = nodeValue(a ?? null);
        if (asString !== null) noteModuleImport(asString);
      }

      // eval(...) — record the dynamic-code site AND recursively re-parse the
      // folded argument for hidden require calls.
      if (t.isIdentifier(callee, { name: 'eval' })) {
        dynamicCode.push({
          line: lineOf(path.node),
          kind: 'eval',
          snippet: snippetOf(path.node),
        });
        // REDTEAM L10 FIX: pull out the eval argument as a string, parse it as
        // JS, and re-run the module-detection logic on the mini-AST. This
        // catches `eval("require('child_process')")` and folded variants like
        // `eval("requ" + "ire('child_process')")`.
        const argValue = nodeValue(args[0] ?? null);
        if (argValue !== null && argValue.length < 8192) {
          scanNestedSource(argValue, noteModuleImport);
        }
      }

      // REDTEAM L10 FIX: `new Function("return require('x')")()` — Babel
      // represents this as a CallExpression whose callee is a NewExpression
      // of Function. When we detect this shape, parse the function body
      // string and scan for module imports.
      if (
        t.isNewExpression(callee) &&
        t.isIdentifier(callee.callee, { name: 'Function' })
      ) {
        // Last argument of `new Function(...)` is the function body string.
        const fnArgs = callee.arguments;
        const bodyNode = fnArgs[fnArgs.length - 1];
        const bodyText = nodeValue(bodyNode as t.Node ?? null);
        if (bodyText !== null && bodyText.length < 8192) {
          scanNestedSource(bodyText, noteModuleImport);
        }
      }

      // dynamic import(...)
      if (t.isImport(callee)) {
        const a = args[0];
        const asString = nodeValue(a ?? null);
        if (asString !== null) {
          noteModuleImport(asString);
        } else if (a) {
          dynamicCode.push({
            line: lineOf(path.node),
            kind: 'dynamic-import',
            snippet: snippetOf(path.node),
          });
        }
      }

      // REDTEAM L5 FIX: Reflect.get(process.env, 'KEY') and Reflect.get(process, 'env').
      // Reflect.get is a MemberExpression callee with object 'Reflect' and property 'get'.
      // First arg is the target; second is the key literal (foldable).
      if (
        t.isMemberExpression(callee) &&
        t.isIdentifier(callee.object, { name: 'Reflect' }) &&
        t.isIdentifier(callee.property, { name: 'get' })
      ) {
        const target = args[0];
        const keyNode = args[1];
        const isEnvTarget =
          !!target &&
          t.isMemberExpression(target) &&
          t.isIdentifier(target.object, { name: 'process' }) &&
          t.isIdentifier(target.property, { name: 'env' });
        const isProcessTargetForEnv =
          !!target &&
          t.isIdentifier(target, { name: 'process' }) &&
          nodeValue(keyNode as t.Node ?? null) === 'env';
        if (isEnvTarget) {
          const line = lineOf(path.node);
          const snippet = snippetOf(path.node);
          const asString = nodeValue(keyNode as t.Node ?? null);
          if (asString !== null) {
            envAccesses.push({ line, keys: [asString], snippet });
          } else {
            envAccesses.push({ line, keys: null, snippet });
          }
        }
        if (isProcessTargetForEnv) {
          // Reflect.get(process, 'env') — treat like alias assignment target
          // when we see the parent VariableDeclarator (handled below), but
          // also record it as a whole-env enumeration signal in place.
          envAccesses.push({
            line: lineOf(path.node),
            keys: null,
            snippet: snippetOf(path.node),
          });
        }
      }

      // REDTEAM L2 FIX: Reflect.ownKeys(process.env) — whole-object enumeration.
      // Existing Object.keys/entries/values/assign are handled in the MemberExpression
      // visitor; Reflect.ownKeys was uncovered. Recognize it here.
      if (
        t.isMemberExpression(callee) &&
        t.isIdentifier(callee.object, { name: 'Reflect' }) &&
        t.isIdentifier(callee.property) &&
        (callee.property.name === 'ownKeys' || callee.property.name === 'has')
      ) {
        const target = args[0];
        if (
          target &&
          t.isMemberExpression(target) &&
          t.isIdentifier(target.object, { name: 'process' }) &&
          t.isIdentifier(target.property, { name: 'env' })
        ) {
          envAccesses.push({
            line: lineOf(path.node),
            keys: null,
            snippet: snippetOf(path.node),
          });
        }
      }

      // Alias-based capability detection:
      // A bare identifier call: spawn(...) — was spawn aliased to child_process?
      if (t.isIdentifier(callee)) {
        const aliasedMod = moduleAliases.get(callee.name);
        if (aliasedMod) noteModuleImport(aliasedMod);
      }
      // Or a member call: cp.spawn(...) — was cp aliased to child_process?
      if (t.isMemberExpression(callee) && t.isIdentifier(callee.object)) {
        const aliasedMod = moduleAliases.get(callee.object.name);
        if (aliasedMod) noteModuleImport(aliasedMod);
      }

      // fs.writeFile / writeFileSync / appendFile / readFileSync — literal-target detection
      if (t.isMemberExpression(callee)) {
        const obj = callee.object;
        const prop = callee.property;
        // Recognize fs directly OR via an alias whose module resolves to fs
        const fsLikeObj =
          t.isIdentifier(obj) &&
          ((obj.name === 'fs' || obj.name === 'fsp' || obj.name === 'fsPromises') ||
            (moduleAliases.get(obj.name) === 'fs' || moduleAliases.get(obj.name) === 'fs/promises' ||
              moduleAliases.get(obj.name) === 'node:fs' || moduleAliases.get(obj.name) === 'node:fs/promises'));
        if (fsLikeObj && t.isIdentifier(prop)) {
          const opName = prop.name;
          const isWrite = /write|append|create|unlink|rmdir|rm|copyFile|chmod|chown/i.test(opName);
          const isRead = /read/i.test(opName);
          if (isWrite) hasFsWriteRef = true;
          if (isRead) hasFsReadRef = true;
          const a = args[0];
          // Try inline extraction first, then fold, then fall back to local-variable lookup.
          let target = extractPathTarget(a);
          if (!target) {
            const folded = nodeValue(a ?? null);
            if (folded !== null) target = folded;
          }
          if (!target && a && t.isIdentifier(a)) {
            target = localPaths.get(a.name) ?? null;
          }
          if (target && target.length < 512) {
            if (isWrite) fsWriteTargets.add(target);
            else if (isRead) fsReadTargets.add(target);
          }
        }
      }
    },
    // process.env access (including aliases)
    MemberExpression(path: NodePath<t.MemberExpression>) {
      const obj = path.node.object;
      const prop = path.node.property;

      // REDTEAM L11: track .charCodeAt references (rot13 co-occurrence signal).
      if (t.isIdentifier(prop, { name: 'charCodeAt' })) {
        hasCharCodeAtRef = true;
      }

      // Directly-typed process.env access
      const isProcessEnvDirect =
        t.isMemberExpression(obj) &&
        t.isIdentifier(obj.object, { name: 'process' }) &&
        t.isIdentifier(obj.property, { name: 'env' });

      // Aliased: `const e = process.env; e.NPM_TOKEN`
      const isProcessEnvAlias =
        t.isIdentifier(obj) && processAliases.get(obj.name) === 'process.env';

      // Aliased: `const p = process; p.env.NPM_TOKEN`
      const isProcessEnvViaProcessAlias =
        t.isMemberExpression(obj) &&
        t.isIdentifier(obj.object) &&
        processAliases.get(obj.object.name) === 'process' &&
        t.isIdentifier(obj.property, { name: 'env' });

      if (isProcessEnvDirect || isProcessEnvAlias || isProcessEnvViaProcessAlias) {
        const line = lineOf(path.node);
        const snippet = snippetOf(path.node);
        // Resolve the property (with folding — catches K where K = String.fromCharCode(...))
        if (t.isIdentifier(prop) && !path.node.computed) {
          envAccesses.push({ line, keys: [prop.name], snippet });
        } else if (t.isStringLiteral(prop)) {
          envAccesses.push({ line, keys: [prop.value], snippet });
        } else {
          const folded = nodeValue(prop);
          if (folded !== null) {
            envAccesses.push({ line, keys: [folded], snippet });
          } else {
            envAccesses.push({ line, keys: null, snippet });
          }
        }
      }

      // Whole-object enumeration of process.env — many equivalent shapes.
      // REDTEAM L2 FIX: the old rule only accepted `Object.keys(process.env)`
      // and similar. Real attackers use spread (`{...process.env}`), for-in
      // (`for (const k in process.env)`), and rest-in-destructure
      // (`const { ...rest } = process.env`). These all end up with `process.env`
      // as the immediate object node whose PARENT is one of:
      //   - CallExpression with callee.object === Object (existing)
      //   - CallExpression with callee.object === Reflect (Reflect.ownKeys is handled in the CallExpression visitor above, but this covers the case where we visit process.env before its consuming CallExpression)
      //   - SpreadElement (spread into array or object)
      //   - ForInStatement (right side)
      //   - ForOfStatement (right side — Object.entries loop pattern)
      //   - AssignmentExpression right side that binds to `{ ...x }` — covered via ObjectPattern below
      if (
        t.isIdentifier(obj, { name: 'process' }) &&
        t.isIdentifier(prop, { name: 'env' })
      ) {
        const parent = path.parent;
        const isObjectKeysCall =
          parent &&
          t.isCallExpression(parent) &&
          t.isMemberExpression(parent.callee) &&
          t.isIdentifier(parent.callee.object, { name: 'Object' });
        const isSpread = parent && t.isSpreadElement(parent);
        const isForIn = parent && t.isForInStatement(parent) && parent.right === path.node;
        const isForOf = parent && t.isForOfStatement(parent) && parent.right === path.node;
        if (isObjectKeysCall || isSpread || isForIn || isForOf) {
          envAccesses.push({
            line: lineOf(path.node),
            keys: null,
            snippet: snippetOf(path.node),
          });
        }
      }
    },
    // new Function(...)
    NewExpression(path: NodePath<t.NewExpression>) {
      if (t.isIdentifier(path.node.callee, { name: 'Function' })) {
        dynamicCode.push({
          line: lineOf(path.node),
          kind: 'new-function',
          snippet: snippetOf(path.node),
        });
      }
    },
    // Track local variable bindings — for paths, module aliases, process
    // aliases, and (REDTEAM L1/L2/L5/L8) destructured env access.
    VariableDeclarator(path: NodePath<t.VariableDeclarator>) {
      const id = path.node.id;
      const init = path.node.init;
      if (!init) return;

      // REDTEAM L1/L2/L5 FIX — destructure from process.env
      // ObjectPattern binding never triggers the MemberExpression visitor
      // for `process.env.X`. We check whether the init resolves to process.env
      // (directly or via alias or via Reflect.get(process, 'env')) and, if
      // the id is an ObjectPattern, walk each destructured property.
      if (t.isObjectPattern(id)) {
        const initIsProcessEnv =
          // direct: process.env
          (t.isMemberExpression(init) &&
            t.isIdentifier(init.object, { name: 'process' }) &&
            ((t.isIdentifier(init.property, { name: 'env' }) && !init.computed) ||
              (t.isStringLiteral(init.property, { value: 'env' }) && init.computed))) ||
          // aliased: const env = process.env; const { NPM_TOKEN } = env;
          (t.isIdentifier(init) && processAliases.get(init.name) === 'process.env') ||
          // Reflect.get(process, 'env')
          (t.isCallExpression(init) &&
            t.isMemberExpression(init.callee) &&
            t.isIdentifier(init.callee.object, { name: 'Reflect' }) &&
            t.isIdentifier(init.callee.property, { name: 'get' }) &&
            init.arguments[0] &&
            t.isIdentifier(init.arguments[0], { name: 'process' }) &&
            nodeValue(init.arguments[1] as t.Node ?? null) === 'env');

        if (initIsProcessEnv) {
          const line = lineOf(path.node);
          const snippet = snippetOf(path.node);
          for (const prop of id.properties) {
            if (t.isObjectProperty(prop)) {
              const key = prop.key;
              if (t.isIdentifier(key) && !prop.computed) {
                envAccesses.push({ line, keys: [key.name], snippet });
              } else if (t.isStringLiteral(key)) {
                envAccesses.push({ line, keys: [key.value], snippet });
              } else {
                const folded = nodeValue(key as t.Node);
                if (folded !== null) envAccesses.push({ line, keys: [folded], snippet });
                else envAccesses.push({ line, keys: null, snippet });
              }
            } else if (t.isRestElement(prop)) {
              // `const { ...rest } = process.env` — whole-object enumeration
              envAccesses.push({ line, keys: null, snippet });
            }
          }
        }
        // ObjectPattern binding doesn't create a scalar varName for further
        // alias tracking; stop here.
        return;
      }

      if (!t.isIdentifier(id)) return;
      const varName = id.name;

      // Filesystem path binding: `var x = path.join(os.homedir(), '.npmrc')`
      const pathTarget = extractPathTarget(init);
      if (pathTarget && pathTarget.length < 512) {
        localPaths.set(varName, pathTarget);
      }

      // Module alias binding: `const cp = require('child_process')` — fold-aware
      if (t.isCallExpression(init) && t.isIdentifier(init.callee, { name: 'require' })) {
        const modName = nodeValue(init.arguments[0] ?? null);
        if (modName !== null) {
          moduleAliases.set(varName, modName);
        }
      }
      // REDTEAM L3 — `const cp = require.call(null, 'child_process')` alias binding
      if (
        t.isCallExpression(init) &&
        t.isMemberExpression(init.callee) &&
        t.isIdentifier(init.callee.object, { name: 'require' }) &&
        t.isIdentifier(init.callee.property) &&
        (init.callee.property.name === 'call' || init.callee.property.name === 'apply')
      ) {
        if (init.callee.property.name === 'call') {
          const modArg = init.arguments[1];
          const modName = nodeValue(modArg ?? null);
          if (modName !== null) moduleAliases.set(varName, modName);
        } else {
          const arr = init.arguments[1];
          if (t.isArrayExpression(arr)) {
            const first = arr.elements[0];
            if (first) {
              const modName = nodeValue(first as t.Node);
              if (modName !== null) moduleAliases.set(varName, modName);
            }
          }
        }
      }
      // REDTEAM L3 — `const cp = process.mainModule.require('child_process')`
      if (
        t.isCallExpression(init) &&
        t.isMemberExpression(init.callee) &&
        t.isIdentifier(init.callee.property, { name: 'require' }) &&
        t.isMemberExpression(init.callee.object) &&
        t.isIdentifier(init.callee.object.object, { name: 'process' }) &&
        t.isIdentifier(init.callee.object.property, { name: 'mainModule' })
      ) {
        const modName = nodeValue(init.arguments[0] ?? null);
        if (modName !== null) moduleAliases.set(varName, modName);
      }
      // REDTEAM L3 — `const cp = Module._load('child_process')`
      if (
        t.isCallExpression(init) &&
        t.isMemberExpression(init.callee) &&
        t.isIdentifier(init.callee.property, { name: '_load' })
      ) {
        const modName = nodeValue(init.arguments[0] ?? null);
        if (modName !== null) moduleAliases.set(varName, modName);
      }
      // Second-level alias: `const spawn = cp.spawn` — spawn inherits cp's module
      if (t.isMemberExpression(init) && t.isIdentifier(init.object)) {
        const parentMod = moduleAliases.get(init.object.name);
        if (parentMod) moduleAliases.set(varName, parentMod);
      }
      // Alias to another alias: `const cp2 = cp` — inherit
      if (t.isIdentifier(init)) {
        const parentMod = moduleAliases.get(init.name);
        if (parentMod) moduleAliases.set(varName, parentMod);
        const parentProc = processAliases.get(init.name);
        if (parentProc) processAliases.set(varName, parentProc);
      }

      // Process aliases: `const p = process` and `const e = process.env`.
      // REDTEAM L8 FIX: also handle computed-property access like
      // `process["env"]` and `process["e" + "nv"]` (fold-aware).
      if (t.isIdentifier(init, { name: 'process' })) {
        processAliases.set(varName, 'process');
      }
      if (
        t.isMemberExpression(init) &&
        t.isIdentifier(init.object, { name: 'process' })
      ) {
        // Non-computed: process.env
        if (t.isIdentifier(init.property, { name: 'env' }) && !init.computed) {
          processAliases.set(varName, 'process.env');
        }
        // Computed with string literal or fold-resolvable to 'env'
        if (init.computed) {
          const propValue = nodeValue(init.property);
          if (propValue === 'env') processAliases.set(varName, 'process.env');
        }
      }
      // REDTEAM L5: `const env = Reflect.get(process, 'env')`
      if (
        t.isCallExpression(init) &&
        t.isMemberExpression(init.callee) &&
        t.isIdentifier(init.callee.object, { name: 'Reflect' }) &&
        t.isIdentifier(init.callee.property, { name: 'get' }) &&
        init.arguments[0] &&
        t.isIdentifier(init.arguments[0], { name: 'process' }) &&
        nodeValue(init.arguments[1] as t.Node ?? null) === 'env'
      ) {
        processAliases.set(varName, 'process.env');
      }
      // Aliased-through-alias env: `const p = process; const e = p.env`
      if (
        t.isMemberExpression(init) &&
        t.isIdentifier(init.object) &&
        processAliases.get(init.object.name) === 'process' &&
        t.isIdentifier(init.property, { name: 'env' })
      ) {
        processAliases.set(varName, 'process.env');
      }
    },
    // String literals → URLs, encoded URLs, hot-path candidates
    StringLiteral(path: NodePath<t.StringLiteral>) {
      const val = path.node.value;
      if (val.length > 0 && val.length < 2048) {
        for (const m of val.matchAll(URL_REGEX)) urls.add(m[0]);
      }
      if (val.length >= 24 && val.length <= 4096) {
        const dec = tryDecodeUrl(val);
        if (dec) {
          encodedUrls.push({
            url: dec.url,
            encoding: dec.encoding,
            line: lineOf(path.node),
            encodedPreview: val.slice(0, 60),
          });
        }
      }
      if (val.length >= 200) {
        const h = shannonEntropy(val);
        if (h > 4.5) {
          suspiciousLiterals.push({
            line: lineOf(path.node),
            length: val.length,
            entropy: h,
            preview: val.slice(0, 40),
          });
        }
      }
      if (val.length > 2 && val.length < 200 && LOOKS_LIKE_PATH.test(val)) {
        pathLiterals.add(val);
      }
    },
    TemplateLiteral(path: NodePath<t.TemplateLiteral>) {
      for (const q of path.node.quasis) {
        for (const m of q.value.cooked?.matchAll(URL_REGEX) ?? []) urls.add(m[0]);
      }
    },
  });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return {
      ...base,
      parseError: `traverse failed: ${msg.slice(0, 200)}`,
    };
  }

  // ---- POST-FOLD SWEEP ----
  // Every node the fold pass resolved to a string is a candidate for URL /
  // path / encoded-URL extraction, whether it appears bare in the source or
  // inside a require()/env-access we already processed.
  for (const [node, folded] of iterateFolds(folds, ast, traverse as unknown as (n: t.Node, opts: unknown) => void)) {
    if (folded.length === 0 || folded.length > 4096) continue;
    // URL literals recovered from folding (e.g. String.fromCharCode chain that decodes to a URL)
    for (const m of folded.matchAll(URL_REGEX)) urls.add(m[0]);
    // Encoded URL probe on the folded value (a b64 blob that's already been decoded once
    // may STILL contain an encoded URL — rare, but cheap to check)
    if (folded.length >= 24) {
      const dec = tryDecodeUrl(folded);
      if (dec) {
        encodedUrls.push({
          url: dec.url,
          encoding: dec.encoding,
          line: node.loc?.start.line ?? 0,
          encodedPreview: folded.slice(0, 60),
        });
      }
    }
    if (folded.length > 2 && folded.length < 200 && LOOKS_LIKE_PATH.test(folded)) {
      pathLiterals.add(folded);
    }
  }

  // REDTEAM L11 FIX: rot13 / XOR / custom-substitution decoder detection.
  // If the file uses BOTH String.fromCharCode AND charCodeAt, it almost
  // certainly contains a per-char decoder loop — the primitive attackers use
  // to hide URLs, module names, and env-key names from static scans. We emit
  // a dynamicCode entry marking the char-arithmetic decoder shape AND promote
  // any short-but-suspect string literal in the file to a suspiciousLiteral
  // that OBF detectors will treat as signal.
  //
  // Legitimate use: hash / encoding / codec libraries. Trade-off accepted:
  // those are OFTEN legit but a package that grew this shape between versions
  // is worth flagging. The corpus / FP-smoke will confirm the noise floor.
  if (hasFromCharCodeCall && hasCharCodeAtRef) {
    dynamicCode.push({
      line: 1,
      kind: 'char-arithmetic-decoder',
      snippet: 'file uses String.fromCharCode + charCodeAt — per-char decoder shape',
    });
    // Promote any short (>=8 char) literal that could plausibly be encoded
    // exfil-URL-like content. We check for `.` + alpha content, which matches
    // rot13('exfil.example.invalid') = 'rksvy.rknzcyr.vainyvq'.
    for (const p of pathLiterals) {
      if (p.length >= 8 && /[a-zA-Z]/.test(p) && p.includes('.')) {
        // Already tracked as pathLiteral, but also mark suspicious.
        suspiciousLiterals.push({
          line: 1,
          length: p.length,
          entropy: shannonEntropy(p),
          preview: p.slice(0, 40),
        });
      }
    }
    // Also sweep the base URL-literal set — a legit-looking short domain
    // might already be there; escalate.
    // But primarily we want to catch the encoded strings that DIDN'T become
    // pathLiterals — small opaque literals. Walk the AST once more via the
    // already-computed fold map: any literal ≥ 8 chars with letters + a dot
    // in a file that has the decoder shape is suspect.
    if (ast) {
      const seen = new Set<string>();
      const walkStack: unknown[] = [ast];
      let walkCount = 0;
      while (walkStack.length > 0 && walkCount < 5000) {
        walkCount++;
        const n = walkStack.pop();
        if (!n || typeof n !== 'object') continue;
        const node = n as t.Node;
        if (t.isStringLiteral(node)) {
          const v = node.value;
          if (v.length >= 8 && v.length < 200 && /[a-zA-Z]/.test(v) && v.includes('.') && !seen.has(v)) {
            seen.add(v);
            suspiciousLiterals.push({
              line: node.loc?.start.line ?? 0,
              length: v.length,
              entropy: shannonEntropy(v),
              preview: v.slice(0, 40),
            });
          }
        }
        for (const k of Object.keys(node)) {
          if (k === 'loc' || k === 'start' || k === 'end') continue;
          const v = (node as unknown as Record<string, unknown>)[k];
          if (Array.isArray(v)) {
            for (const c of v) if (c && typeof c === 'object') walkStack.push(c);
          } else if (v && typeof v === 'object') {
            walkStack.push(v);
          }
        }
      }
    }
  }

  // Post-pass: promote suspicious path literals to fs*Targets when the file
  // references fs.read/write. This is heuristic — a file that literally
  // contains '~/.npmrc' AND uses fs.readFileSync IS almost certainly reading
  // that file, even if we can't statically follow the intermediate variable.
  if (hasFsReadRef || hasFsWriteRef) {
    // Only promote literals that match a known-sensitive marker so we don't
    // FP on innocuous config strings. See HOT_PATH_PATTERNS in the detectors
    // module for the reference list; here we use a lightweight superset.
    const SENSITIVE_HINT = /(\.npmrc|\.ssh|id_rsa|\.aws\/|wallet|keystore|keychain|\.git\/config|\.bash_history|\.zsh_history|Local Storage|Ethereum|Solana|\/etc\/|\/root\/|Desktop|Documents)/i;
    for (const p of pathLiterals) {
      if (!SENSITIVE_HINT.test(p)) continue;
      if (hasFsReadRef) fsReadTargets.add(p);
      if (hasFsWriteRef) fsWriteTargets.add(p);
    }
  }

  return {
    ...base,
    networkModules: [...netMods].sort(),
    execModules: [...execMods].sort(),
    fsModules: [...fsMods].sort(),
    urlLiterals: [...urls].sort(),
    encodedUrls,
    envAccesses,
    dynamicCode,
    fsWriteTargets: [...fsWriteTargets].sort(),
    fsReadTargets: [...fsReadTargets].sort(),
    suspiciousLiterals,
  };
}

/**
 * Yield every (node, foldedValue) pair from the fold map, SKIPPING any node
 * whose immediate parent is also folded. The parent's folded value is the
 * concatenation of the child's plus its siblings — so URL / path signal
 * present in the child is already emitted by the parent's sweep. Emitting
 * both is a metamorphic gap: for a source of shape
 *
 *     http.request("http://" + host + "/api")
 *
 * the constant-folding pass folds the inner `"http://" + host` sub-expression
 * (parent = BinaryExpression, itself folded) AND the outer whole-argument
 * BinaryExpression (parent = CallExpression, not folded). The inner-fold
 * emission is `"http://example.com"` — an intermediate value that has no
 * runtime existence. The template-literal shape `` `http://${host}/api` ``
 * folds in ONE pass with no inner-fold intermediate, so it emits only the
 * outer `"http://example.com/api"`. Both programs are runtime-equivalent, so
 * emitting the extra intermediate breaks the metamorphic invariant.
 *
 * Fix (assurance Wave 5-W → captured pair
 * assurance/corpus/metamorphic/equivalent-expression-string-concat-vs-template):
 * only emit the OUTERMOST folded value in each subtree — the value that has
 * no folded ancestor. This preserves every URL / path / encoded-URL signal
 * (the outer value strictly contains the inner) while making the sweep
 * shape-invariant across concat vs template forms of the same runtime string.
 */
function* iterateFolds(
  folds: WeakMap<t.Node, string>,
  ast: t.File,
  traverseFn: (n: t.Node, opts: unknown) => void,
): IterableIterator<[t.Node, string]> {
  const results: Array<[t.Node, string]> = [];
  traverseFn(ast, {
    enter(path: NodePath) {
      const f = folds.get(path.node);
      if (f === undefined) return;
      // If this node's parent is also folded, its parent's sweep will emit
      // a superset of anything we'd emit here — skip to avoid the concat
      // vs template asymmetry described above.
      if (path.parent && folds.has(path.parent as t.Node)) return;
      results.push([path.node, f]);
    },
  });
  for (const r of results) yield r;
}
