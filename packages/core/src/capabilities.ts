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
  'http', 'https', 'net', 'dgram', 'tls', 'undici', 'axios', 'node-fetch',
  'got', 'request', 'superagent', 'ws',
  'node:http', 'node:https', 'node:net', 'node:dgram', 'node:tls',
]);
const EXEC_MODULES = new Set([
  'child_process', 'worker_threads', 'vm',
  'node:child_process', 'node:worker_threads', 'node:vm',
]);
const FS_MODULES = new Set([
  'fs', 'fs/promises', 'node:fs', 'node:fs/promises', 'graceful-fs',
]);

// Sensitive keys under process.env — used by ENV detector (packages/detectors).
// Exported so the detector layer has one source of truth.
export const SENSITIVE_ENV_KEYS: readonly string[] = [
  'NPM_TOKEN',
  'GITHUB_TOKEN', 'GH_TOKEN', 'GH_PAT',
  'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN',
  'GOOGLE_APPLICATION_CREDENTIALS', 'GCP_TOKEN',
  'DOCKER_AUTH_CONFIG', 'DOCKER_PASSWORD',
  'CI',
  'HOME', 'USER', 'USERNAME',
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

const URL_REGEX = /\b(https?:\/\/[^\s'"`<>]+|(?:[a-z0-9-]+\.){1,}(?:com|net|org|io|dev|co|app|xyz|ru|cn|tk|ml|ga|cf|invalid))\b/gi;

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
  const suspiciousLiterals: SuspiciousLiteral[] = [];

  function noteModuleImport(name: string): void {
    if (NETWORK_MODULES.has(name)) netMods.add(name);
    if (EXEC_MODULES.has(name)) execMods.add(name);
    if (FS_MODULES.has(name)) fsMods.add(name);
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

  traverse(ast, {
    // Static ES module imports
    ImportDeclaration(path: NodePath<t.ImportDeclaration>) {
      noteModuleImport(path.node.source.value);
    },
    // CommonJS require(...)
    CallExpression(path: NodePath<t.CallExpression>) {
      const callee = path.node.callee;
      const args = path.node.arguments;

      // require('x')
      if (t.isIdentifier(callee, { name: 'require' })) {
        const a = args[0];
        if (t.isStringLiteral(a)) {
          noteModuleImport(a.value);
        } else if (a) {
          dynamicCode.push({
            line: lineOf(path.node),
            kind: 'dynamic-require',
            snippet: snippetOf(path.node),
          });
        }
      }

      // eval(...)
      if (t.isIdentifier(callee, { name: 'eval' })) {
        dynamicCode.push({
          line: lineOf(path.node),
          kind: 'eval',
          snippet: snippetOf(path.node),
        });
      }

      // new Function(...) is handled in NewExpression below.
      // dynamic import(...)
      // Babel represents dynamic import as import() being a CallExpression whose callee is Import node.
      if (t.isImport(callee)) {
        const a = args[0];
        if (t.isStringLiteral(a)) {
          noteModuleImport(a.value);
        } else if (a) {
          dynamicCode.push({
            line: lineOf(path.node),
            kind: 'dynamic-import',
            snippet: snippetOf(path.node),
          });
        }
      }

      // fs.writeFile / writeFileSync / appendFile / readFileSync — literal-target detection
      if (t.isMemberExpression(callee)) {
        const obj = callee.object;
        const prop = callee.property;
        if (
          t.isIdentifier(obj) &&
          (obj.name === 'fs' || obj.name === 'fsp' || obj.name === 'fsPromises') &&
          t.isIdentifier(prop)
        ) {
          const opName = prop.name;
          const isWrite = /write|append|create|unlink|rmdir|rm|copyFile|chmod|chown/i.test(opName);
          const isRead = /read/i.test(opName);
          if (isWrite) hasFsWriteRef = true;
          if (isRead) hasFsReadRef = true;
          const a = args[0];
          // Try inline extraction first, then fall back to local-variable lookup.
          let target = extractPathTarget(a);
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
    // process.env access
    MemberExpression(path: NodePath<t.MemberExpression>) {
      const obj = path.node.object;
      const prop = path.node.property;
      const isProcessEnv =
        t.isMemberExpression(obj) &&
        t.isIdentifier(obj.object, { name: 'process' }) &&
        t.isIdentifier(obj.property, { name: 'env' });
      if (isProcessEnv) {
        const line = lineOf(path.node);
        const snippet = snippetOf(path.node);
        if (t.isIdentifier(prop) && !path.node.computed) {
          envAccesses.push({ line, keys: [prop.name], snippet });
        } else if (t.isStringLiteral(prop)) {
          envAccesses.push({ line, keys: [prop.value], snippet });
        } else {
          envAccesses.push({ line, keys: null, snippet });
        }
      }
      // Object.keys(process.env) / Object.entries(process.env) — whole-object enumeration
      if (
        t.isIdentifier(obj, { name: 'process' }) &&
        t.isIdentifier(prop, { name: 'env' }) &&
        path.parent &&
        t.isCallExpression(path.parent) &&
        t.isMemberExpression(path.parent.callee) &&
        t.isIdentifier(path.parent.callee.object, { name: 'Object' })
      ) {
        envAccesses.push({
          line: lineOf(path.node),
          keys: null,
          snippet: snippetOf(path.node),
        });
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
    // Track local variable bindings that resolve to filesystem paths.
    VariableDeclarator(path: NodePath<t.VariableDeclarator>) {
      if (!t.isIdentifier(path.node.id)) return;
      const varName = path.node.id.name;
      const init = path.node.init;
      if (!init) return;
      const target = extractPathTarget(init);
      if (target && target.length < 512) {
        localPaths.set(varName, target);
      }
    },
    // String literals → URLs, encoded URLs, hot-path candidates
    StringLiteral(path: NodePath<t.StringLiteral>) {
      const val = path.node.value;
      if (val.length > 0 && val.length < 2048) {
        for (const m of val.matchAll(URL_REGEX)) urls.add(m[0]);
      }
      // Encoded URL probe — try base64/hex decode on long-enough opaque literals
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
      // Suspicious long high-entropy literals
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
      // Path-shape literals — record as candidate fs targets if the FILE uses fs.
      // We finalize the write-vs-read classification in a post-pass below.
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
