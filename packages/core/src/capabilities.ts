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
  if (text.length < 500) return false;
  const lines = text.split('\n');
  const totalLines = lines.length;
  if (totalLines === 0) return false;
  const avgLen = text.length / totalLines;
  // Heuristic: mean line length > 200 chars AND fewer than 5% short lines.
  const shortLines = lines.filter((l) => l.length < 60).length;
  return avgLen > 200 && shortLines / totalLines < 0.05;
}

const URL_REGEX = /\b(https?:\/\/[^\s'"`<>]+|(?:[a-z0-9-]+\.){1,}(?:com|net|org|io|dev|co|app|xyz|ru|cn|tk|ml|ga|cf|invalid))\b/gi;

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
    envAccesses: [],
    dynamicCode: [],
    fsWriteTargets: [],
    suspiciousLiterals: [],
  };

  // .json isn't parseable as JS; still worth extracting URL literals.
  if (filePath.endsWith('.json')) {
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
  const envAccesses: EnvAccess[] = [];
  const dynamicCode: DynamicCodeSite[] = [];
  const fsWriteTargets = new Set<string>();
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

      // fs.writeFile / writeFileSync / appendFile — literal-target detection
      if (t.isMemberExpression(callee)) {
        const obj = callee.object;
        const prop = callee.property;
        if (
          t.isIdentifier(obj) &&
          (obj.name === 'fs' || obj.name === 'fsp' || obj.name === 'fsPromises') &&
          t.isIdentifier(prop) &&
          /write|append|create|unlink|rmdir|rm|copyFile|chmod|chown/i.test(prop.name)
        ) {
          const a = args[0];
          if (t.isStringLiteral(a) && a.value.length < 512) {
            fsWriteTargets.add(a.value);
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
    // String literals → URLs
    StringLiteral(path: NodePath<t.StringLiteral>) {
      const val = path.node.value;
      if (val.length > 0 && val.length < 2048) {
        for (const m of val.matchAll(URL_REGEX)) urls.add(m[0]);
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
    },
    TemplateLiteral(path: NodePath<t.TemplateLiteral>) {
      for (const q of path.node.quasis) {
        for (const m of q.value.cooked?.matchAll(URL_REGEX) ?? []) urls.add(m[0]);
      }
    },
  });

  return {
    ...base,
    networkModules: [...netMods].sort(),
    execModules: [...execMods].sort(),
    fsModules: [...fsMods].sort(),
    urlLiterals: [...urls].sort(),
    envAccesses,
    dynamicCode,
    fsWriteTargets: [...fsWriteTargets].sort(),
    suspiciousLiterals,
  };
}
