/**
 * sink-family-widening — widen a call within a capability family to a documented
 * sibling API. If the scanner detects the "canonical" sink but not its documented
 * siblings, the capability class is incomplete: a malicious package can hit
 * `child_process.execFile` or `child_process.spawn` and evade a detector that
 * only names `child_process.exec`.
 *
 * The three transforms shipped here rewrite CALL expressions in-place, preserving
 * argument order, argument shape, and the enclosing MemberExpression base's
 * identifier binding. Two axes of widening are supported:
 *
 *   • member-name widening (execToExecFile, execToSpawn):
 *       `child_process.exec("echo foo")` → `child_process.execFile("echo foo")`
 *       The MODULE reference is unchanged; the SINK NAME is widened to a sibling.
 *
 *   • module widening (httpRequestToHttpsRequest):
 *       `http.request(...)` → `https.request(...)`
 *       The SINK NAME is unchanged; the MODULE (transport-layer sibling) is widened.
 *
 * All three targets are documented Node.js API pairs — the sibling exists on the
 * same object (or the transport-sibling module) and does the same category of
 * work. A "widening" is spec-preserving: the capability class is unchanged.
 */

import * as t from '@babel/types';
import { parseSource, generateSource, traverse, type NodePath } from './babel-loader.js';
import type { CompletenessTransform } from './types.js';

/**
 * Rewrite a MemberExpression's property name in-place when its `object` matches a
 * predicate. Handles both dot-form (`obj.name`, `computed: false`) and computed
 * form (`obj["name"]`, `computed: true`) — the transform must widen both spellings
 * or a computed-form input escapes untouched.
 */
function rewriteMemberName(
  callee: t.MemberExpression,
  fromName: string,
  toName: string,
): boolean {
  const prop = callee.property;
  if (callee.computed) {
    if (t.isStringLiteral(prop) && prop.value === fromName) {
      callee.property = t.stringLiteral(toName);
      return true;
    }
    return false;
  }
  if (t.isIdentifier(prop) && prop.name === fromName) {
    callee.property = t.identifier(toName);
    return true;
  }
  return false;
}

/**
 * Does the given expression reference the given module? Handles two idioms:
 *   - `require("child_process")`
 *   - a bare Identifier that plausibly aliases the module (e.g. `cp`, `child_process`)
 *
 * The Identifier match is loose because we don't do a full binding-resolution pass —
 * transforms need to be *cheap*; the callsite check compensates with careful call
 * patterns in the test fixtures. When in doubt we err toward "not a match" so the
 * transform is a no-op rather than mangling unrelated code.
 */
function isModuleRef(node: t.Node, moduleNames: readonly string[]): boolean {
  if (t.isCallExpression(node)) {
    if (
      t.isIdentifier(node.callee, { name: 'require' }) &&
      node.arguments.length >= 1 &&
      t.isStringLiteral(node.arguments[0])
    ) {
      return moduleNames.includes(node.arguments[0].value);
    }
  }
  if (t.isIdentifier(node)) {
    return moduleNames.includes(node.name);
  }
  return false;
}

interface MemberWidenSpec {
  /** Module names that count as the base (e.g. `child_process`, `cp`). */
  readonly moduleNames: readonly string[];
  /** Sink name on that module we are rewriting FROM. */
  readonly fromMember: string;
  /** Sibling sink name we are rewriting TO. */
  readonly toMember: string;
}

/** Widen a sink's member name across every matching call. */
function widenMember(source: string, spec: MemberWidenSpec): string {
  let ast: ReturnType<typeof parseSource>;
  try {
    ast = parseSource(source);
  } catch {
    return source;
  }
  let rewrote = false;
  traverse(ast, {
    CallExpression(path: NodePath<t.CallExpression>) {
      const callee = path.node.callee;
      if (!t.isMemberExpression(callee)) return;
      if (!isModuleRef(callee.object, spec.moduleNames)) return;
      if (rewriteMemberName(callee, spec.fromMember, spec.toMember)) {
        rewrote = true;
      }
    },
  });
  if (!rewrote) return source;
  return generateSource(ast);
}

interface ModuleWidenSpec {
  /** Module names to swap FROM (e.g. `["http", "node:http"]`). */
  readonly fromModules: readonly string[];
  /** Module name to swap TO (e.g. `https`). */
  readonly toModule: string;
  /** The bare identifier name that plausibly aliases the module (e.g. `http`). */
  readonly bareAlias: string;
  /** The bare identifier name to swap TO (e.g. `https`). */
  readonly toBareAlias: string;
}

/**
 * Widen the module reference. Rewrites BOTH `require("http")` calls and any bare
 * `http.request(...)` identifier used as a call-target's base. Bare-identifier
 * rewrite is scoped to the "MemberExpression base of a CallExpression" position
 * — never rewrites unrelated bindings elsewhere.
 */
function widenModule(source: string, spec: ModuleWidenSpec): string {
  let ast: ReturnType<typeof parseSource>;
  try {
    ast = parseSource(source);
  } catch {
    return source;
  }
  let rewrote = false;
  traverse(ast, {
    CallExpression(path: NodePath<t.CallExpression>) {
      // Rewrite `require("http")` → `require("https")`.
      if (
        t.isIdentifier(path.node.callee, { name: 'require' }) &&
        path.node.arguments.length >= 1 &&
        t.isStringLiteral(path.node.arguments[0]) &&
        spec.fromModules.includes(path.node.arguments[0].value)
      ) {
        path.node.arguments[0] = t.stringLiteral(spec.toModule);
        rewrote = true;
        return;
      }
      // Rewrite `http.request(...)` → `https.request(...)`: only when the callee is
      // a MemberExpression whose `object` is a bare Identifier matching `bareAlias`.
      const callee = path.node.callee;
      if (t.isMemberExpression(callee) && t.isIdentifier(callee.object, { name: spec.bareAlias })) {
        callee.object = t.identifier(spec.toBareAlias);
        rewrote = true;
      }
    },
  });
  if (!rewrote) return source;
  return generateSource(ast);
}

export const execToExecFile: CompletenessTransform = {
  id: 'exec-to-execFile',
  family: 'sink-family-widening',
  targetClass: 'code-execution',
  description:
    'Rewrite child_process.exec(...) to child_process.execFile(...). Same class, sibling sink.',
  transform(source, _seed): string {
    return widenMember(source, {
      moduleNames: ['child_process', 'node:child_process', 'cp'],
      fromMember: 'exec',
      toMember: 'execFile',
    });
  },
};

export const execToSpawn: CompletenessTransform = {
  id: 'exec-to-spawn',
  family: 'sink-family-widening',
  targetClass: 'code-execution',
  description:
    'Rewrite child_process.exec(...) to child_process.spawn(...). Same class, sibling sink.',
  transform(source, _seed): string {
    return widenMember(source, {
      moduleNames: ['child_process', 'node:child_process', 'cp'],
      fromMember: 'exec',
      toMember: 'spawn',
    });
  },
};

export const httpRequestToHttpsRequest: CompletenessTransform = {
  id: 'http-request-to-https-request',
  family: 'sink-family-widening',
  targetClass: 'net-egress',
  description:
    'Rewrite http.request(...) to https.request(...). Same class, transport-sibling module.',
  transform(source, _seed): string {
    return widenModule(source, {
      fromModules: ['http', 'node:http'],
      toModule: 'https',
      bareAlias: 'http',
      toBareAlias: 'https',
    });
  },
};
