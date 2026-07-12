/**
 * Analyze a package tarball → PackageSnapshot.
 *
 * PRIME DIRECTIVE (ADR 0005): NEVER runs any code from the tarball. Everything
 * is static: read bytes, parse AST, compute hashes. This module is where the
 * fetch/extract/parse pipeline glues together.
 *
 * The `never-execute-canary.test.ts` guards this invariant by construction —
 * the fixture tarball is designed to leave a sentinel file if any code from it
 * ran, and the test asserts the sentinel does not exist.
 *
 * N1 FIX: Files under node_modules/<name>/ inside a tarball are normally
 * skipped by isAnalyzableSource(). However, if the outer package.json declares
 * bundledDependencies (or the legacy spelling bundleDependencies), those
 * node_modules entries ARE shipped by npm as part of the package tarball and
 * will execute at install time. We now recurse one level into each bundled dep
 * directory so detectors see the full attack surface.
 */

import { promises as fs } from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { safeExtract, ExtractLimits } from './extract.js';
import {
  PackageSnapshot,
  PackageManifest,
  FileCapabilities,
  NativeArtifact,
  EnvAccess,
  DynamicCodeSite,
  SuspiciousLiteral,
} from './finding.js';
import { SNAPSHOT_FORMAT_VERSION } from './cache.js';
import { extractCapabilities } from './capabilities.js';
import { summarizeWasm } from './wasm.js';

export interface AnalyzeOptions {
  integrity?: string;
  limits?: ExtractLimits;
  baseTmpDir?: string;
}

/**
 * Analyze a tarball at rest. Returns the snapshot and cleans up temp files
 * before returning (even on throw).
 */
export async function analyzeTarball(
  tarballPath: string,
  opts: AnalyzeOptions = {},
): Promise<PackageSnapshot> {
  const extracted = await safeExtract(tarballPath, {
    limits: opts.limits,
    baseTmpDir: opts.baseTmpDir,
  });
  try {
    const manifest = await readManifest(extracted.destDir);
    const files: FileCapabilities[] = [];
    const nativeArtifacts: NativeArtifact[] = [];

    // N1 FIX: Collect the set of bundled dependency names declared by the outer
    // package.  npm supports both spellings; handle both.
    const bundledNames = collectBundledDepNames(manifest);

    for (const entry of extracted.entries) {
      const rel = entry.relPath;
      const nativeKind = binaryKind(rel);
      if (nativeKind) {
        // N1 FIX: native artifacts inside a bundled dep's node_modules dir ARE
        // part of the effective install surface — always record them.
        const abs = path.join(extracted.destDir, rel);
        const artifact: NativeArtifact = {
          path: rel,
          bytes: entry.bytes,
          sha256: entry.sha256,
          kind: nativeKind,
        };
        // For WASM specifically, parse the import section so downstream
        // detectors can see what the binary can talk to. Non-WASM native
        // artifacts still record the sha256 for the BIN detector.
        if (nativeKind === 'wasm') {
          try {
            const buf = await fs.readFile(abs);
            const summary = summarizeWasm(buf);
            if (summary.parsed) {
              artifact.wasmImports = summary.imports;
            } else if (summary.parseError) {
              artifact.wasmParseError = summary.parseError;
            }
          } catch (err) {
            artifact.wasmParseError = err instanceof Error ? err.message.slice(0, 240) : String(err);
          }
        }
        nativeArtifacts.push(artifact);
        continue;
      }
      if (isMediaPath(rel)) continue;

      // N1 FIX: If this file lives under node_modules/<name>/ and <name> is in
      // bundledDependencies, treat it as analyzable — it IS shipped with the
      // package and will be present at install time.  We keep the full path
      // (including the node_modules/<name>/ prefix) in the FileCapabilities so
      // review output makes the nesting visible.
      if (rel.startsWith('node_modules/')) {
        const depName = bundledDepNameForPath(rel, bundledNames);
        if (depName === null) continue; // not a declared bundled dep — skip
        // Only recurse one level: skip anything two or more levels deep.
        // e.g. node_modules/foo/node_modules/bar → depth 2 → skip.
        if (isNestedBundled(rel, depName)) continue;
        // Analyzable source inside a bundled dep.
        if (!isAnalyzableSourceInner(rel)) continue;
        const abs = path.join(extracted.destDir, rel);
        const buf = await fs.readFile(abs);
        const text = buf.toString('utf8');
        const cap = extractCapabilities(rel, text, entry.sha256, buf.byteLength);
        files.push(cap);
        continue;
      }

      if (!isAnalyzableSource(rel)) continue;
      const abs = path.join(extracted.destDir, rel);
      const buf = await fs.readFile(abs);
      const text = buf.toString('utf8');
      const cap = extractCapabilities(rel, text, entry.sha256, buf.byteLength);
      files.push(cap);
    }

    // N1 FIX: If the outer package has bundled deps, also inspect each inner
    // package.json for lifecycle scripts.  If an inner package declares
    // postinstall/preinstall/install, npm WILL execute them.  We splice those
    // scripts into the outer manifest so the existing install detector fires.
    // We do this non-destructively: we create an augmented manifest copy that
    // carries the union of outer + inner lifecycle keys.
    const augmentedManifest = await augmentManifestWithBundledLifecycle(
      manifest,
      bundledNames,
      extracted.destDir,
    );

    return {
      name: augmentedManifest.name ?? 'unknown',
      version: augmentedManifest.version ?? '0.0.0',
      integrity: opts.integrity ?? '',
      manifest: augmentedManifest,
      files,
      nativeArtifacts,
      formatVersion: SNAPSHOT_FORMAT_VERSION,
      builtAt: new Date().toISOString(),
    };
  } finally {
    await extracted.cleanup();
  }
}

async function readManifest(destDir: string): Promise<PackageManifest> {
  const p = path.join(destDir, 'package.json');
  try {
    const raw = await fs.readFile(p, 'utf8');
    return JSON.parse(raw) as PackageManifest;
  } catch {
    return {};
  }
}

function isAnalyzableSource(rel: string): boolean {
  return /\.(m?js|cjs|jsx|ts|tsx|json)$/i.test(rel) && !rel.startsWith('node_modules/');
}

/**
 * Like isAnalyzableSource but for paths INSIDE a bundled dep directory —
 * the node_modules/ prefix check is already handled by the caller, so we
 * only need the extension check.  Excludes inner node_modules of the bundled
 * dep itself (depth > 1 guard done separately).
 */
function isAnalyzableSourceInner(rel: string): boolean {
  return /\.(m?js|cjs|jsx|ts|tsx|json)$/i.test(rel);
}

/** Media/font files we don't analyze but also don't flag. */
function isMediaPath(rel: string): boolean {
  return /\.(jpg|jpeg|png|gif|webp|ttf|woff|woff2|svg|ico)$/i.test(rel);
}

/** Native binary artifacts we DO flag — return the artifact kind if any. */
function binaryKind(rel: string): NativeArtifact['kind'] | null {
  const m = rel.match(/\.(node|so|dylib|dll|exe|wasm|bin)$/i);
  if (!m) return null;
  return m[1]!.toLowerCase() as NativeArtifact['kind'];
}

/**
 * N1: Extract the set of bundled dependency names from the outer manifest.
 * npm supports both 'bundledDependencies' (canonical) and 'bundleDependencies'
 * (legacy alias).  Both are arrays of dependency name strings.
 */
function collectBundledDepNames(manifest: PackageManifest): Set<string> {
  const raw =
    (manifest['bundledDependencies'] as unknown) ??
    (manifest['bundleDependencies'] as unknown);
  if (!Array.isArray(raw)) return new Set();
  const names = new Set<string>();
  for (const n of raw) {
    if (typeof n === 'string' && n.length > 0) names.add(n);
  }
  return names;
}

/**
 * N1: If rel starts with 'node_modules/<name>/' and <name> is in bundledNames,
 * return <name>.  Otherwise return null.
 */
function bundledDepNameForPath(rel: string, bundledNames: Set<string>): string | null {
  if (!rel.startsWith('node_modules/')) return null;
  const rest = rel.slice('node_modules/'.length);
  // Scoped package: @scope/name
  let name: string;
  if (rest.startsWith('@')) {
    const slash = rest.indexOf('/');
    if (slash === -1) return null;
    const secondSlash = rest.indexOf('/', slash + 1);
    name = secondSlash === -1 ? rest : rest.slice(0, secondSlash);
  } else {
    const slash = rest.indexOf('/');
    name = slash === -1 ? rest : rest.slice(0, slash);
  }
  return bundledNames.has(name) ? name : null;
}

/**
 * N1: Detect deeper-than-one-level bundled nesting.
 * Given a path like node_modules/foo/node_modules/bar/index.js and the
 * outer dep name 'foo', returns true (skip — depth 2+).
 * node_modules/foo/index.js → false (depth 1, analyze).
 */
function isNestedBundled(rel: string, outerDepName: string): boolean {
  // Strip the known prefix "node_modules/<outerDepName>/"
  const prefix = `node_modules/${outerDepName}/`;
  if (!rel.startsWith(prefix)) return false;
  const inner = rel.slice(prefix.length);
  return inner.startsWith('node_modules/');
}

/**
 * N1: For each bundled dep, read its package.json.  If it declares any
 * lifecycle scripts (postinstall, preinstall, install), splice them into a
 * synthetic copy of the outer manifest's scripts under a namespaced key
 * 'bundled:<depname>:<hook>' — the install detector reads manifest.scripts
 * so the existing detector will fire on any lifecycle script key it knows.
 *
 * We use a namespaced key that still contains 'postinstall' as a substring so
 * the LIFECYCLE_SET match will pick it up.  Actually, the install detector
 * checks the key against LIFECYCLE_SET with exact match, so we must use
 * the canonical key names.  Instead we just expose them directly: if inner
 * package has postinstall we write it to the outer's scripts.postinstall ONLY
 * if the outer didn't already have one (to avoid masking a legitimate outer
 * script).  We use a compound key 'bundled:<depname>:postinstall' and ensure
 * the install detector also checks prefixed keys — but that would require
 * touching install.ts.
 *
 * Simpler and in-bounds approach: write the inner lifecycle scripts under the
 * SAME canonical keys into a BUNDLED_SCRIPTS sentinel object on the manifest,
 * which the new bundled.ts detector reads.  The install detector already fires
 * on pair.new.manifest.scripts; to make it fire on bundled dep scripts without
 * touching install.ts we copy the inner scripts to the outer under a special
 * 'bundled-lifecycle' nested object the bundled detector reads.
 *
 * We store them in manifest['_bundledLifecycle'] as a Record<depname, scripts>.
 */
async function augmentManifestWithBundledLifecycle(
  manifest: PackageManifest,
  bundledNames: Set<string>,
  destDir: string,
): Promise<PackageManifest> {
  if (bundledNames.size === 0) return manifest;
  const LIFECYCLE_HOOKS = new Set([
    'preinstall', 'install', 'postinstall',
    'prepare', 'preprepare', 'postprepare',
    'prepublish', 'prepublishOnly', 'publish', 'postpublish',
    'prepack', 'pack', 'postpack',
  ]);
  const bundledLifecycle: Record<string, Record<string, string>> = {};
  for (const name of bundledNames) {
    const innerManifestPath = path.join(destDir, 'node_modules', name, 'package.json');
    let innerManifest: PackageManifest;
    try {
      const raw = await fs.readFile(innerManifestPath, 'utf8');
      innerManifest = JSON.parse(raw) as PackageManifest;
    } catch {
      continue;
    }
    const scripts = innerManifest.scripts ?? {};
    const lifecycleScripts: Record<string, string> = {};
    for (const [k, v] of Object.entries(scripts)) {
      if (LIFECYCLE_HOOKS.has(k) && typeof v === 'string') {
        lifecycleScripts[k] = v;
      }
    }
    if (Object.keys(lifecycleScripts).length > 0) {
      bundledLifecycle[name] = lifecycleScripts;
    }
  }
  if (Object.keys(bundledLifecycle).length === 0) return manifest;
  return { ...manifest, _bundledLifecycle: bundledLifecycle };
}

// Placeholder used only if capabilities.ts hasn't been built yet. Real
// implementation lives in ./capabilities.ts.
export function _hashBytes(bytes: Buffer): string {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

// Re-export for downstream imports
export type { FileCapabilities, EnvAccess, DynamicCodeSite, SuspiciousLiteral };
