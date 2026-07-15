/**
 * PyPI EcosystemAdapter (P4c — ADR 0009).
 *
 * Ties fetch + extract + capability extraction into a PackageSnapshot
 * matching the shape the shared engine uses for npm. Because the snapshot
 * shape is universal, the SAME detectors that run on npm findings
 * (`@vetlock/detectors`) run on PyPI findings unchanged.
 *
 * NEVER runs any Python code from an analysed artifact. See ADR 0005.
 */

import { promises as fs } from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import type {
  PackageSnapshot,
  PackageManifest,
  FileCapabilities,
  NativeArtifact,
} from './finding.js';
import { SNAPSHOT_FORMAT_VERSION } from './cache.js';
import {
  fetchPypiArtifact,
  extractPypiArtifact,
  type PypiPackageRef,
  type PypiFetchedArtifact,
} from './artifact-pypi.js';
import {
  extractPythonCapabilities,
  isPythonSource,
  analyzeSetupPy,
  analyzePyproject,
} from './capability-pypi.js';
import type { ExtractLimits } from './extract.js';

export interface AnalyzePypiOptions {
  integrity?: string;
  limits?: ExtractLimits;
  baseTmpDir?: string;
  registry?: string;
}

/**
 * Analyse a fetched PyPI artifact at rest. Mirrors `analyzeTarball` from
 * analyze.ts. Cleans up temp files before returning (even on throw).
 */
export async function analyzePypiArtifactFile(
  artifact: PypiFetchedArtifact,
  opts: AnalyzePypiOptions & { name?: string; version?: string } = {},
): Promise<PackageSnapshot> {
  const extracted = await extractPypiArtifact(artifact, {
    limits: opts.limits,
    baseTmpDir: opts.baseTmpDir,
  });
  try {
    const files: FileCapabilities[] = [];
    const nativeArtifacts: NativeArtifact[] = [];

    // Read the manifest sources. Wheels have a `<pkg>-<ver>.dist-info/METADATA`
    // file (RFC-822 style) at the top level; sdists have `setup.py` and
    // optionally `pyproject.toml`. We synthesise a `PackageManifest` shape
    // that carries the fields the existing detectors read (name, version,
    // scripts, dependencies).
    const manifest = await buildPypiManifest(extracted.destDir, artifact.kind, opts);

    for (const entry of extracted.entries) {
      const rel = entry.relPath;
      const nativeKind = pypiBinaryKind(rel);
      if (nativeKind) {
        nativeArtifacts.push({
          path: rel,
          bytes: entry.bytes,
          sha256: entry.sha256,
          kind: nativeKind,
        });
        continue;
      }
      // Analyse Python source files
      if (isPythonSource(rel)) {
        const abs = path.join(extracted.destDir, rel);
        try {
          const buf = await fs.readFile(abs);
          const text = buf.toString('utf8');
          const cap = extractPythonCapabilities(rel, text, entry.sha256, buf.byteLength);
          files.push(cap);
        } catch (err) {
          files.push({
            path: rel,
            bytes: entry.bytes,
            sha256: entry.sha256,
            parseError: err instanceof Error ? err.message.slice(0, 240) : String(err),
            entropy: 0,
            minified: false,
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
          });
        }
      }
    }

    return {
      name: manifest.name ?? opts.name ?? 'unknown',
      version: manifest.version ?? opts.version ?? '0.0.0',
      integrity: opts.integrity ?? '',
      manifest,
      files,
      nativeArtifacts,
      formatVersion: SNAPSHOT_FORMAT_VERSION,
      builtAt: new Date().toISOString(),
    };
  } finally {
    await extracted.cleanup();
  }
}

/**
 * Convenience: fetch → analyse.  Used by the engine's dispatch layer when
 * `ecosystem === 'pypi'`.
 */
export async function analyzePypi(
  ref: PypiPackageRef,
  opts: AnalyzePypiOptions = {},
): Promise<PackageSnapshot> {
  const artifact = await fetchPypiArtifact({
    ...ref,
    registry: ref.registry ?? opts.registry,
  });
  try {
    return await analyzePypiArtifactFile(artifact, {
      ...opts,
      name: ref.name,
      version: ref.version,
    });
  } finally {
    // Only unlink temp files we fetched ourselves. Callers that pass
    // localArtifact own the file lifetime.
    if (!ref.localArtifact) {
      await fs.unlink(artifact.path).catch(() => {});
    }
  }
}

/**
 * Build a PackageManifest from the extracted PyPI artifact files.
 *
 * Wheel: read `<pkg>-<ver>.dist-info/METADATA` (RFC-822) + `entry_points.txt`
 * Sdist: read `PKG-INFO` (also RFC-822) + `pyproject.toml` + `setup.py`
 *
 * The `scripts` field is populated with a synthetic 'install' key when
 * setup.py contains a hostile top-level side effect. That reuses the JS
 * `install.script-added` detector (ADR 0011 completeness — we don't invent
 * a Python-specific detector where a universal one already fits).
 */
async function buildPypiManifest(
  destDir: string,
  kind: 'wheel' | 'sdist',
  opts: { name?: string; version?: string },
): Promise<PackageManifest> {
  const manifest: PackageManifest = {
    // Ecosystem breadcrumb — meta detector already tolerates arbitrary keys
    // on PackageManifest, and this lets a debug renderer show origin.
    ecosystem: 'pypi',
  };

  // Look for METADATA (wheel) / PKG-INFO (sdist)
  const metadataCandidates = [
    'METADATA',
    'PKG-INFO',
  ];
  // Also scan .dist-info directories inside a wheel
  try {
    const topLevel = await fs.readdir(destDir);
    for (const name of topLevel) {
      if (/\.dist-info$/.test(name)) {
        metadataCandidates.unshift(path.join(name, 'METADATA'));
      }
      if (/\.egg-info$/.test(name)) {
        metadataCandidates.unshift(path.join(name, 'PKG-INFO'));
      }
    }
  } catch { /* dir doesn't exist yet — fine */ }

  for (const rel of metadataCandidates) {
    const abs = path.join(destDir, rel);
    try {
      const text = await fs.readFile(abs, 'utf8');
      parseRfc822Metadata(text, manifest);
      break;
    } catch { /* try next */ }
  }

  // pyproject.toml — entry points and scripts
  try {
    const pyprojectText = await fs.readFile(path.join(destDir, 'pyproject.toml'), 'utf8');
    const hooks = analyzePyproject(pyprojectText);
    if (hooks.entryPoints.length > 0) {
      // Record in a way the bin detector could read (bin is JS-specific, but
      // the meta trail is preserved for reviewers). We deliberately do NOT
      // convert entry_points into a synthetic lifecycle script — a
      // console_scripts entry is a bin, not an install hook. It only runs
      // when the user invokes the CLI.
      manifest['entryPoints'] = hooks.entryPoints;
    }
    for (const [k, v] of Object.entries(hooks.scripts)) {
      manifest.scripts ??= {};
      manifest.scripts[k] = v;
    }
  } catch { /* pyproject.toml absent — fine */ }

  // setup.py — install-time hostile side-effect detection
  try {
    const setupPyText = await fs.readFile(path.join(destDir, 'setup.py'), 'utf8');
    const hooks = analyzeSetupPy(setupPyText);
    for (const [k, v] of Object.entries(hooks.scripts)) {
      manifest.scripts ??= {};
      manifest.scripts[k] = v;
    }
  } catch { /* setup.py absent — fine */ }

  // Fall-back: use ref name/version if metadata was unreadable.
  if (!manifest.name && opts.name) manifest.name = opts.name;
  if (!manifest.version && opts.version) manifest.version = opts.version;

  void kind; // hook for future divergent handling
  return manifest;
}

/**
 * Parse an RFC-822-style METADATA / PKG-INFO block. Extracts:
 *   Name, Version, Requires-Dist (→ dependencies), Author-email → maintainers
 */
function parseRfc822Metadata(text: string, manifest: PackageManifest): void {
  const lines = text.split(/\r?\n/);
  let currentKey: string | null = null;
  let currentVal = '';
  const kv: Array<[string, string]> = [];
  const seen = new Set<string>();
  for (const line of lines) {
    if (line === '') break; // headers end at blank line
    if (/^\s/.test(line) && currentKey) {
      currentVal += ' ' + line.trim();
      continue;
    }
    const m = line.match(/^([A-Za-z][A-Za-z0-9-]*):\s*(.*)$/);
    if (!m) continue;
    const key = m[1]!.toLowerCase();
    if ((key === 'name' || key === 'version') && seen.has(key)) {
      throw new Error(`Malformed METADATA: duplicate field "${key}"`);
    }
    seen.add(key);
    if (currentKey) kv.push([currentKey, currentVal]);
    currentKey = m[1]!;
    currentVal = m[2]!;
  }
  if (currentKey) kv.push([currentKey, currentVal]);

  const deps: Record<string, string> = {};
  const maintainers: Array<{ name?: string; email?: string }> = [];
  for (const [k, v] of kv) {
    switch (k) {
      case 'Name':
        manifest.name = v.trim();
        break;
      case 'Version':
        manifest.version = v.trim();
        break;
      case 'Requires-Dist': {
        // Format: `pkgname (>=1.0)` or `pkgname; python_version < "3.9"`
        const m = v.match(/^([A-Za-z0-9_.\-[\]]+)\s*(?:\(([^)]+)\))?/);
        if (m) {
          const name = m[1]!.replace(/\[.*?\]$/, '');
          const spec = m[2] ?? '';
          if (name) deps[name] = spec;
        }
        break;
      }
      case 'Author-email':
      case 'Maintainer-email':
        maintainers.push({ email: v.trim() });
        break;
      case 'Author':
      case 'Maintainer':
        maintainers.push({ name: v.trim() });
        break;
    }
  }
  if (Object.keys(deps).length > 0) manifest.dependencies = deps;
  if (maintainers.length > 0) manifest.maintainers = maintainers;
}

function pypiBinaryKind(rel: string): NativeArtifact['kind'] | null {
  const m = rel.match(/\.(so|dylib|dll|exe|wasm|bin|pyd)$/i);
  if (!m) return null;
  const ext = m[1]!.toLowerCase();
  // .pyd is Windows Python's shared library — treat as .dll
  if (ext === 'pyd') return 'dll';
  return ext as NativeArtifact['kind'];
}

/**
 * Trivial handle used by the engine to know which adapter to route through
 * for a given ecosystem tag. Not currently used at runtime — the engine
 * dispatches by lockfile filename hint via lockfile-any.ts. Kept as an
 * export so future code can register additional adapters uniformly.
 */
export const PYPI_ADAPTER_ID = 'pypi';

// Utility for use inside sha256 computations across pypi module ecosystem.
export function _sha256HexOf(buf: Buffer): string {
  return crypto.createHash('sha256').update(buf).digest('hex');
}
