/**
 * Shared corpus fixture-loading + replay plumbing.
 *
 * Both generate-detections.ts and generate-goldens.ts need to: list every
 * corpus/<id> fixture (excluding _meta and fp-smoke), load its manifest +
 * lockfile pair, and run it through vetlock with a `file:./...`-aware fetch
 * override (so tarballs resolve relative to the fixture directory instead of
 * needing a live registry). This module is that shared plumbing, factored out
 * of generate-detections.ts so generate-goldens.ts doesn't have to duplicate
 * it.
 *
 * The `resolveFileRef` / makeLocalFetch shape here mirrors
 * packages/cli/test/corpus-replay.test.ts — see that file for the original
 * pattern and its rationale (relative file: refs keep the corpus portable
 * across machines / CI runners).
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runDiff, type RunResult } from '@vetlock/core';
import { runAll } from '@vetlock/detectors';

export const REPO_ROOT = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '..', '..', '..', '..',
);
export const CORPUS_ROOT = path.join(REPO_ROOT, 'corpus');

export interface Manifest {
  id: string;
  title: string;
  year: number;
  threatClass: string;
  summary: string;
  provenance: 'PUBLISHED' | 'RECONSTRUCTED';
  topology: 'direct' | 'transitive';
  expect: {
    mustFire: string[];
    verdict: string;
    known_limitation?: string;
  };
}

/**
 * List every corpus fixture id, sorted — excludes `_meta` (build scratch
 * space) and `fp-smoke` (benign-bump fixtures with a different manifest
 * shape, covered by their own test).
 */
export function listFixtureIds(): string[] {
  return fs
    .readdirSync(CORPUS_ROOT, { withFileTypes: true })
    .filter((d) => d.isDirectory() && !d.name.startsWith('_') && d.name !== 'fp-smoke')
    .map((d) => d.name)
    .sort();
}

/**
 * Resolve a lockfile's `resolved: file:...` URL to an absolute tarball path.
 * Corpus fixtures use RELATIVE (`file:./...`) refs for portability — see
 * build-all.ts::relativeFileResolved. Absolute `file:///...` refs are also
 * accepted (legacy shape / hand-rolled fixtures).
 */
export function resolveFileRef(resolved: string, fixtureDir: string): string {
  const raw = resolved.slice('file:'.length);
  if (raw.startsWith('///')) return raw.slice(2); // canonical file:/// → /abs
  if (raw.startsWith('//')) return raw.slice(raw.indexOf('/', 2)); // file://host/path
  // Relative form (file:./x, file:../x, file:x): resolve against the fixture dir.
  return path.resolve(fixtureDir, raw.replace(/^\.\//, ''));
}

function sanitize(s: string): string {
  return s.replace(/[^A-Za-z0-9._-]/g, '_');
}

function findLocalArtifact(
  dir: string,
  name: string,
  version: string,
): string | null {
  if (!fs.existsSync(dir) || !fs.statSync(dir).isDirectory()) return null;
  const exact = [
    `${sanitize(name)}-${version}.tar.gz`,
    `${sanitize(name)}-${version}.tgz`,
    `${sanitize(name)}-${version}.whl`,
  ];
  for (const base of exact) {
    const p = path.join(dir, base);
    if (fs.existsSync(p) && fs.statSync(p).isFile()) return p;
  }
  for (const entry of fs.readdirSync(dir)) {
    const p = path.join(dir, entry);
    if (!fs.statSync(p).isFile()) continue;
    if (/(\.tar\.gz|\.tgz|\.whl)$/i.test(entry) && entry.includes(version)) return p;
  }
  return null;
}

/** Build a fetchOverride bound to one fixture's directory. */
export const makeLocalFetch = (fixtureDir: string) =>
  async (ref: { resolved?: string | null; name: string; version: string }): Promise<string> => {
    if (ref.resolved?.startsWith('file:')) return resolveFileRef(ref.resolved, fixtureDir);
    const exactDir = path.join(fixtureDir, `${ref.name}-${ref.version}`);
    const fromExact = findLocalArtifact(exactDir, ref.name, ref.version);
    if (fromExact) return fromExact;
    const fallback = findLocalArtifact(path.join(fixtureDir, sanitize(ref.name)), ref.name, ref.version)
      ?? findLocalArtifact(fixtureDir, ref.name, ref.version);
    if (fallback) return fallback;
    throw new Error(`corpus fixture should not need to fetch ${ref.name}@${ref.version}`);
  };

export interface FixtureLockfiles {
  beforePath: string;
  afterPath: string;
  oldLockfilePath: string;
  newLockfilePath: string;
}

export function resolveFixtureLockfiles(fixtureDir: string): FixtureLockfiles {
  const candidates: Array<{
    before: string;
    after: string;
    hint: string;
  }> = [
    {
      before: 'lockfile.before.json',
      after: 'lockfile.after.json',
      hint: 'package-lock.json',
    },
    {
      before: 'requirements.before.txt',
      after: 'requirements.after.txt',
      hint: 'requirements.txt',
    },
    {
      before: 'poetry.lock.before',
      after: 'poetry.lock.after',
      hint: 'poetry.lock',
    },
    {
      before: 'uv.lock.before',
      after: 'uv.lock.after',
      hint: 'uv.lock',
    },
  ];
  for (const candidate of candidates) {
    const beforePath = path.join(fixtureDir, candidate.before);
    const afterPath = path.join(fixtureDir, candidate.after);
    if (fs.existsSync(beforePath) && fs.existsSync(afterPath)) {
      return {
        beforePath,
        afterPath,
        oldLockfilePath: candidate.hint,
        newLockfilePath: candidate.hint,
      };
    }
  }
  throw new Error(
    `fixture at ${fixtureDir} has no supported lockfile pair (expected one of: ` +
      candidates.map((c) => `${c.before} + ${c.after}`).join(', ') +
      ')',
  );
}

export interface FixtureRun {
  id: string;
  manifest: Manifest;
  result: RunResult;
}

/** Load manifest.json for one fixture id. */
export function loadManifest(id: string): Manifest {
  const manifestPath = path.join(CORPUS_ROOT, id, 'manifest.json');
  return JSON.parse(fs.readFileSync(manifestPath, 'utf8')) as Manifest;
}

/** Run vetlock end-to-end (before → after) for one fixture id. */
export async function runFixture(id: string): Promise<FixtureRun> {
  const fixtureDir = path.join(CORPUS_ROOT, id);
  const manifest = loadManifest(id);
  const lockfiles = resolveFixtureLockfiles(fixtureDir);
  const before = fs.readFileSync(lockfiles.beforePath, 'utf8');
  const after = fs.readFileSync(lockfiles.afterPath, 'utf8');
  const result = await runDiff(before, after, {
    runDetectors: (pair) => runAll(pair),
    fetchOverride: makeLocalFetch(fixtureDir),
    oldLockfilePath: lockfiles.oldLockfilePath,
    newLockfilePath: lockfiles.newLockfilePath,
  });
  return { id, manifest, result };
}

/** Run every non-excluded corpus fixture, in sorted id order. */
export async function runAllFixtures(): Promise<FixtureRun[]> {
  const runs: FixtureRun[] = [];
  for (const id of listFixtureIds()) {
    const manifestPath = path.join(CORPUS_ROOT, id, 'manifest.json');
    if (!fs.existsSync(manifestPath)) continue;
    runs.push(await runFixture(id));
  }
  return runs;
}

/**
 * Strip VOLATILE fields from a RunResult before it's compared/committed as a
 * determinism golden. Two categories:
 *
 *   - `durationMs` at the top level (wall-clock timing, never stable).
 *   - `builtAt` anywhere nested (PackageSnapshot's ISO build timestamp) — this
 *     doesn't appear in RunResult today (findings/changes/errors/rollup carry
 *     no snapshot echo), but we strip it defensively/recursively so this stays
 *     correct if a future field ever echoes a snapshot back.
 *
 * Everything else — findings, provenance, changes, errors, rollup — is kept
 * verbatim; those are exactly what determinism is supposed to guarantee.
 */
export function canonicalizeResult(result: RunResult): unknown {
  const { durationMs, ...rest } = result as unknown as Record<string, unknown> & {
    durationMs: number;
  };
  void durationMs; // deliberately dropped
  return stripBuiltAt(rest);
}

function stripBuiltAt(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(stripBuiltAt);
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (k === 'builtAt') continue;
      out[k] = stripBuiltAt(v);
    }
    return out;
  }
  return value;
}
