/**
 * Universal lockfile dispatcher — auto-detect the format from filename and/or
 * content, then delegate to the right parser.
 *
 * Supported:
 *   - package-lock.json    (npm v2+, existing parser)
 *   - pnpm-lock.yaml       (pnpm v5+, js-yaml-backed parser)
 *   - yarn.lock            (yarn classic v1 + yarn berry v2+)
 *
 * Returns a `LockGraph` regardless of source format.
 */

import type { LockGraph } from './lockfile.js';
import { parseLockfile as parseNpmLock, UnsupportedLockfileError } from './lockfile.js';
import { parsePnpmLockText } from './lockfile-pnpm.js';
import { parseYarnLockText } from './lockfile-yarn.js';

export type LockfileKind = 'npm' | 'pnpm' | 'yarn-classic' | 'yarn-berry';

export interface DetectionResult {
  kind: LockfileKind;
  graph: LockGraph;
}

/**
 * Parse lockfile text — kind is detected from `filename` when provided, or by
 * peeking at the first few bytes of `text`.
 */
export function parseLockfileText(text: string, filename?: string): DetectionResult {
  const kind = detectKind(text, filename);
  switch (kind) {
    case 'npm': {
      const graph = parseNpmLock(JSON.parse(text));
      return { kind, graph };
    }
    case 'pnpm': {
      const graph = parsePnpmLockText(text);
      return { kind, graph };
    }
    case 'yarn-classic':
    case 'yarn-berry': {
      const graph = parseYarnLockText(text);
      return { kind, graph };
    }
    default:
      throw new UnsupportedLockfileError(`unable to detect lockfile format`);
  }
}

export function detectKind(text: string, filename?: string): LockfileKind {
  if (filename) {
    const base = filename.split(/[\\/]/).pop() ?? '';
    if (base === 'package-lock.json' || base === 'npm-shrinkwrap.json') return 'npm';
    if (base === 'pnpm-lock.yaml' || base === 'pnpm-lock.yml') return 'pnpm';
    if (base === 'yarn.lock') {
      // Could be classic or berry — peek at content
      return /^\s*__metadata:/m.test(text) ? 'yarn-berry' : 'yarn-classic';
    }
  }
  // Content-only detection
  const trimmed = text.trimStart();
  if (trimmed.startsWith('{')) return 'npm';
  if (/^lockfileVersion:/m.test(trimmed)) return 'pnpm';
  if (/^__metadata:/m.test(trimmed)) return 'yarn-berry';
  if (/^# yarn lockfile v1/m.test(trimmed) || /^\w[\w./@-]*@[^:]+:\s*$/m.test(trimmed)) return 'yarn-classic';
  throw new UnsupportedLockfileError('could not detect lockfile format from content');
}
