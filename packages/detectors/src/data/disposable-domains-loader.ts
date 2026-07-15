/**
 * Loader for the bundled disposable-domains.json snapshot used by the
 * meta.disposable-author-domain detector.
 *
 * Snapshot: packages/detectors/src/data/disposable-domains.json. See that
 * file's $comment for source + regeneration protocol.
 */

import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

interface DisposableDoc {
  domains: string[];
}

let cached: Set<string> | null = null;

export function getDisposableDomains(): Set<string> {
  if (cached) return cached;
  const here = path.dirname(fileURLToPath(import.meta.url));
  const candidates = [
    path.join(here, 'disposable-domains.json'),
    path.join(here, '..', '..', 'src', 'data', 'disposable-domains.json'),
  ];
  let text: string | null = null;
  for (const p of candidates) {
    try { text = readFileSync(p, 'utf8'); break; } catch { /* try next */ }
  }
  if (text === null) {
    throw new Error(`could not locate disposable-domains.json. Tried: ${candidates.join(', ')}`);
  }
  const parsed = JSON.parse(text) as DisposableDoc;
  if (!Array.isArray(parsed.domains)) {
    throw new Error('disposable-domains.json is malformed — missing domains[]');
  }
  cached = new Set(parsed.domains.map((d) => d.toLowerCase()));
  return cached;
}
