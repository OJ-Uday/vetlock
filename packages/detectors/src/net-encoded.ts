/**
 * NET encoded-endpoint detector — URLs recovered from base64/hex decoding of
 * high-entropy string literals.
 *
 * BLOCK, high. This closes the classic evasion where the exfil URL is written
 * as `Buffer.from('aHR0cHM6...', 'base64').toString()`. The URL_REGEX in the
 * capability extractor already tries to decode long literals and, when the
 * result contains a URL, records it under `file.encodedUrls`. This detector
 * emits one finding per new encoded URL not present in the old snapshot.
 *
 * NOTE: unicode-escape-only concealment currently resolves upstream as a plain
 * URL literal rather than an `encodedUrls` entry, and raw string-literal bytes
 * are not exposed on PackageSnapshot yet. TODO(core): expose raw literals if we
 * want `net.encoded-endpoint` to preserve the original concealment form.
 */

import type { Detector, Finding, PackageSnapshot, SnapshotPair } from '@vetlock/core';
import { directionFor } from './direction.js';

function collectEncoded(snap: PackageSnapshot | null): Map<string, { file: string; line: number; encoding: string; preview: string }> {
  const m = new Map<string, { file: string; line: number; encoding: string; preview: string }>();
  if (!snap) return m;
  for (const f of snap.files) {
    for (const e of f.encodedUrls) {
      if (!m.has(e.url)) m.set(e.url, { file: f.path, line: e.line, encoding: e.encoding, preview: e.encodedPreview });
    }
  }
  return m;
}

export const netEncodedDetector: Detector = {
  id: 'net-encoded',
  category: 'NET',
  run(pair: SnapshotPair): Finding[] {
    if (!pair.new) return [];
    const dir = directionFor(pair.old);
    const oldEnc = collectEncoded(pair.old);
    const newEnc = collectEncoded(pair.new);
    const out: Finding[] = [];
    for (const [url, ev] of newEnc.entries()) {
      if (oldEnc.has(url)) continue;
      out.push({
        detector: 'net.encoded-endpoint',
        category: 'NET',
        package: pair.new.name,
        from: dir.from,
        to: pair.new.version,
        direction: dir.direction,
        severity: 'BLOCK',
        confidence: 'high',
        message: `New network endpoint concealed via ${ev.encoding} encoding: ${url}`,
        evidence: [
          { file: ev.file, line: ev.line, snippet: `${ev.encoding}("${ev.preview}") → ${url}` },
        ],
        provenance: [],
      });
    }
    return out;
  },
};
