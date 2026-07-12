/**
 * META detector — maintainer / publisher changes on the package manifest.
 * Fires when the set of maintainer emails or the publisher (`_npmUser.email`)
 * changed between old and new. WARN, medium.
 */

import type { Detector, Finding, SnapshotPair } from '@vetlock/core';

export const maintainerDetector: Detector = {
  id: 'meta',
  category: 'META',
  run(pair: SnapshotPair): Finding[] {
    if (!pair.old || !pair.new) return [];
    const oldEmails = collectEmails(pair.old.manifest);
    const newEmails = collectEmails(pair.new.manifest);
    if (oldEmails.length === 0 || newEmails.length === 0) return [];

    const oldSet = new Set(oldEmails);
    const newSet = new Set(newEmails);
    const removed = oldEmails.filter((e) => !newSet.has(e));
    const added = newEmails.filter((e) => !oldSet.has(e));
    if (removed.length === 0 && added.length === 0) return [];

    return [
      {
        detector: 'meta.maintainer-change',
        category: 'META',
        package: pair.new.name,
        from: pair.old.version,
        to: pair.new.version,
        direction: 'changed',
        severity: 'WARN',
        confidence: 'medium',
        message: 'Publisher/maintainer set changed between versions.',
        evidence: [
          {
            file: 'package.json',
            line: 1,
            snippet: `maintainers: [${oldEmails.join(', ')}] → [${newEmails.join(', ')}]`.slice(0, 240),
          },
        ],
        provenance: [],
      },
    ];
  },
};

function collectEmails(manifest: { maintainers?: Array<{ email?: string }>; _npmUser?: { email?: string } }): string[] {
  const set = new Set<string>();
  if (manifest.maintainers) {
    for (const m of manifest.maintainers) {
      if (m.email) set.add(m.email);
    }
  }
  if (manifest._npmUser?.email) set.add(manifest._npmUser.email);
  return [...set].sort();
}
