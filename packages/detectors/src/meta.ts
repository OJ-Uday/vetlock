/**
 * META detector — maintainer / publisher changes on the package manifest.
 *
 * Behavior (v0.2, with trust store):
 *
 *   - Old and new both fully within the built-in trust store → INFO
 *     (routine team rotation on well-known packages)
 *   - Old was a trusted publisher, new one is NOT → BLOCK (takeover shape)
 *   - Neither is on trust store → WARN (unknown package or unfamiliar org)
 *   - New is trusted, old wasn't → INFO (a maintainer joined a trusted org;
 *     unusual but not an attack shape)
 *
 * The runAll() layer additionally correlates with the user's .vetlock.json
 * `trustedPublishers` config for per-repo customization.
 */

import type { Detector, Finding, SnapshotPair, Severity } from '@vetlock/core';
import { BUILTIN_TRUST_STORE, isTrustedPublisher } from './publishers.js';

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

    const trustList = BUILTIN_TRUST_STORE[pair.new.name] ?? [];
    const oldTrusted = trustList.length > 0 && oldEmails.every(
      (e) => isTrustedPublisher(e, trustList),
    );
    const newTrusted = trustList.length > 0 && newEmails.every(
      (e) => isTrustedPublisher(e, trustList),
    );
    const anyNewTrusted = trustList.length > 0 && newEmails.some(
      (e) => isTrustedPublisher(e, trustList),
    );

    let severity: Severity = 'WARN';
    let confidence: 'high' | 'medium' | 'low' = 'medium';
    let note = '';

    if (trustList.length === 0) {
      // Package not in the built-in trust store — vanilla WARN.
      severity = 'WARN';
      confidence = 'medium';
    } else if (oldTrusted && !anyNewTrusted) {
      // Trusted publisher entirely replaced by unknown emails — classic takeover.
      severity = 'BLOCK';
      confidence = 'high';
      note = ` [takeover pattern: trusted publisher(s) replaced by unknown]`;
    } else if (oldTrusted && !newTrusted && anyNewTrusted) {
      // Some trusted stayed, an unknown was added. Still a WARN — could be
      // a legitimate new team member OR an added attacker account.
      severity = 'WARN';
      confidence = 'medium';
      note = ` [new publisher added alongside trusted team]`;
    } else if (newTrusted && oldTrusted) {
      // Rotation within trust — INFO.
      severity = 'INFO';
      confidence = 'high';
      note = ` [rotation within trusted publishers]`;
    } else if (!oldTrusted && newTrusted) {
      // Odd but not an attack shape.
      severity = 'INFO';
      confidence = 'medium';
      note = ` [publisher moved TO a trusted publisher list]`;
    }

    return [
      {
        detector: 'meta.maintainer-change',
        category: 'META',
        package: pair.new.name,
        from: pair.old.version,
        to: pair.new.version,
        direction: 'changed',
        severity,
        confidence,
        message: 'Publisher/maintainer set changed between versions.' + note,
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
