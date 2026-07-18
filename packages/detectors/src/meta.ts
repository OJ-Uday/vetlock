/**
 * META detector — maintainer / publisher changes on the package manifest.
 *
 * Behavior (v0.2, with trust store):
 *
 *   - Old and new both fully within the built-in trust store → INFO
 *     (routine team rotation on well-known packages)
 *   - Old was a trusted publisher, new one is NOT → BLOCK (takeover shape)
 *   - Old had emails, new has ZERO emails → BLOCK (S6 dropped-maintainer)
 *   - Neither is on trust store → WARN (unknown package or unfamiliar org)
 *   - New is trusted, old wasn't → INFO (a maintainer joined a trusted org;
 *     unusual but not an attack shape)
 *
 * REDTEAM S6 FIX: the old rule bailed early when EITHER side had zero emails.
 * That silenced the dropped-maintainer attack shape: attacker republishes a
 * compromised package with the maintainers field STRIPPED. Now we treat a
 * populated-to-empty transition as a first-class signal.
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

    // Both empty: genuine no-op — the package never had maintainers metadata.
    if (oldEmails.length === 0 && newEmails.length === 0) return [];

    // REDTEAM S6 FIX: old had maintainers, new has NONE.
    // That's the "attacker republished the tarball with the maintainers field
    // stripped" shape — either they don't know the field is a signal, or they
    // do and are actively suppressing it. Either way it's higher signal than
    // an ordinary maintainer swap.
    if (oldEmails.length > 0 && newEmails.length === 0) {
      const trustList = BUILTIN_TRUST_STORE[pair.new.name] ?? [];
      const oldWasTrusted =
        trustList.length > 0 &&
        oldEmails.every((e) => isTrustedPublisher(e, trustList));
      // If the OLD side was trusted (built-in trust store) and the new side
      // has ZERO emails, that's takeover-with-suppression: BLOCK / high.
      // If old wasn't in the trust store (obscure package), still WARN
      // because dropping maintainer info is unusual for legitimate releases.
      const severity: Severity = oldWasTrusted ? 'BLOCK' : 'WARN';
      const confidence: 'high' | 'medium' = oldWasTrusted ? 'high' : 'medium';
      const note = oldWasTrusted
        ? ' [takeover pattern: trusted publisher(s) replaced by EMPTY maintainer field — attacker suppressed the signal]'
        : ' [maintainer field emptied — unusual for legit releases]';
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
              snippet: `maintainers: [${oldEmails.join(', ')}] → []`.slice(0, 240),
            },
          ],
          provenance: [],
        },
      ];
    }

    // REDTEAM S6 corollary: new has maintainers, old had none. This is a
    // suddenly-appeared signal — package that never had metadata now does.
    // Not a takeover per se, but still worth surfacing at WARN.
    if (oldEmails.length === 0 && newEmails.length > 0) {
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
          message:
            'Publisher/maintainer set changed between versions. [new package version added maintainer metadata that was previously absent]',
          evidence: [
            {
              file: 'package.json',
              line: 1,
              snippet: `maintainers: [] → [${newEmails.join(', ')}]`.slice(0, 240),
            },
          ],
          provenance: [],
        },
      ];
    }

    // Both non-empty — original behavior.
    const oldSet = new Set(oldEmails);
    const newSet = new Set(newEmails);
    const removed = oldEmails.filter((e) => !newSet.has(e));
    const added = newEmails.filter((e) => !oldSet.has(e));
    if (removed.length === 0 && added.length === 0) return [];

    const trustList = BUILTIN_TRUST_STORE[pair.new.name] ?? [];
    const oldTrusted = trustList.length > 0 && oldEmails.every(
      (e) => isTrustedPublisher(e, trustList),
    );
    const unknownAdded = trustList.length > 0
      ? added.filter((e) => !isTrustedPublisher(e, trustList))
      : [];
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
      severity = 'WARN';
      confidence = 'medium';
    } else if (oldTrusted && !anyNewTrusted) {
      severity = 'BLOCK';
      confidence = 'high';
      note = ` [takeover pattern: trusted publisher(s) replaced by unknown]`;
    } else if (unknownAdded.length > 0) {
      severity = 'WARN';
      confidence = 'medium';
      note = ` [new unknown maintainer added: ${unknownAdded.join(', ')}]`;
    } else if (newTrusted && oldTrusted) {
      severity = 'INFO';
      confidence = 'high';
      note = ` [rotation within trusted publishers]`;
    } else if (!oldTrusted && newTrusted) {
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
