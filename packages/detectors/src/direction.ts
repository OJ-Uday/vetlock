/**
 * Shared helper for detectors: decide the direction/from field pair when a
 * finding describes a delta discovered while the whole package went from
 * pair.old to pair.new.
 *
 * When pair.old is null → the package itself was added → direction 'added',
 *   from = null (the schema requires this).
 * When pair.old exists → the package was upgraded → direction 'changed',
 *   from = pair.old.version. The finding *describes* something new within
 *   that changed package.
 *
 * We DO NOT use direction 'added' for sub-features of an upgraded package —
 * that reads ambiguously and violates the diff-framing invariant test.
 */

import type { PackageSnapshot, Direction } from '@vetlock/core';

export function directionFor(oldSnap: PackageSnapshot | null): {
  direction: Direction;
  from: string | null;
} {
  if (oldSnap === null) return { direction: 'added', from: null };
  return { direction: 'changed', from: oldSnap.version };
}
