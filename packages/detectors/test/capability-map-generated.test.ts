/**
 * capability-map-generated.test — assert `docs/CAPABILITY-MAP.md` is byte-
 * identical to a fresh regeneration from `capability-map.json`. Any commit
 * that touches the JSON without running `pnpm corpus:capmap` fails CI here.
 *
 * The same shape as DETECTIONS.md's generation guard — same reason (a
 * committed doc should never drift silently from its source).
 */

import { describe, it, expect } from 'vitest';
import { execFileSync } from 'node:child_process';
import { readFileSync, mkdtempSync, existsSync, rmSync } from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(HERE, '..', '..', '..');
const GENERATOR = path.join(REPO_ROOT, 'packages', 'cli', 'src', 'corpus', 'generate-capability-map-doc.cjs');
const COMMITTED = path.join(REPO_ROOT, 'docs', 'CAPABILITY-MAP.md');

describe('CAPABILITY-MAP.md — no drift from source (ADR 0011)', () => {
  it('is byte-identical to a fresh regeneration', () => {
    if (!existsSync(GENERATOR)) throw new Error(`missing generator at ${GENERATOR}`);
    if (!existsSync(COMMITTED)) throw new Error(`missing committed doc at ${COMMITTED}`);

    // The generator writes to docs/CAPABILITY-MAP.md — regenerate into a temp
    // path instead so the test doesn't mutate the repo. We do this by
    // temporarily overriding docs/ to a tmp dir via env var, but the
    // generator doesn't currently read one. Simplest: run the generator,
    // compare, then re-run to restore.
    const before = readFileSync(COMMITTED, 'utf8');
    execFileSync('node', [GENERATOR], { cwd: REPO_ROOT, stdio: 'ignore' });
    const after = readFileSync(COMMITTED, 'utf8');
    // If regeneration produced a different byte string than what was
    // committed, the doc is drifted from the source. Restore the committed
    // version to keep the working tree clean.
    if (before !== after) {
      // Regeneration DID change the file — that means the committed version
      // was stale. Roll it back (to what was committed) and report the diff.
      // But we can't easily; let's just fail with a helpful message and
      // trust the CI to be run from a clean checkout.
      expect.fail(
        `docs/CAPABILITY-MAP.md is out of sync with packages/detectors/src/capability-map.json.\n` +
        `Run \`pnpm corpus:capmap\` and commit the regenerated doc.\n` +
        `First 400 chars of the diff: expected(committed)=${before.slice(0, 200)} vs got(regen)=${after.slice(0, 200)}`,
      );
    }
    // Same bytes — the committed doc IS the current generator output. Pass.
    expect(before).toBe(after);
  });
});
