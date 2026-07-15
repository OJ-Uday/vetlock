/**
 * Refresh determinism goldens — one corpus/<id>/.golden.json per fixture,
 * containing the canonicalised vetlock output for that fixture's before/after
 * lockfile pair.
 *
 * Run with:  node packages/cli/dist/corpus/generate-goldens.js
 *   (wired as the root `pnpm corpus:goldens` script)
 *
 * These files are committed. packages/cli/test/golden-drift.test.ts replays
 * every fixture and compares byte-for-byte against the committed golden — a
 * mismatch means either a real behavior change (intentional: re-run this
 * script and commit the diff) or a determinism regression (NOT intentional:
 * do not paper over it by regenerating).
 *
 * Mirrors generate-detections.ts's shape; both scripts share the corpus
 * loading + local-fetch-override plumbing via ./fixture-runner.ts.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { CORPUS_ROOT, canonicalizeResult, listFixtureIds, runFixture } from './fixture-runner.js';

async function main() {
  const ids = listFixtureIds();
  let written = 0;

  for (const id of ids) {
    const manifestPath = path.join(CORPUS_ROOT, id, 'manifest.json');
    if (!fs.existsSync(manifestPath)) continue;

    const { result } = await runFixture(id);
    const golden = {
      _schema: 'v1',
      ...(canonicalizeResult(result) as Record<string, unknown>),
    };
    const outPath = path.join(CORPUS_ROOT, id, '.golden.json');
    fs.writeFileSync(outPath, JSON.stringify(golden, null, 2) + '\n');
    written++;
    console.log(`wrote ${path.relative(process.cwd(), outPath)}`);
  }

  console.log(`\n${written} golden file(s) refreshed across ${ids.length} fixture(s).`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
