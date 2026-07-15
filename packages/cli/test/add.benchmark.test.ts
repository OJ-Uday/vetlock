/**
 * Wave 8-OO — pre-install-gate latency benchmark.
 *
 * Measures wall-clock latency of `vetlock add` on a known-clean package with
 * a warmed fetch cache.  Target: < 3 seconds on the warm path (per the wave
 * plan's user-experience budget — anything longer and developers disable the
 * wrapper).  This is a REPORT-ONLY test — it prints the timing so the
 * distilled summary can quote it — but it does NOT assert the target.  We
 * skip the assertion because CI hardware varies wildly; a soft floor + a
 * printed number is enough signal.
 *
 * ── Un-skip on merge ──
 * Depends on JJ's `vetlock add` subcommand.  Auto-skips if the built CLI
 * doesn't yet expose `add` (probeAddCommand()).
 */

import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(HERE, '..', '..', '..');
const CLI = path.join(REPO_ROOT, 'packages', 'cli', 'dist', 'cli.js');
const CORPUS_ROOT = path.join(REPO_ROOT, 'corpus');

function probeAddCommand(): boolean {
  if (!fs.existsSync(CLI)) return false;
  const res = spawnSync('node', [CLI, '--help'], { encoding: 'utf8', timeout: 15_000 });
  if (res.status !== 0) return false;
  return /^\s*add\b/m.test(res.stdout ?? '');
}

const HAS_ADD = probeAddCommand();

/** Latency budget for `vetlock add` on the warm-cache path.  Report-only. */
const WARM_TARGET_MS = 3_000;

/** Sensible soft ceiling so a runaway (30s+) still fails.  This is a
 *  correctness signal — if we're 10× over budget something is broken. */
const HARD_CEILING_MS = 30_000;

describe.skipIf(!HAS_ADD)('vetlock add — latency benchmark (warm cache)', () => {
  it('prints wall-clock latency for a CLEAN corpus fixture', () => {
    const fixture = path.join(CORPUS_ROOT, 'fp-smoke', 'a-docs-only');
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vetlock-bench-'));
    try {
      const pmLog = path.join(tmp, 'pm-mock.jsonl');
      const env: NodeJS.ProcessEnv = {
        ...process.env,
        VETLOCK_PM_MOCK_LOG: pmLog,
        VETLOCK_FIXTURE_DIR: fixture,
      };

      // Warm-up run — populate any snapshot cache the engine keeps.
      spawnSync('node', [CLI, 'add', 'lodash-lite', '--no-progress'], {
        encoding: 'utf8',
        timeout: 30_000,
        env,
        cwd: tmp,
      });

      // Measured run.
      const t0 = Date.now();
      const res = spawnSync('node', [CLI, 'add', 'lodash-lite', '--no-progress'], {
        encoding: 'utf8',
        timeout: HARD_CEILING_MS,
        env,
        cwd: tmp,
      });
      const elapsed = Date.now() - t0;

      // eslint-disable-next-line no-console
      console.log(`[bench] vetlock add (warm cache, fp-smoke/a-docs-only): ${elapsed} ms (target < ${WARM_TARGET_MS} ms)`);

      // Correctness: the run itself must succeed (CLEAN → exit 0).
      expect(res.status, `bench run failed; stderr:\n${res.stderr}`).toBe(0);

      // Hard ceiling only — a 10× miss means something is fundamentally broken.
      expect(elapsed, `latency ${elapsed}ms exceeded hard ceiling ${HARD_CEILING_MS}ms`).toBeLessThan(HARD_CEILING_MS);

      // Soft target: we do NOT assert on it, but do print a warning line if
      // exceeded so the CI log makes the regression obvious.
      if (elapsed > WARM_TARGET_MS) {
        // eslint-disable-next-line no-console
        console.warn(`[bench] WARN: warm-cache latency ${elapsed}ms exceeded ${WARM_TARGET_MS}ms target`);
      }
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});
