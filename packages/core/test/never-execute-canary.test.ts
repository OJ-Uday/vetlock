/**
 * @critical NEVER-EXECUTE canary. This test is the repo's soul (ADR 0005).
 *
 * We build a tarball whose every script and every .js file, if executed by
 * ANY means, would write a sentinel file to the OS tmpdir. Then we run the
 * full analyzer pipeline against it. If the sentinel exists afterwards, we've
 * broken the prime directive.
 *
 * A future PR that skips or deletes this test must justify itself in review.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { promises as fs } from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as crypto from 'node:crypto';
import { analyzeTarball } from '../src/analyze.js';
import { writeTempTgz } from './tgz-builder.js';

const CANARY_ID = crypto.randomBytes(8).toString('hex');
const CANARY_PATH = path.join(os.tmpdir(), `vetlock-canary-${CANARY_ID}`);

/**
 * The code below is intentionally scary: if it ran, the sentinel would exist.
 * Every file body writes the sentinel. The postinstall script also writes it.
 * If either the analyzer or its dependencies executed anything from this tar,
 * we'd see the sentinel.
 */
const sentinelWriter = `
const fs = require('fs');
try { fs.writeFileSync(${JSON.stringify(CANARY_PATH)}, 'PWNED', { flag: 'a' }); } catch (e) {}
module.exports = { hello: 'world' };
`;

const pkgJson = JSON.stringify(
  {
    name: 'canary-pkg',
    version: '1.0.0',
    main: 'index.js',
    scripts: {
      preinstall: `node -e "require('fs').writeFileSync('${CANARY_PATH}', 'PWNED-preinstall')"`,
      postinstall: `node -e "require('fs').writeFileSync('${CANARY_PATH}', 'PWNED-postinstall')"`,
    },
  },
  null,
  2,
);

beforeAll(async () => {
  // Best-effort cleanup in case an earlier run left a sentinel.
  await fs.unlink(CANARY_PATH).catch(() => {});
});

afterAll(async () => {
  await fs.unlink(CANARY_PATH).catch(() => {});
});

describe('NEVER-EXECUTE canary (@critical)', () => {
  it('analyzes a hostile tarball WITHOUT producing the sentinel file', async () => {
    const tgz = await writeTempTgz([
      { name: 'package/package.json', content: Buffer.from(pkgJson) },
      { name: 'package/index.js', content: Buffer.from(sentinelWriter) },
      { name: 'package/lib/util.js', content: Buffer.from(sentinelWriter) },
      { name: 'package/bin/tool.js', content: Buffer.from(sentinelWriter) },
    ]);

    const snap = await analyzeTarball(tgz);

    // Analysis succeeded — snapshot exists, files parsed.
    expect(snap.name).toBe('canary-pkg');
    expect(snap.version).toBe('1.0.0');
    expect(snap.files.length).toBeGreaterThanOrEqual(3);
    // Postinstall / preinstall scripts must be visible in the manifest — we
    // WILL want them; detectors need to see them. But they must NOT have run.
    expect(snap.manifest.scripts?.postinstall).toBeDefined();
    expect(snap.manifest.scripts?.preinstall).toBeDefined();

    // Sentinel file must NOT exist.
    let sentinelExists = false;
    try {
      await fs.access(CANARY_PATH);
      sentinelExists = true;
    } catch {
      sentinelExists = false;
    }
    expect(sentinelExists).toBe(false);
  });
});
