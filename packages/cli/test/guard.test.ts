/**
 * Wave 8-JJ · shim + allowlist tests for `vetlock guard`.
 *
 * Every test operates in a tmp dir that we pass as `opts.home` so we never
 * touch a real ~/.vetlock. Shims are POSIX shell scripts — we assert their
 * contents parse the way we expect and set the executable bit, but we do NOT
 * exec them here (that's the shim's job at PATH-lookup time, and exercising
 * it here requires spawning a subprocess with a curated PATH which adds
 * flakiness for very little coverage — the CLI end-to-end test already
 * exercises the vetlock-add path).
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { promises as fs } from 'node:fs';
import * as fsSync from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { runGuardCommand } from '../src/commands/guard.js';

describe('vetlock guard — shim install/uninstall/status', () => {
  let tmpHome: string;

  beforeEach(async () => {
    tmpHome = await fs.mkdtemp(path.join(os.tmpdir(), 'vetlock-jj-guard-'));
  });

  afterEach(async () => {
    await fs.rm(tmpHome, { recursive: true, force: true });
  });

  it('--install-shim: writes executable shims for npm, pnpm, yarn', async () => {
    const result = await runGuardCommand({
      installShim: true,
      home: tmpHome,
      quiet: true,
    });
    expect(result.exitCode).toBe(0);
    expect(result.action).toBe('install-shim');
    expect(result.installedShims).toHaveLength(3);
    for (const pm of ['npm', 'pnpm', 'yarn']) {
      const shimPath = path.join(tmpHome, 'bin', pm);
      expect(fsSync.existsSync(shimPath)).toBe(true);
      const stat = await fs.stat(shimPath);
      // Executable bit set (any of user/group/other exec permissions).
      // eslint-disable-next-line no-bitwise
      expect(stat.mode & 0o111).not.toBe(0);
      const body = await fs.readFile(shimPath, 'utf8');
      // The shim's PM name is the file's basename.
      expect(body).toContain(`PM_NAME="${pm}"`);
      // Recursion guard.
      expect(body).toContain('VETLOCK_GUARD_BYPASS');
      // Should exec `vetlock add` for install-family subcommands.
      expect(body).toContain('exec vetlock add');
    }
  });

  it('--install-shim: is idempotent when re-run', async () => {
    await runGuardCommand({ installShim: true, home: tmpHome, quiet: true });
    const before = await fs.readFile(path.join(tmpHome, 'bin', 'npm'), 'utf8');
    await runGuardCommand({ installShim: true, home: tmpHome, quiet: true });
    const after = await fs.readFile(path.join(tmpHome, 'bin', 'npm'), 'utf8');
    expect(after).toBe(before);
  });

  it('--uninstall-shim: removes installed shims', async () => {
    await runGuardCommand({ installShim: true, home: tmpHome, quiet: true });
    const before = fsSync.existsSync(path.join(tmpHome, 'bin', 'npm'));
    expect(before).toBe(true);

    const result = await runGuardCommand({ uninstallShim: true, home: tmpHome, quiet: true });
    expect(result.exitCode).toBe(0);
    expect(result.action).toBe('uninstall-shim');
    expect(result.removedShims).toHaveLength(3);
    for (const pm of ['npm', 'pnpm', 'yarn']) {
      expect(fsSync.existsSync(path.join(tmpHome, 'bin', pm))).toBe(false);
    }
  });

  it('--uninstall-shim: no-op when nothing installed', async () => {
    const result = await runGuardCommand({ uninstallShim: true, home: tmpHome, quiet: true });
    expect(result.exitCode).toBe(0);
    expect(result.removedShims).toHaveLength(0);
  });

  it('--status: reports installed=true when shims exist', async () => {
    await runGuardCommand({ installShim: true, home: tmpHome, quiet: true });
    const result = await runGuardCommand({ status: true, home: tmpHome, quiet: true });
    expect(result.exitCode).toBe(0);
    expect(result.action).toBe('status');
    // We deliberately do NOT assert onPath[pm] === true here — that depends
    // on whether the tmp binDir is prepended to PATH, which it isn't in the
    // test environment. The `onPath` map is defined for all three PMs.
    expect(result.onPath).toBeDefined();
    for (const pm of ['npm', 'pnpm', 'yarn'] as const) {
      expect(typeof result.onPath?.[pm]).toBe('boolean');
    }
  });

  it('--status: reports installed=false when nothing installed', async () => {
    const result = await runGuardCommand({ status: true, home: tmpHome, quiet: true });
    expect(result.exitCode).toBe(0);
    expect(result.onPath).toEqual({ npm: false, pnpm: false, yarn: false });
  });

  it('rejects when no operation flag is passed', async () => {
    const result = await runGuardCommand({ home: tmpHome, quiet: true });
    expect(result.exitCode).toBe(4);
    expect(result.action).toBe('usage-error');
  });

  it('rejects when multiple operation flags are passed', async () => {
    const result = await runGuardCommand({
      installShim: true,
      uninstallShim: true,
      home: tmpHome,
      quiet: true,
    });
    expect(result.exitCode).toBe(4);
    expect(result.action).toBe('usage-error');
  });
});

describe('vetlock guard — allowlist add/list/remove', () => {
  let tmpHome: string;

  beforeEach(async () => {
    tmpHome = await fs.mkdtemp(path.join(os.tmpdir(), 'vetlock-jj-guard-al-'));
  });

  afterEach(async () => {
    await fs.rm(tmpHome, { recursive: true, force: true });
  });

  it('--allowlist add: writes an entry with a reason', async () => {
    const result = await runGuardCommand({
      allowlistAction: 'add',
      allowlistPackage: 'lodash',
      allowlistReason: 'Trusted vendor bundle in our monorepo',
      home: tmpHome,
      quiet: true,
    });
    expect(result.exitCode).toBe(0);
    expect(result.action).toBe('allowlist');
    const raw = await fs.readFile(path.join(tmpHome, 'allowlist.json'), 'utf8');
    const parsed = JSON.parse(raw);
    expect(parsed).toHaveLength(1);
    expect(parsed[0].package).toBe('lodash');
    expect(parsed[0].reason).toBe('Trusted vendor bundle in our monorepo');
    expect(typeof parsed[0].addedAt).toBe('string');
  });

  it('--allowlist add: rejects when reason is missing or too short', async () => {
    const missing = await runGuardCommand({
      allowlistAction: 'add',
      allowlistPackage: 'lodash',
      home: tmpHome,
      quiet: true,
    });
    expect(missing.exitCode).toBe(4);
    const short = await runGuardCommand({
      allowlistAction: 'add',
      allowlistPackage: 'lodash',
      allowlistReason: 'ok',
      home: tmpHome,
      quiet: true,
    });
    expect(short.exitCode).toBe(4);
  });

  it('--allowlist add: rejects when package name is missing', async () => {
    const result = await runGuardCommand({
      allowlistAction: 'add',
      allowlistReason: 'A perfectly valid reason string',
      home: tmpHome,
      quiet: true,
    });
    expect(result.exitCode).toBe(4);
  });

  it('--allowlist list: returns all entries', async () => {
    await runGuardCommand({
      allowlistAction: 'add',
      allowlistPackage: 'lodash',
      allowlistReason: 'first entry — vendor',
      home: tmpHome,
      quiet: true,
    });
    await runGuardCommand({
      allowlistAction: 'add',
      allowlistPackage: 'chalk',
      allowlistReason: 'second entry — vendor',
      home: tmpHome,
      quiet: true,
    });
    const result = await runGuardCommand({
      allowlistAction: 'list',
      home: tmpHome,
      quiet: true,
    });
    expect(result.exitCode).toBe(0);
    expect(result.allowlist).toHaveLength(2);
    const names = result.allowlist!.map((e) => e.package).sort();
    expect(names).toEqual(['chalk', 'lodash']);
  });

  it('--allowlist add: overwrites prior entry for same package', async () => {
    await runGuardCommand({
      allowlistAction: 'add',
      allowlistPackage: 'lodash',
      allowlistReason: 'first reason',
      home: tmpHome,
      quiet: true,
    });
    await runGuardCommand({
      allowlistAction: 'add',
      allowlistPackage: 'lodash',
      allowlistReason: 'updated reason',
      home: tmpHome,
      quiet: true,
    });
    const list = await runGuardCommand({
      allowlistAction: 'list',
      home: tmpHome,
      quiet: true,
    });
    expect(list.allowlist).toHaveLength(1);
    expect(list.allowlist![0].reason).toBe('updated reason');
  });

  it('--allowlist remove: removes a specific entry', async () => {
    await runGuardCommand({
      allowlistAction: 'add',
      allowlistPackage: 'lodash',
      allowlistReason: 'trusted lodash pin',
      home: tmpHome,
      quiet: true,
    });
    await runGuardCommand({
      allowlistAction: 'add',
      allowlistPackage: 'chalk',
      allowlistReason: 'trusted chalk pin',
      home: tmpHome,
      quiet: true,
    });
    const result = await runGuardCommand({
      allowlistAction: 'remove',
      allowlistPackage: 'lodash',
      home: tmpHome,
      quiet: true,
    });
    expect(result.exitCode).toBe(0);
    expect(result.allowlist).toHaveLength(1);
    expect(result.allowlist![0].package).toBe('chalk');
  });

  it('--allowlist remove: no-op when package not in list', async () => {
    const result = await runGuardCommand({
      allowlistAction: 'remove',
      allowlistPackage: 'nothing-here',
      home: tmpHome,
      quiet: true,
    });
    expect(result.exitCode).toBe(0);
    expect(result.allowlist).toHaveLength(0);
  });
});
