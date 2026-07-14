/**
 * DifferentialLedger unit tests.
 *
 * The ledger is the honest record — its contract is:
 *   - add() records a pending (unclassified) finding
 *   - classify() moves it into a classified delta with a rationale
 *   - report() renders every classified delta into markdown
 *   - isClean() is true iff every delta is classified (empty ledgers are clean by
 *     vacuous truth)
 *   - save() writes a stable-formatted JSON file that round-trips
 *
 * These tests pin those semantics.
 */

import { describe, it, expect } from 'vitest';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  DifferentialLedger,
  type LedgerFile,
  type ScannerFinding,
} from '../../src/differential/index.js';

function findingFixture(overrides: Partial<ScannerFinding> = {}): ScannerFinding {
  return {
    scanner: 'npm-audit',
    package: 'minimist',
    severity: 'CRITICAL',
    cve: 'CVE-2020-7598',
    title: 'Prototype Pollution in minimist',
    rawMessage: '{"package":"minimist"}',
    ...overrides,
  };
}

describe('DifferentialLedger — add + classify', () => {
  it('adding a delta records it as pending, not classified', () => {
    const ledger = new DifferentialLedger();
    const f = findingFixture();
    ledger.add(f);
    expect(ledger.pendingCount).toBe(1);
    expect(ledger.size).toBe(0);
    expect(ledger.pending()).toHaveLength(1);
    expect(ledger.deltas()).toHaveLength(0);
  });

  it('classifying a pending finding moves it into the classified deltas', () => {
    const ledger = new DifferentialLedger();
    const f = findingFixture();
    ledger.add(f);
    ledger.classify(f, 'CVE-only; vetlock is behavioral, not an advisory-DB proxy', 'advisory-only');
    expect(ledger.pendingCount).toBe(0);
    expect(ledger.size).toBe(1);
    expect(ledger.deltas()[0].class).toBe('advisory-only');
    expect(ledger.deltas()[0].rationale).toMatch(/behavioral/);
  });

  it('classifying a not-yet-added finding still records it (streaming case)', () => {
    const ledger = new DifferentialLedger();
    const f = findingFixture({ package: 'lodash' });
    ledger.classify(f, 'known noise on this fixture', 'noise');
    expect(ledger.size).toBe(1);
    expect(ledger.pendingCount).toBe(0);
  });

  it('re-classifying the same finding replaces (does not stack duplicates)', () => {
    const ledger = new DifferentialLedger();
    const f = findingFixture();
    ledger.classify(f, 'first pass', 'noise');
    ledger.classify(f, 'second pass, actually a real gap', 'real-gap');
    expect(ledger.size).toBe(1);
    expect(ledger.deltas()[0].class).toBe('real-gap');
    expect(ledger.deltas()[0].rationale).toMatch(/second pass/);
  });

  it('add() is idempotent per (scanner, package, severity, cve, title) key', () => {
    const ledger = new DifferentialLedger();
    const f = findingFixture();
    ledger.add(f);
    ledger.add({ ...f }); // same key, cloned object
    expect(ledger.pendingCount).toBe(1);
  });
});

describe('DifferentialLedger — isClean', () => {
  it('is clean iff every delta is classified (adding a delta moves it into report() output)', () => {
    const ledger = new DifferentialLedger();
    expect(ledger.isClean()).toBe(true);

    const f = findingFixture();
    ledger.add(f);
    expect(ledger.isClean()).toBe(false);

    ledger.classify(f, 'the CVE-lookup non-goal', 'intentional-non-goal');
    expect(ledger.isClean()).toBe(true);

    // The classified delta renders in the report — this is the "moves into report()
    // output" half of the contract.
    const md = ledger.report();
    expect(md).toContain('intentional non-goal');
    expect(md).toContain('minimist');
    expect(md).toContain('the CVE-lookup non-goal');
  });
});

describe('DifferentialLedger — report()', () => {
  it('renders a clean-yes/no line and per-class buckets', () => {
    const ledger = new DifferentialLedger();
    ledger.classify(
      findingFixture({ package: 'a-pkg' }),
      'CVE-only',
      'advisory-only',
    );
    ledger.classify(
      findingFixture({ package: 'b-pkg', cve: undefined, title: 'behavioral escape' }),
      'vetlock should have caught this',
      'real-gap',
    );
    const md = ledger.report();
    expect(md).toContain('**Clean:** yes');
    expect(md).toContain('REAL GAP');
    expect(md).toContain('advisory-only');
    expect(md).toContain('a-pkg');
    expect(md).toContain('b-pkg');
  });

  it('report is deterministic (same inputs → same output)', () => {
    const ledger1 = new DifferentialLedger();
    const ledger2 = new DifferentialLedger();
    const findings = [
      findingFixture({ package: 'z' }),
      findingFixture({ package: 'a' }),
      findingFixture({ package: 'm' }),
    ];
    for (const f of findings) ledger1.classify(f, 'r', 'noise');
    // Insert in different order — sorted rendering must produce the same bytes.
    for (const f of [findings[2], findings[0], findings[1]]) ledger2.classify(f, 'r', 'noise');
    expect(ledger1.report()).toBe(ledger2.report());
  });
});

describe('DifferentialLedger — save() + load()', () => {
  it('produces valid JSON at the expected path', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'vetlock-ledger-'));
    const path = join(dir, 'differential-ledger.json');
    try {
      const ledger = new DifferentialLedger();
      ledger.classify(findingFixture(), 'advisory-only case', 'advisory-only');
      ledger.add(findingFixture({ package: 'other-pkg' }));

      await ledger.save(path);
      const raw = await readFile(path, 'utf-8');
      const parsed = JSON.parse(raw) as LedgerFile;
      expect(parsed.version).toBe(1);
      expect(parsed.deltas).toHaveLength(1);
      expect(parsed.pending).toHaveLength(1);
      expect(parsed.deltas[0].class).toBe('advisory-only');
      // Trailing newline so `git diff` treats it as a proper text file.
      expect(raw.endsWith('\n')).toBe(true);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('round-trips through save() + static load()', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'vetlock-ledger-'));
    const path = join(dir, 'differential-ledger.json');
    try {
      const original = new DifferentialLedger();
      original.classify(findingFixture(), 'r1', 'advisory-only');
      original.add(findingFixture({ package: 'pending-pkg' }));
      await original.save(path);

      const loaded = await DifferentialLedger.load(path);
      expect(loaded.size).toBe(1);
      expect(loaded.pendingCount).toBe(1);
      expect(loaded.deltas()[0].class).toBe('advisory-only');
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('load() of a nonexistent file returns an empty ledger', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'vetlock-ledger-'));
    try {
      const loaded = await DifferentialLedger.load(join(dir, 'does-not-exist.json'));
      expect(loaded.size).toBe(0);
      expect(loaded.pendingCount).toBe(0);
      expect(loaded.isClean()).toBe(true);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
