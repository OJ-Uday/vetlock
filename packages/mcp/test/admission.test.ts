import { describe, expect, it } from 'vitest';
import {
  analyzeLockfileChange,
  canonicalJson,
  createReceipt,
  evaluatePolicy,
  sha256,
  verifyReceipt,
} from '../src/admission.js';

const finding = {
  detector: 'install.script-added', category: 'INSTALL' as const, package: 'example', from: null, to: '1.0.0',
  direction: 'added' as const, severity: 'BLOCK' as const, confidence: 'high' as const, message: 'new install script',
  evidence: [{ file: 'package.json', line: 1, snippet: 'postinstall' }], provenance: [],
};

describe('admission policy', () => {
  it('blocks BLOCK findings by default', () => {
    expect(evaluatePolicy([finding]).decision).toBe('block');
  });

  it('sends WARN findings to review by default', () => {
    expect(evaluatePolicy([{ ...finding, severity: 'WARN' }]).decision).toBe('review');
  });
});

describe('unsigned receipts', () => {
  it('is deterministic for the same data and detects modification', () => {
    const base = {
      package: 'example', packageVersion: '1.0.0', artifactSha256: sha256('artifact'), projectHash: sha256('project'),
      policyHash: sha256('policy'), findingsHash: sha256(canonicalJson([finding])), decision: 'block' as const,
      issuedAt: '2026-01-01T00:00:00.000Z',
    };
    const receipt = createReceipt(base);
    expect(createReceipt(base).receiptHash).toBe(receipt.receiptHash);
    expect(verifyReceipt(receipt).valid).toBe(true);
    expect(verifyReceipt({ ...receipt, decision: 'allow' }).valid).toBe(false);
  });
});

describe('lockfile scanning', () => {
  it('does not execute packages for empty npm lockfiles', async () => {
    const os = await import('node:os');
    const fs = await import('node:fs/promises');
    const path = await import('node:path');
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'vetlock-mcp-'));
    const before = path.join(dir, 'before.package-lock.json');
    const after = path.join(dir, 'after.package-lock.json');
    const lock = JSON.stringify({ name: 'fixture', version: '1.0.0', lockfileVersion: 3, packages: { '': { name: 'fixture', version: '1.0.0' } } });
    await Promise.all([fs.writeFile(before, lock), fs.writeFile(after, lock)]);
    try {
      const result = await analyzeLockfileChange(before, after);
      expect(result.neverExecuted).toBe(true);
      expect(result.findings).toEqual([]);
    } finally { await fs.rm(dir, { recursive: true, force: true }); }
  });
});
