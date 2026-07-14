/**
 * Oracle self-tests.
 *
 * These tests define the oracle contract. Every oracle takes a `RunOutcome` (or a pair) and
 * returns an `OracleResult` — a structured pass/fail with a reason. No exceptions escape.
 *
 * TDD order: this file specifies the contract, then the oracle modules implement it. If a
 * new oracle is added later, add its test here first.
 */

import { describe, it, expect } from 'vitest';
import type { RunOutcome, Findings } from '../../src/oracles/types.js';
import {
  oracleNoCrash,
  oracleNoHang,
  oracleNoOom,
  oracleFailSafe,
  oracleFindingSurvives,
  oracleIdentityInvariant,
} from '../../src/oracles/index.js';

// ----- fixture builders ---------------------------------------------------------------------
// Every RunOutcome is built via a tiny helper. Keeps individual tests focused on the oracle's
// contract, not on filling out fields.

const FIXED_SEED = 42;

function okOutcome(findings: Findings = [], wallMs = 100): RunOutcome {
  return { kind: 'ok', findings, wallMs, peakRssBytes: 50 * 1024 * 1024, seed: FIXED_SEED };
}

function crashOutcome(name = 'TypeError', message = 'boom'): RunOutcome {
  return {
    kind: 'crash',
    error: { name, message, stack: `${name}: ${message}\n  at test` },
    wallMs: 42,
    seed: FIXED_SEED,
  };
}

function timeoutOutcome(wallMs = 5000): RunOutcome {
  return { kind: 'timeout', wallMs, seed: FIXED_SEED };
}

function oomOutcome(peakRssBytes = 512 * 1024 * 1024): RunOutcome {
  return { kind: 'oom', peakRssBytes, seed: FIXED_SEED };
}

function failSafeOutcome(reason = 'analysis-failed', findings: Findings = []): RunOutcome {
  const withDefault: Findings =
    findings.length > 0
      ? findings
      : [{ capabilityClass: 'analysis-failed', severity: 'BLOCK', reason }];
  return { kind: 'fail-safe', reason, findings: withDefault, wallMs: 200, seed: FIXED_SEED };
}

const CODE_EXEC_FINDING = {
  capabilityClass: 'code-execution',
  severity: 'BLOCK' as const,
  reason: 'child_process.exec detected',
  location: { file: 'index.js', line: 5 },
};

// ----- oracleNoCrash -----------------------------------------------------------------------

describe('oracleNoCrash', () => {
  it('passes for ok outcomes', () => {
    const r = oracleNoCrash(okOutcome());
    expect(r).toEqual({ oracle: 'no-crash', pass: true });
  });

  it('passes for timeout (runner caught the pathology)', () => {
    // A timeout is not a crash; the runner detected it and terminated cleanly.
    expect(oracleNoCrash(timeoutOutcome()).pass).toBe(true);
  });

  it('passes for oom (runner caught the pathology)', () => {
    expect(oracleNoCrash(oomOutcome()).pass).toBe(true);
  });

  it('passes for fail-safe (engine gave up but flagged)', () => {
    expect(oracleNoCrash(failSafeOutcome()).pass).toBe(true);
  });

  it('fails for crash outcomes and carries the error name in evidence', () => {
    const r = oracleNoCrash(crashOutcome('RangeError', 'stack overflow'));
    expect(r.pass).toBe(false);
    expect(r.oracle).toBe('no-crash');
    expect(r.reason).toMatch(/RangeError/);
    expect(r.evidence).toBeDefined();
  });
});

// ----- oracleNoHang ------------------------------------------------------------------------

describe('oracleNoHang', () => {
  it('passes for ok outcomes', () => {
    expect(oracleNoHang(okOutcome()).pass).toBe(true);
  });

  it('passes for fail-safe (engine returned inside budget)', () => {
    expect(oracleNoHang(failSafeOutcome()).pass).toBe(true);
  });

  it('passes for crash (a crash is not a hang; oracleNoCrash handles it)', () => {
    // Oracles are independent — one failure per axis. A crash is NOT a hang.
    expect(oracleNoHang(crashOutcome()).pass).toBe(true);
  });

  it('passes for oom (oom is not a hang either)', () => {
    expect(oracleNoHang(oomOutcome()).pass).toBe(true);
  });

  it('fails for timeout outcomes and carries the wallMs in evidence', () => {
    const r = oracleNoHang(timeoutOutcome(30_000));
    expect(r.pass).toBe(false);
    expect(r.oracle).toBe('no-hang');
    expect(r.reason).toMatch(/timeout|30000/);
    expect(r.evidence).toMatchObject({ wallMs: 30_000 });
  });
});

// ----- oracleNoOom -------------------------------------------------------------------------

describe('oracleNoOom', () => {
  it('passes for ok outcomes', () => {
    expect(oracleNoOom(okOutcome()).pass).toBe(true);
  });

  it('passes for timeout, crash, fail-safe (each is a different axis)', () => {
    expect(oracleNoOom(timeoutOutcome()).pass).toBe(true);
    expect(oracleNoOom(crashOutcome()).pass).toBe(true);
    expect(oracleNoOom(failSafeOutcome()).pass).toBe(true);
  });

  it('fails for oom outcomes and carries peak memory in evidence', () => {
    const r = oracleNoOom(oomOutcome(600 * 1024 * 1024));
    expect(r.pass).toBe(false);
    expect(r.oracle).toBe('no-oom');
    expect(r.evidence).toMatchObject({ peakRssBytes: 600 * 1024 * 1024 });
  });
});

// ----- oracleFailSafe ----------------------------------------------------------------------
// The composite. For hostile inputs, the runner must resolve to something the harness accepts:
//   ok (with findings on a known-malicious fixture), fail-safe, timeout, or oom.
// Unsafe:
//   crash, or ok-with-empty-findings when the fixture is known to be malicious
//   (the silent-green / fail-open regression the 31-exploit campaign closed).

describe('oracleFailSafe', () => {
  it('passes for ok with any finding on a known-malicious input', () => {
    // No `mustFindClass` constraint — we just need *some* finding.
    const r = oracleFailSafe(okOutcome([CODE_EXEC_FINDING]));
    expect(r.pass).toBe(true);
  });

  it('passes for ok with a finding of the required class when constrained', () => {
    const r = oracleFailSafe(okOutcome([CODE_EXEC_FINDING]), { mustFindClass: 'code-execution' });
    expect(r.pass).toBe(true);
  });

  it('fails for ok with empty findings when the input is known-malicious', () => {
    // This is the silent-green / fail-open case. Without a mustFindClass constraint we still
    // fail-open if the caller signals the fixture is malicious via `mustFindClass: '*'`.
    const r = oracleFailSafe(okOutcome([]), { mustFindClass: '*' });
    expect(r.pass).toBe(false);
    expect(r.reason).toMatch(/silent|fail-open|no findings/i);
  });

  it('fails for ok with findings but missing the required class', () => {
    // The engine caught *something* but not the class the fixture actually exhibits.
    // A crafted "sink-sibling swap" where the class annotation moves but the payload doesn't.
    const r = oracleFailSafe(okOutcome([{ ...CODE_EXEC_FINDING, capabilityClass: 'net-egress' }]), {
      mustFindClass: 'code-execution',
    });
    expect(r.pass).toBe(false);
    expect(r.reason).toMatch(/code-execution/);
  });

  it('passes for fail-safe (the engine gave up but flagged BLOCK)', () => {
    expect(oracleFailSafe(failSafeOutcome()).pass).toBe(true);
  });

  it('passes for timeout and oom (runner caught the pathology; not silent-green)', () => {
    expect(oracleFailSafe(timeoutOutcome()).pass).toBe(true);
    expect(oracleFailSafe(oomOutcome()).pass).toBe(true);
  });

  it('fails for crash', () => {
    const r = oracleFailSafe(crashOutcome());
    expect(r.pass).toBe(false);
    expect(r.oracle).toBe('fail-safe');
    expect(r.reason).toMatch(/crash|exception|escape/i);
  });

  it('passes for ok without mustFindClass and without findings (benign input)', () => {
    // If the caller doesn't assert malice, empty findings is a normal ok verdict.
    expect(oracleFailSafe(okOutcome([])).pass).toBe(true);
  });
});

// ----- oracleFindingSurvives ---------------------------------------------------------------
// The completeness heart. before = canonical caught fixture. after = mutated variant.
// after MUST still contain a finding of the specified capability class.

describe('oracleFindingSurvives', () => {
  it('passes when both before and after contain a finding of the target class', () => {
    const before = okOutcome([CODE_EXEC_FINDING]);
    const after = okOutcome([{ ...CODE_EXEC_FINDING, location: { file: 'nested/lib.js' } }]);
    const r = oracleFindingSurvives(before, after, 'code-execution');
    expect(r.pass).toBe(true);
  });

  it('fails when after has zero findings (evasion succeeded)', () => {
    const before = okOutcome([CODE_EXEC_FINDING]);
    const after = okOutcome([]);
    const r = oracleFindingSurvives(before, after, 'code-execution');
    expect(r.pass).toBe(false);
    expect(r.reason).toMatch(/evasion|survive|missing/i);
    expect(r.evidence).toMatchObject({ class: 'code-execution' });
  });

  it('fails when after findings are all of a different class', () => {
    const before = okOutcome([CODE_EXEC_FINDING]);
    const after = okOutcome([{ ...CODE_EXEC_FINDING, capabilityClass: 'net-egress' }]);
    const r = oracleFindingSurvives(before, after, 'code-execution');
    expect(r.pass).toBe(false);
  });

  it('fails when before does not have the target class (test setup error)', () => {
    // If before doesn't have the class, "survives" is meaningless. The oracle must complain
    // so the harness author notices the fixture is mislabeled.
    const before = okOutcome([{ ...CODE_EXEC_FINDING, capabilityClass: 'fs-write' }]);
    const after = okOutcome([CODE_EXEC_FINDING]);
    const r = oracleFindingSurvives(before, after, 'code-execution');
    expect(r.pass).toBe(false);
    expect(r.reason).toMatch(/before|baseline/i);
  });

  it('fails when after is crash/timeout/oom (the mutation broke the engine)', () => {
    const before = okOutcome([CODE_EXEC_FINDING]);
    for (const bad of [crashOutcome(), timeoutOutcome(), oomOutcome()]) {
      const r = oracleFindingSurvives(before, bad, 'code-execution');
      expect(r.pass).toBe(false);
      expect(r.reason).toMatch(/crash|timeout|oom|not.*ok/i);
    }
  });

  it('passes when after is fail-safe with the class in its findings', () => {
    // Fail-safe with a matching BLOCK is still a catch — the finding survived, the detector
    // just errored on the specific mutation and the engine block'd conservatively.
    const before = okOutcome([CODE_EXEC_FINDING]);
    const after = failSafeOutcome('analysis-failed', [CODE_EXEC_FINDING]);
    expect(oracleFindingSurvives(before, after, 'code-execution').pass).toBe(true);
  });
});

// ----- oracleIdentityInvariant -------------------------------------------------------------
// Two semantically-identical inputs must produce structurally-identical findings post-normalization.
// Normalization: sort findings deterministically by (file, line, capabilityClass, severity, reason);
// strip anything non-deterministic (RSS, wallMs, seed).

describe('oracleIdentityInvariant', () => {
  it('passes when two ok outcomes have identical findings', () => {
    const a = okOutcome([CODE_EXEC_FINDING]);
    const b = okOutcome([CODE_EXEC_FINDING]);
    expect(oracleIdentityInvariant(a, b).pass).toBe(true);
  });

  it('passes when findings differ only in order (normalization sorts)', () => {
    const f1 = { ...CODE_EXEC_FINDING, location: { file: 'a.js', line: 1 } };
    const f2 = { ...CODE_EXEC_FINDING, location: { file: 'b.js', line: 1 } };
    const a = okOutcome([f1, f2]);
    const b = okOutcome([f2, f1]);
    expect(oracleIdentityInvariant(a, b).pass).toBe(true);
  });

  it('passes when timings differ (wallMs / peakRssBytes are stripped by normalization)', () => {
    const a: RunOutcome = { kind: 'ok', findings: [CODE_EXEC_FINDING], wallMs: 100, peakRssBytes: 10_000_000, seed: FIXED_SEED };
    const b: RunOutcome = { kind: 'ok', findings: [CODE_EXEC_FINDING], wallMs: 300, peakRssBytes: 30_000_000, seed: FIXED_SEED };
    expect(oracleIdentityInvariant(a, b).pass).toBe(true);
  });

  it('fails when the two outcomes have different findings', () => {
    const a = okOutcome([CODE_EXEC_FINDING]);
    const b = okOutcome([{ ...CODE_EXEC_FINDING, capabilityClass: 'net-egress' }]);
    const r = oracleIdentityInvariant(a, b);
    expect(r.pass).toBe(false);
    expect(r.reason).toMatch(/differ|invariant/i);
  });

  it('fails when the two outcomes have different kinds (ok vs crash)', () => {
    const a = okOutcome([CODE_EXEC_FINDING]);
    const b = crashOutcome();
    expect(oracleIdentityInvariant(a, b).pass).toBe(false);
  });

  it('fails when one has findings and the other has none', () => {
    const a = okOutcome([CODE_EXEC_FINDING]);
    const b = okOutcome([]);
    expect(oracleIdentityInvariant(a, b).pass).toBe(false);
  });
});
