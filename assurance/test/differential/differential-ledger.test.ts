/**
 * differential-ledger.test — packet §5 P3 named test.
 *
 * The packet's requirement (P3 done-gate): "invariance 100%; differential ledger
 * published + classified; deltas triaged" — with the specific assertion "every delta is
 * classified, none silently ignored". That is what this file enforces.
 *
 * Three invariants:
 *   1. An empty ledger is clean (vacuous truth — no deltas can't be "silently ignored").
 *   2. A ledger with an unclassified delta is NOT clean (this is the whole point).
 *   3. Every classified delta renders in the report (readable audit trail).
 */

import { describe, it, expect } from 'vitest';
import {
  DifferentialLedger,
  type ScannerFinding,
} from '../../src/differential/index.js';

function fixture(overrides: Partial<ScannerFinding> = {}): ScannerFinding {
  return {
    scanner: 'npm-audit',
    package: 'lodash',
    severity: 'HIGH',
    cve: 'CVE-2019-10744',
    title: 'Prototype Pollution',
    rawMessage: '',
    ...overrides,
  };
}

describe('differential-ledger (packet §5 P3 named test)', () => {
  it('empty ledger is clean (0 deltas classified = clean by vacuous truth)', () => {
    const ledger = new DifferentialLedger();
    expect(ledger.pendingCount).toBe(0);
    expect(ledger.size).toBe(0);
    expect(ledger.isClean()).toBe(true);
  });

  it('a ledger with an unclassified delta is not clean', () => {
    const ledger = new DifferentialLedger();
    ledger.add(fixture());
    expect(ledger.pendingCount).toBe(1);
    expect(ledger.isClean()).toBe(false);
  });

  it('once every delta is classified the ledger is clean again', () => {
    const ledger = new DifferentialLedger();
    const f = fixture();
    ledger.add(f);
    expect(ledger.isClean()).toBe(false);
    ledger.classify(f, 'CVE-only; behavioral analyzer does not proxy the advisory DB', 'advisory-only');
    expect(ledger.isClean()).toBe(true);
  });

  it('all classified deltas render in the report (readable audit trail)', () => {
    const ledger = new DifferentialLedger();
    ledger.classify(
      fixture({ package: 'alpha', title: 'alpha CVE' }),
      'alpha is CVE-only',
      'advisory-only',
    );
    ledger.classify(
      fixture({ package: 'beta', title: 'beta gap', cve: undefined }),
      'beta is a real behavioral gap vetlock should have caught',
      'real-gap',
    );
    ledger.classify(
      fixture({ package: 'gamma', title: 'gamma non-goal' }),
      'gamma is intentional non-goal',
      'intentional-non-goal',
    );
    ledger.classify(
      fixture({ package: 'delta', title: 'delta noise' }),
      'delta is a well-known FP from this scanner',
      'noise',
    );

    const md = ledger.report();
    for (const pkg of ['alpha', 'beta', 'gamma', 'delta']) {
      expect(md).toContain(pkg);
    }
    // Each rationale renders too — the classification isn't just a label, it carries the
    // reasoning that keeps the ledger honest.
    expect(md).toContain('alpha is CVE-only');
    expect(md).toContain('real behavioral gap');
    expect(md).toContain('intentional non-goal');
    expect(md).toContain('well-known FP');
    // Every bucket header renders when it has content.
    expect(md).toContain('REAL GAP');
    expect(md).toContain('intentional non-goal');
    expect(md).toContain('advisory-only');
    expect(md).toContain('noise');
  });
});
