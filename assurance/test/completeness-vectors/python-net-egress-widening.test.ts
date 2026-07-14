/**
 * python-net-egress-widening — completeness-vector transform self-tests.
 */

import { describe, it, expect } from 'vitest';
import { pyUrllibToRequests } from '../../src/completeness-vectors/python-net-egress-widening.js';

const SEEDS: readonly number[] = [0, 1, 7, 42, 1337, 2_147_483_647];

const PY_WITH_URLLIB =
  'import urllib.request\nresp = urllib.request.urlopen("http://example.com/")\n';
const PY_WITH_FROM =
  'from urllib.request import urlopen\nresp = urlopen("http://example.com/")\n';

describe('completeness-vectors — python-net-egress-widening', () => {
  it('declares the python-net-egress targetClass', () => {
    expect(pyUrllibToRequests.targetClass).toBe('python-net-egress');
    expect(pyUrllibToRequests.family).toBe('sink-family-widening');
  });

  it('is pure/deterministic', () => {
    for (const seed of SEEDS) {
      const a = pyUrllibToRequests.transform(PY_WITH_URLLIB, seed);
      const b = pyUrllibToRequests.transform(PY_WITH_URLLIB, seed);
      expect(b).toBe(a);
    }
  });

  it('rewrites import urllib.request → import requests', () => {
    const out = pyUrllibToRequests.transform(PY_WITH_URLLIB, 0);
    expect(out).not.toBe(PY_WITH_URLLIB);
    expect(out).toContain('import requests');
    expect(out).toContain('requests.get(');
    expect(out).not.toContain('import urllib.request');
  });

  it('rewrites from urllib.request import urlopen → from requests import get', () => {
    const out = pyUrllibToRequests.transform(PY_WITH_FROM, 0);
    expect(out).not.toBe(PY_WITH_FROM);
    expect(out).toContain('from requests import get');
    expect(out).toContain('requests.get(');
  });

  it('is a no-op on Python without urllib idioms', () => {
    const benign = 'import os\nprint(os.getcwd())\n';
    for (const seed of SEEDS) {
      expect(pyUrllibToRequests.transform(benign, seed)).toBe(benign);
    }
  });
});
