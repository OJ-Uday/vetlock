/**
 * python-net-egress-widening — completeness-vector transform for the
 * `python-net-egress` class (STARTUP §3.5 sinks: `socket-first-use`,
 * `urllib-first-use`).
 *
 * The class covers Python's outbound-network primitives — `urllib.request`,
 * `requests`, `httpx`, `aiohttp`, `urllib3`, and the lower-level `socket`
 * module. Detection keys on module imports (`import urllib`, `import
 * requests`, etc.). The transform shipped here — `pyUrllibToRequests` —
 * rewrites `import urllib.request` and `urllib.request.urlopen(...)` calls to
 * the equivalent `requests` library idiom. Both hit the network at the class's
 * granularity; the module ID surfaces one shape or the other but the class
 * (`python-net-egress`) is the same in either.
 *
 * Rewrites performed on Python source, line-based:
 *   • `import urllib.request` → `import requests`
 *   • `from urllib.request import urlopen` → `from requests import get`
 *   • `urllib.request.urlopen(url)` → `requests.get(url)`
 *   • `urlopen(url)` → `requests.get(url)`  (only when `import urllib.request` shape found)
 *
 * If none of these patterns are present the transform is a no-op.
 *
 * ENGINE ROUTING NOTE — routed to `NO_ENGINE_DETECTOR_YET` in
 * evasion-catch-rate.test.ts. Same rationale as python-code-exec-widening.ts:
 * the assurance runner doesn't yet ship a Python-routed scenario.
 */

import type { CompletenessTransform } from './types.js';

function rewriteUrllibToRequests(source: string): string {
  const lines = source.split('\n');
  let sawImport = false;
  let rewrote = false;
  for (let i = 0; i < lines.length; i++) {
    let line = lines[i];
    if (/^\s*import\s+urllib\.request\b/.test(line)) {
      line = line.replace(/^(\s*)import\s+urllib\.request\b/, '$1import requests');
      sawImport = true;
      rewrote = true;
    } else if (/^\s*from\s+urllib\.request\s+import\s+urlopen\b/.test(line)) {
      line = line.replace(
        /^(\s*)from\s+urllib\.request\s+import\s+urlopen\b/,
        '$1from requests import get',
      );
      sawImport = true;
      rewrote = true;
    }
    if (line.includes('urllib.request.urlopen(')) {
      line = line.split('urllib.request.urlopen(').join('requests.get(');
      rewrote = true;
    }
    if (sawImport && /\burlopen\(/.test(line)) {
      line = line.replace(/\burlopen\(/g, 'requests.get(');
      rewrote = true;
    }
    lines[i] = line;
  }
  return rewrote ? lines.join('\n') : source;
}

export const pyUrllibToRequests: CompletenessTransform = {
  id: 'py-urllib-to-requests',
  family: 'sink-family-widening',
  targetClass: 'python-net-egress',
  description:
    "Rewrite Python urllib.request idioms to the requests-library equivalent (import urllib.request → import requests; urllib.request.urlopen(x) → requests.get(x)). Same class (network egress), sibling module — completeness probe for the python-net-egress class.",
  transform(source, _seed): string {
    return rewriteUrllibToRequests(source);
  },
};
