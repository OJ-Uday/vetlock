# base64-decode-to-atob — obfuscation-decode evasion

**Corpus entry:** `assurance/corpus/evasion/base64-decode-to-atob/` · **Status: OPEN** · Found: Wave 6 integration (2026-07-14).

## What evades

The `base64-decode-to-atob` completeness-vector transform rewrites:
- BEFORE: `Buffer.from(x, 'base64').toString('utf8')` — engine's obfuscation detector catches this via `Buffer.from(*, 'base64')` module-and-string signature.
- AFTER: `atob(x)` — `atob` is a browser-standard global exposed in Node ≥16 (no import required). The engine's `capabilities.ts::extractCapabilities` does not recognize it as a base64-decode signal.

Both forms are semantically identical: decode a base64 string. An attacker who wants to slip an encoded payload past `Buffer.from(_, 'base64')` detection can just call `atob(_)`.

## Why blocking matters

The obfuscation-decode class is the "encoded payload" signal — combined with a network fetch or `eval`, it's exactly the shape of a hostile update trying to smuggle a payload past static analysis. The whole point of catching Buffer.from-base64 is to catch encoded strings-that-become-code. Missing `atob()` leaves an equivalent surface completely unmonitored.

## Reproduction

```ts
import { runBounded } from '@vetlock/assurance/runner';
import { oracleFindingSurvives } from '@vetlock/assurance/oracles';
import { base64DecodeToAtob } from '@vetlock/assurance/completeness-vectors';

const source = 'const decoded = Buffer.from("aGVsbG8=", "base64").toString("utf8");\n';
const mutated = base64DecodeToAtob.transform(source, 42);

const [a, b] = await Promise.all([
  runBounded({ kind: 'engine:extractCapabilities', enginePath: '@vetlock/core', relPath: 'a.js', text: source }, BOUNDS),
  runBounded({ kind: 'engine:extractCapabilities', enginePath: '@vetlock/core', relPath: 'a.js', text: mutated }, BOUNDS),
]);
// oracleFindingSurvives(a, b, 'obfuscation-decode').pass === false → evasion
```

## Fix path (STARTUP-side)

Extend `packages/core/src/capabilities.ts` to recognize `atob()` calls (both as a globals ref and as `globalThis.atob`) — same detector shape that surfaces `Buffer.from(_, 'base64')`. Add to `EXECMODULES` (via `dynamicCode`) or `encodedUrls` / `suspiciousLiterals` axes.

## Assertion-flip when STARTUP lands the fix

`assurance/test/evasion/evasion-catch-rate.test.ts` currently has this transform in `KNOWN_GAP_IDS` with a GAP-pinning assertion `expect(verdict.pass).toBe(false)`. When STARTUP wires `atob` detection:

1. Remove `'base64-decode-to-atob'` from `KNOWN_GAP_IDS`.
2. The transform rejoins the standard survives loop automatically.
3. Add the fix commit SHA to this README's Status line.
