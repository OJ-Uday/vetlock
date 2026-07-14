# hex-decode-to-parseInt — obfuscation-decode evasion

**Corpus entry:** `assurance/corpus/evasion/hex-decode-to-parseInt/` · **Status: OPEN** · Found: Wave 6 integration (2026-07-14).

## What evades

The `hex-decode-to-parseInt` completeness-vector transform rewrites:
- BEFORE: `Buffer.from(x, 'hex')` — engine's obfuscation detector catches this via `Buffer.from(*, 'hex')` signature.
- AFTER: `(s => new Uint8Array(s.match(/.{1,2}/g).map(b => parseInt(b, 16))))(x)` — a pure-JS hex→bytes IIFE built from `parseInt`, `.match`, and `Uint8Array`. Engine's detector doesn't recognize this pattern as hex decoding.

Both forms decode a hex string into bytes. An attacker who wants to slip an encoded payload past `Buffer.from(_, 'hex')` detection can inline the parseInt-based decoder — legitimate JS with no external module.

## Why blocking matters

Same threat class as `base64-decode-to-atob`: catching one encoding form but not its equivalent is a completeness hole. `Buffer.from(_, 'hex')` catches package.postinstall payloads that use `hex` as the encoding argument; the parseInt-based form is used by minified/obfuscated code precisely because static tools often miss it.

## Reproduction

```ts
import { hexDecodeToParseInt } from '@vetlock/assurance/completeness-vectors';
const source = 'const raw = Buffer.from("68656c6c6f", "hex");\n';
const mutated = hexDecodeToParseInt.transform(source, 42);
// mutated contains an IIFE building a Uint8Array via parseInt — engine misses this
```

## Fix path (STARTUP-side)

Extend `packages/core/src/capabilities.ts` to recognize the specific pattern `parseInt(_, 16)` inside a map over `s.match(/.{1,2}/g)` — or, more broadly, `parseInt(_, 16)` calls generally as an obfuscation-decode signal.

## Assertion-flip when STARTUP lands the fix

Same protocol as `base64-decode-to-atob/README.md`. Remove `'hex-decode-to-parseInt'` from `KNOWN_GAP_IDS` in `evasion-catch-rate.test.ts`. Add fix SHA here.
