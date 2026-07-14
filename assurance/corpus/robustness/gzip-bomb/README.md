# gzip-bomb — hostile gzip streams (two modes)

**Landed by Wave 3-M.** Companion generator: `assurance/src/robustness/gzip-bomb.ts`.
Companion tests: `assurance/test/robustness/gzip-bomb.test.ts`.

## What this demonstrates

Two categories of malicious gzip stream the scanner must handle safely.

1. **high-ratio** — a small (<250 KB) gzip stream that decompresses to many MiB
   (5 MiB baseline, 100 MiB stress). Made from all-zeros content: DEFLATE reduces long
   runs of identical bytes to a tiny back-reference, so the fixture on disk is a few
   hundred bytes while the decompressed payload is huge. A naive scanner that reads the
   whole decompressed stream into memory would OOM; the scanner MUST enforce a per-entry
   and total-bytes cap that fires before memory is exhausted.
2. **invalid-header** — malformed gzip bytes (bogus magic OR a truncated valid stream).
   `zlib` must throw a plain `Error` the scanner surfaces cleanly, not a native abort.

## Current scanner behavior (as of 2026-07-14)

All modes are handled cleanly by `@vetlock/core`'s `safeExtract`:

| mode                 | baseline                              | stress                                          |
| -------------------- | ------------------------------------- | ----------------------------------------------- |
| high-ratio           | ok — 5 MiB is under all caps          | `UnsafeArchiveError` kind: `entry-too-large` (per-entry cap fires at 50 MiB) |
| invalid-header       | rejected — clean Error from zlib       | rejected — clean Error from zlib (truncated stream) |

**No gaps found.** The extractor's cap-based approach means it never tries to hold the
decompressed stream in memory beyond the per-entry cap. Malformed streams are rejected
before any allocation of note.

## Why blocking these matters (attack class in the wild)

A gzip bomb published in an npm tarball can:
- Force the scanner to OOM (high-ratio) if it lacks caps → CI DoS.
- Force the scanner to native-abort on malformed input → the surrounding harness (worker
  thread, subprocess) crashes, taking downstream state with it.

The correct behavior is what the scanner already does: enforce caps early on the
decompressed byte stream, and surface zlib errors as ordinary Errors.

## Fixtures

No committed binary fixtures — the generator is deterministic. To reproduce any case:

```ts
import { gzipBomb } from '../../src/robustness/gzip-bomb.js';

const input = gzipBomb.generate(1, { mode: 'high-ratio', scale: 'stress' });
// input.bytes                   → .tgz Buffer (~200 KB on disk)
// input.decompressedBytesClaim  → 100 * 1024 * 1024 (100 MiB)
```

Then feed through `analyzeTarball` via the tests' `analyzeBounded` wrapper.

## Regression tests

`assurance/test/robustness/gzip-bomb.test.ts` — 4 tests, one per (mode, scale). Each test
asserts a specific outcome; a regression that removes a cap or breaks the error surface
appears as a clean test failure.

## Status

- **Found:** 2026-07-14 (assurance Wave 3-M)
- **Filed as engine gap:** N/A — the scanner already handles both modes.
