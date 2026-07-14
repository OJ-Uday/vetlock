# tar-bomb — hostile tarball metadata (four modes)

**Landed by Wave 3-M.** Companion generator: `assurance/src/robustness/tar-bomb.ts`.
Companion tests: `assurance/test/robustness/tar-bomb.test.ts`.

## What this demonstrates

Four categories of malicious tarball SHAPE the scanner must handle safely. Every generated
fixture is bounded (<1 MB on disk); the pathology is in the METADATA (tar headers, entry
paths, entry counts), not in the actual expanded size. The scanner's `safeExtract` must
refuse or contain each mode:

1. **oversized-claim** — tar headers claim 4 GiB per entry, real content is <100 bytes.
   A parser that pre-allocates on the header claim would OOM instantly; the scanner reads
   the real stream size and never trusts the claim.
2. **nested-paths** — one entry with 100+ slash-separated segments in its path.
   Exercises `mkdir -p` depth and any path-length guard.
3. **zip-slip** — entries with paths like `../../../etc/passwd` and `/absolute/path`.
   The classic tar-extract vulnerability that writes files outside the destination.
4. **many-entries** — 15_000 distinct entries in one archive. Exercises the
   entry-count cap (default 10_000).

## Current scanner behavior (as of 2026-07-14)

All four modes are handled cleanly by `@vetlock/core`'s `safeExtract`:

| mode              | baseline (small)              | stress (aggressive)                             |
| ----------------- | ----------------------------- | ----------------------------------------------- |
| oversized-claim   | ok — real bytes are tiny      | ok — real bytes are tiny                        |
| nested-paths      | ok — mkdir -p handles it      | ok — mkdir -p handles it                        |
| zip-slip          | `UnsafeArchiveError`          | `UnsafeArchiveError`                            |
|                   |  kind: `traversal` / `absolute-path` |  kind: `traversal` / `absolute-path`     |
| many-entries      | ok — under cap                | `UnsafeArchiveError` kind: `entry-count-exceeded` |

**No gaps found.** The scanner's per-entry, total-bytes, and entry-count caps all fire
correctly.  No hangs, no OOMs, no native aborts on any of the 4 x 2 = 8 test cases.

## Why blocking these matters (attack class in the wild)

An attacker who publishes a package with a hostile tarball can:
- Force the scanner to OOM (compression-bomb variants) → CI DoS → merge blocker.
- Escape the extraction dir (zip-slip) → write to arbitrary FS paths on the scanner host.
- Starve scanner iteration budgets (many-entries) → analysis timeout on the affected package.

The correct behavior is what the scanner already does: refuse fast, with a typed error
that identifies which cap fired.

## Fixtures

No committed binary fixtures — the generator is deterministic. To reproduce any case:

```ts
import { tarBomb } from '../../src/robustness/tar-bomb.js';

// Any of the eight (mode, scale) combinations:
const input = tarBomb.generate(1, { mode: 'zip-slip', scale: 'stress' });
// input.bytes  → .tgz Buffer (< 1 MB)
// input.filename, input.description, input.mode, input.scale
```

Then feed through `analyzeTarball` via the tests' `analyzeBounded` wrapper.

## Regression tests

`assurance/test/robustness/tar-bomb.test.ts` — 8 tests, one per (mode, scale). Each test
asserts a specific outcome; a regression that makes the scanner ok where it should reject
(or vice versa) surfaces as a clean test failure.

## Status

- **Found:** 2026-07-14 (assurance Wave 3-M)
- **Filed as engine gap:** N/A — the scanner already handles all four modes.
