# The pre-install gate (Wave 8-JJ)

**Status**: shipped (2026 · `vetlock add` + `vetlock guard`)

## Motivation

The **single largest attack window** in the npm supply chain is:

```
     ┌── developer                                              ┌── CI
     │                                                          │
t=0  │  npm install evil@1.0                                    │
t=1  │    ↓ downloads tarball                                   │
t=2  │    ↓ extracts                                            │
t=3  │    ↓ runs preinstall / install / postinstall  ◄── attack │
t=4  │    ↓ exfiltrates ~/.npmrc, ~/.aws/creds, env             │
t=5  │  done — dev machine compromised                          │
                                                                │
                                       ⋯ lockfile pushed ⋯      │
t=6                                                             │  vetlock diff runs
                                                                │    ↓ sees the change
                                                                │    ↓ blocks the PR
```

By the time CI sees the diff at `t=6`, the exfil at `t=3` has already happened. **Every** post-install scanner has this gap.

`vetlock add` shifts the gate LEFT of `t=3`:

```
     ┌── developer
     │
t=0  │  vetlock add evil@1.0
t=1  │    ↓ fetch tarball (bytes only)
t=2  │    ↓ extract (NEVER runs code, ADR 0005)
t=3  │    ↓ run detectors
t=4  │    verdict BLOCK  ─── refuse, exit 3, no npm invoked ✓
```

Or with `guard`, transparently on top of muscle-memory `npm install`:

```
     ┌── developer
     │
t=0  │  npm install evil@1.0    (npm is a shim at ~/.vetlock/bin/npm)
t=1  │  shim reroutes → vetlock add evil@1.0
     │    ↓ (same static gate)
t=4  │  verdict BLOCK → real npm install NEVER runs ✓
```

## What "NEVER-EXECUTE" actually means

Every step from fetch through verdict operates on **bytes**, not code.

- **Fetch** — `pacote.tarball(spec)` returns the raw tarball buffer. pacote does not import, extract, or run anything from that buffer. See ADR 0004.
- **Extract** — `@vetlock/core::safeExtract` opens the .tgz with `node:tar`, walks entries statically, writes files to a scratch dir with `ignore-scripts` semantics. No `require`, no `dlopen`, no `spawn` from tarball contents. See ADR 0005.
- **Analyze** — Babel parses `.js`/`.ts` files into ASTs, we walk them to extract capabilities. Parsing is not evaluation.
- **Detect** — pure functions over `PackageSnapshot` pairs. See `@vetlock/detectors::runAll`.

The only subprocess we spawn on the analyzed package's behalf is the real `npm` / `pnpm` / `yarn` binary at the very end — and only when the verdict passes. Before that call, the package has never had a chance to touch the machine beyond a scratch dir of static files we own.

Tests that guard this invariant:
- `packages/core/test/never-execute-canary.test.ts` — fixture tarball drops a sentinel if any code ran; test asserts sentinel is absent.
- `packages/cli/test/add.test.ts` — the malicious-corpus test asserts a fake-PM stub file is NOT created when the verdict is BLOCK, proving `shellOutToPm` was never reached.

## How it compares

| Tool          | Runs at                     | Prevents postinstall exfil? | Blocks the install action?                 |
| ------------- | --------------------------- | --------------------------- | ------------------------------------------ |
| npm audit     | CI                          | No                          | No — advisory only                         |
| Snyk / Socket | CI + registry               | No                          | Registry-side; dev machine still vulnerable |
| guarddog      | Registry + CI               | No                          | Post-run scan                              |
| **vetlock add** | **Dev machine, pre-install** | **Yes**                     | **Yes — refuses `npm install`**            |

## Usage

```
# Explicit gate
vetlock add lodash@4.17.21          # CLEAN → shell out to npm install
vetlock add evil-typosquat@1.0      # BLOCK → exit 3, no install

# Report only
vetlock add lodash@4.17.21 --dry-run --json > report.json

# Force through (with scary banner)
vetlock add lodash@4.17.21 --force-danger

# Transparent shim over npm install
vetlock guard --install-shim
# add ~/.vetlock/bin to PATH in your rc file
npm install lodash@4.17.21          # transparently gated

# Escape hatch: allowlist a package you've reviewed
vetlock guard --allowlist add --package lodash --reason "trusted vendor pin"
```

## Latency

Measured on an M1 MacBook Pro (2026-07-15):

| Package                | Tarball size | Gate p50 (dry-run) | Notes                        |
| ---------------------- | ------------ | ------------------ | ---------------------------- |
| chalk@5.3.0 (corpus)   | 462 B        | ~16 ms             | Small stub                   |
| lodash@4.17.21 (real)  | 319 KB       | ~3.4 s             | 78 findings incl. 2 BLOCK    |

The dominant cost on a real package is the detector suite over the extracted AST — network fetch is a small addition on a first-time install and near-zero on pacote's cached second-time. Gate latency is bounded by the same tarball-size / file-count factors that any static analyzer faces.

## Failure modes we chose to accept

- **Latency on real installs** — a large tarball can take a few seconds. That's acceptable because the alternative is silent compromise. `--dry-run` and `--allowlist` are available for tight loops.
- **`vetlock add` requires network** unless the tarball is in pacote's cache. If your dev machine is offline, use `--dry-run` against a locally-fetched tarball.
- **Bare `npm install` (no package name)** — the shim passes through unchanged. That reinstalls whatever the lockfile says; if you want that gated, run `vetlock scan <lockfile>` in a pre-commit hook.
- **Registry impersonation** — `vetlock add` fetches via pacote, which honors your `.npmrc`. If your `.npmrc` points at a compromised registry, that's a machine-owner problem, not a `vetlock` problem.

See also: `packages/cli/README.md` for the full CLI surface, `docs/adr/0005-never-execute.md` for the invariant contract, and `docs/THREAT-MODEL.md` for the broader picture.
