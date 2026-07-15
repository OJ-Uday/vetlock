# vetlock — behavioral diff for npm dependency updates

`vetlock` answers **"what does this dependency update DO now that it didn't before?"**  
Behavior-first supply-chain security, focused on the diff that lands in a PR.

## Sub-commands

- **`vetlock diff <before> <after>`** — compare two lockfiles (npm / pnpm / yarn), report behavioral changes (new network endpoints, install-time scripts, new file writes, etc.).
- **`vetlock scan <lockfile>`** — scan-mode (single-input) capability profile: what does this tree DO?
- **`vetlock add <pkg>[@version]`** — **pre-install gate**. Fetch, statically analyze, and gate BEFORE the package manager runs any lifecycle script from the tarball. See below.
- **`vetlock guard [--install-shim|--allowlist …]`** — install a PATH shim that routes casual `npm install` / `pnpm add` / `yarn add` traffic through `vetlock add`. Also manages `~/.vetlock/allowlist.json`.
- **`vetlock demo`** — run against the bundled Shai-Hulud fixture (no network required).

## `vetlock add` — closing the postinstall window

The **largest attack window** in the npm supply chain is the "postinstall runs before CI sees the diff" gap:

1. developer runs `npm install evil@1.0`
2. npm downloads + extracts + runs `preinstall` / `install` / `postinstall`
3. postinstall exfiltrates `~/.npmrc`, `~/.aws/credentials`, env vars, …
4. postinstall completes; the developer machine is compromised
5. **only then** does the file diff exist for CI to review

Every CI-time scanner (Socket, npm audit, guarddog, Snyk) looks at packages **after** they've already had the chance to run on the dev machine. `vetlock add` closes that window by putting the detector suite in front of the package manager.

### Flow

```
vetlock add <name>[@version]
    │
    ├─ 1. Fetch tarball via pacote's tarball-only mode (bytes only, no extract).
    ├─ 2. Extract via @vetlock/core::safeExtract (ADR 0004) — NEVER runs code.
    ├─ 3. Run full detector suite (net / install / exec / fs / env / obf / …).
    ├─ 4. Verdict BLOCK  → refuse, exit 3, package manager is NOT invoked.
    │  Verdict CLEAN/WARN/INFO → shell out to `npm install` / `pnpm add` / …
    └─ (with --dry-run, step 4 stops after printing the report.)
```

### Options

| Flag              | Effect                                                                       |
| ----------------- | ---------------------------------------------------------------------------- |
| `--pm <manager>`  | Force `npm` / `pnpm` / `yarn`. Default: auto-detect from lockfile.           |
| `--registry <url>`| Registry base URL (overrides `.npmrc` for this call).                        |
| `--dry-run`       | Run the gate, print the report, skip the pm subprocess.                      |
| `--force-danger`  | Install even when BLOCK findings fire (prints a scary banner).               |
| `--json`          | Emit the gate report as JSON instead of TTY.                                 |
| `--quiet`         | Suppress all vetlock output (only the pm subprocess speaks).                 |

### Exit codes

| Code | Meaning                                                                     |
| ---- | --------------------------------------------------------------------------- |
| `0`  | Install proceeded (either CLEAN, WARN/INFO, or forced with `--force-danger`)|
| `3`  | Refused — BLOCK finding fired (or fail-closed on fetch/analyze failure)     |
| `4`  | Usage error (invalid package spec, missing flag)                            |
| `1`  | Package manager itself exited non-zero (bubbled)                            |

## `vetlock guard` — PATH shim for `npm install` traffic

`vetlock add` is only useful if you remember to type it. `guard` installs a tiny POSIX-sh shim to `~/.vetlock/bin/{npm,pnpm,yarn}` that intercepts install-family subcommands and re-invokes them through `vetlock add`.

```
vetlock guard --install-shim
# → writes ~/.vetlock/bin/{npm,pnpm,yarn}
# → prints the exact `export PATH=…` line you need to add to your shell rc

vetlock guard --status
# → reports which shims are installed + whether they're on PATH ahead of the real pm

vetlock guard --uninstall-shim
# → removes the shims

vetlock guard --allowlist add --package lodash --reason "trusted vendor bundle"
vetlock guard --allowlist list
vetlock guard --allowlist remove --package lodash
# → manages ~/.vetlock/allowlist.json — packages listed here bypass the gate
```

Non-install commands (`npm test`, `npm run build`, `pnpm ls`, `yarn build`) pass through to the real binary unchanged. The shim inspects `argv[2]` for `install` / `i` / `add`.

**Recursion guard**: when `vetlock add` shells out to the real `npm install`, it sets `VETLOCK_GUARD_BYPASS=1`. The shim checks this env variable and strips its own dir from PATH before exec'ing the real pm, so there's no infinite loop.

## The NEVER-EXECUTE invariant (ADR 0005)

Every code path in `vetlock add` — fetch, extract, parse, detect — is static. We never `import`, `require`, `dlopen`, `exec`, or `spawn` anything from the analyzed package. The `execFile` at the end runs the ACTUAL package manager (`npm` / `pnpm` / `yarn`) — that's the install itself, gated by our verdict.

If the developer aborts based on a BLOCK verdict, **no code from the analyzed package has ever executed on the machine**. This is verified by:

- `packages/core/test/never-execute-canary.test.ts` — a fixture tarball that leaves a sentinel if any code ran during analysis; the test asserts the sentinel doesn't exist.
- `packages/cli/test/add.test.ts` — the malicious-corpus test asserts that when a BLOCK verdict fires, the fake PM stub file is **not** created (proving `shellOutToPm` was never reached).

## What `vetlock add` does that CI-time scanners can't

| Scanner                          | Runs at                                        | Sees postinstall exfil? |
| -------------------------------- | ---------------------------------------------- | ----------------------- |
| Socket / Snyk / npm audit / …    | CI, after lockfile change                      | **After it already ran on the dev machine** |
| guarddog                         | Package registry / CI                          | Post-install only        |
| **vetlock diff/scan**            | CI, on the diff (behavior-oriented)            | Post-install only        |
| **vetlock add**                  | **Dev machine, BEFORE `npm install` runs**     | **Prevents it entirely** |

`vetlock add` is complementary to `vetlock diff` — CI still runs the diff on every PR. `vetlock add` is the client-side counterpart: the developer's machine is the primary target of typosquat + preinstall attacks, and it deserves its own gate.

## Development

```
pnpm install
pnpm --filter @vetlock/core build && pnpm --filter @vetlock/detectors build
pnpm --filter vetlock test
```
