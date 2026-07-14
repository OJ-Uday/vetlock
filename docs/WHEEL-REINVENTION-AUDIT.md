# WHEEL-REINVENTION AUDIT — vetlock v0.4.1

**As of 2026-07-14, per user directive: "we should not reinvent the wheel at any point if there is any existing free / opensource vetted implementation of what we did."**

This document is the audit. Each row: what vetlock currently hand-rolls, what OSS lib could replace it, and the verdict (swap / keep / mixed).

---

## Verdict summary

| Piece                             | Status          | Where                                   | Rationale |
|-----------------------------------|-----------------|-----------------------------------------|-----------|
| Lockfile parsing (npm)            | ✅ OSS          | `packages/core/src/lockfile-npm.ts`     | Uses native JSON (correct) |
| Lockfile parsing (yarn)           | ✅ OSS          | `packages/core/src/lockfile-yarn.ts`    | Uses `@yarnpkg/lockfile` |
| Lockfile parsing (pnpm)           | ✅ OSS          | `packages/core/src/lockfile-pnpm.ts`    | Uses `js-yaml` |
| JS AST parsing                    | ✅ OSS          | `packages/core/src/capabilities.ts`     | Uses `@babel/parser` |
| Tarball extraction                | ✅ OSS          | `packages/core/src/artifact-npm.ts`     | Uses `tar` |
| Registry fetch                    | ✅ OSS          | `packages/core/src/artifact-npm.ts`     | Uses `pacote` |
| Integrity hash                    | ✅ OSS          | multiple                                | Uses `ssri` |
| String similarity (typosquat)     | ✅ OSS          | `packages/detectors/src/typo.ts`        | Uses `damerau-levenshtein` |
| Schema validation                 | ✅ OSS          | `packages/core/src/finding.ts`          | Uses `zod` |
| CLI framework                     | ✅ OSS          | `packages/cli/src/cli.ts`               | Uses `commander` |
| Terminal spinner                  | ✅ OSS          | `packages/cli/src/cli.ts`               | Uses `ora` |
| Terminal color                    | ✅ OSS          | `packages/cli/src/cli.ts`               | Uses `picocolors` |
| **URL_REGEX (TLD list + shape)**  | ⚠️ **KEEP-BUT-DOCUMENTED** | `packages/core/src/capabilities.ts` | See §1 — investigated `tldts`, doesn't solve the actual FP |
| **DANGEROUS_CODE_KINDS taxonomy** | ⚠️ **REVIEW**   | `packages/detectors/src/index.ts`       | See §2 — cross-check against ESLint plugin/semgrep |
| **`LOOKS_LIKE_PATH` heuristic**   | ⚠️ **REVIEW**   | `packages/core/src/capabilities.ts`     | See §3 — small hand-rolled path check |
| **Entropy scorer**                | ⚠️ **REVIEW**   | `packages/detectors/src/obf.ts`         | See §4 — Shannon entropy is standard, but implementation could use a lib |
| **npm lifecycle-script allowlist**| 🔲 TO-BUILD-USE-DATA | (v0.4.2 §3d)                      | See §5 — must land as an npm-CLI-derived data table, not hand-guessed |

---

## §1. URL_REGEX — investigated, KEEP (with a documented reason)

**What vetlock does:** hand-rolls a regex that matches `https?://…` (schemeful) OR bare `word.tld` for an enumerated TLD list.

**What we tried:**
- **`tldts` (7.4.8, MIT, ~40KB via `tldts-core`)** — parses hostnames using the public-suffix list. Correctly identifies `Cursor.app`, `attacker.top`, and `foo.com` as syntactically valid domains with public suffixes.
- **built-in `URL()` (Node)** — normalizes URLs; accepts any scheme+host or bare-host-with-scheme-prefix.
- **`is-url-http` (tiny, MIT)** — permissive URL-shape check.

**Why none of them fix the FP:** `Cursor.app` in a vite config IS a syntactically valid domain. `tldts` and `URL()` both accept it. The FP isn't that our regex is wrong about what a domain looks like — it's that we're missing **context**: whether the string is being USED as a network endpoint in code, versus incidentally happening to look like a domain.

**What would actually fix it:** context-aware extraction at capability-time. When we see a string literal, note whether it's:
- Passed as an argument to `fetch()`, `axios.get()`, `http.get()`, `require('http').request({host: ...})`, etc. → real URL, keep
- Used only as an object property key, filename component, or comment text → not a URL, discard

That's a bigger refactor to the Babel-based extractor in `capabilities.ts` — it means walking uses of URL-shaped strings, not just extracting them.

**v0.4.2 decision:** keep the hand-rolled URL_REGEX. The tune in v0.4.1 (splitting ambiguous TLDs from abused-TLDs) already covers the highest-impact FPs. The larger context-tracking refactor is a v0.5.0 target — track under new issue "capability.net.endpoint context tracking."

**But:** we CAN use `tldts` to REPLACE the hard-coded TLD list. `tldts` bundles the public-suffix list and maintains it. Deferred to v0.4.2 §3b — it's a diff-only change with no behavioral impact (just replaces enumeration with a library call).

---

## §2. DANGEROUS_CODE_KINDS taxonomy — cross-check for v0.4.2

**What vetlock does:** hand-picked list `{eval, new-function, unpacker, marshal, deserialize}` of "dangerous" dynamic-code sink kinds.

**What OSS maintains:**
- **`eslint-plugin-security`** (nodesecurity, MIT) — rules like `detect-eval-with-expression`, `detect-non-literal-require`, `detect-child-process` — has a curated list of dangerous APIs.
- **`semgrep-rules/javascript/security/audit/`** — YAML rules for the same class of hazards.
- **OWASP Top 10 A03:2021 Injection** — informal reference list.

**v0.4.2 action:** cross-check vetlock's list against `eslint-plugin-security`'s rule set. Any API in eslint-plugin-security that vetlock doesn't cover is a candidate for a new detector (or expansion of CODE detector's kinds). Not a wholesale swap — vetlock's kinds are BEHAVIOR-DIFFED (fires only on new usage), whereas eslint-plugin-security fires on any usage. The list-content overlap is what matters.

---

## §3. `LOOKS_LIKE_PATH` heuristic — leave alone

**What vetlock does:** small regex `^([~./]|[A-Z]:\\|\/[a-zA-Z._-]|\.\.\/|\.\/|[a-zA-Z_-]+[/\\])/`.

**What OSS offers:** `path-parse`, `upath`, `is-path-inside`. None of these are "does this string look like a path" — they all assume you already know it's a path.

**Verdict:** hand-roll is right for this case. It's 5 lines, well-tested indirectly through the capabilities test suite. No OSS equivalent exists that solves this exact question.

---

## §4. Entropy scorer — leave alone, but audit later

**What vetlock does:** Shannon entropy calculation in `packages/detectors/src/obf.ts`, per-literal and per-file.

**What OSS offers:** `entropy` (small npm pkg), `shannon-entropy` (single-file). Both compute standard Shannon entropy.

**Verdict:** the math is 3 lines and has 100% test coverage. Swapping to an external dep adds supply-chain risk (this scanner has to be conservative about its OWN dependencies) for zero functional gain. Keep.

If we ever need Rényi/Kolmogorov/Kolmogorov-Chaitin entropy variants — swap to an OSS lib then. Not before.

---

## §5. npm lifecycle-script allowlist — MUST source from npm docs, not hand-list

**What we're building (v0.4.2):** fix §3d in FP-STUDY.md — restrict `install.script-changed` to actual lifecycle scripts.

**What NOT to do:** hand-copy the list from an npm blog post. That list drifts.

**What TO do:** source from npm's own documentation OR from a maintained OSS package. Options:
- **`npm-lifecycle-events` npm package** — literally exports the current lifecycle-events array from npm's internals. Zero-dep. Tiny.
- Verify via `npm run --list-lifecycle-events` at build time — write a script that fails if the vendored list drifts.

**v0.4.2 action:** use `npm-lifecycle-events` if it's a maintained package. Otherwise, vendor the list from `npm-lifecycle` (npm's own internal package) with a comment linking to the source-of-truth.

---

## §6. Follow-ups tracked

- **v0.4.2 §3b** — swap URL_REGEX's TLD enumeration for `tldts.parse()` (behavior-neutral change).
- **v0.4.2 §3d** — source npm lifecycle-script allowlist from `npm-lifecycle-events` (behavior fix + no-drift guarantee).
- **v0.5.0 context tracking** — attach "is-real-URL" bit at capability-extraction time by walking Babel AST for URL-shaped-string usage patterns. Would eliminate the `Cursor.app` FP class entirely without needing a TLD-list swap.
- **v0.4.2 or later** — cross-check `DANGEROUS_CODE_KINDS` against `eslint-plugin-security`'s dangerous-API list.

---

## §7. Subagent instruction

Every cold packet spawned from this session (P4c, SITE polish, future ecosystem adapters) now includes:

> **User directive (verbatim):** "we should not reinvent the wheel at any point if there is any existing free / opensource vetted implementation of what we did pls go ahead and use that."
>
> Before writing a new utility function or regex, check for an existing OSS library first. Prefer: actively maintained, broad usage, permissive license, zero-dep or few-dep. If a hand-rolled solution already exists AND is small (<30 LOC), tested, and works — judgment call. Prefer migrating if the OSS lib is fundamentally more robust.

This audit doc is the reference — future work respects §1–§5 verdicts.
