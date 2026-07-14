# LAUNCH-CHECKLIST.md

Living, tickable list of everything that must be true before vetlock can
"take a customer tomorrow" (the P9 gate in `packets/PACKET-VETLOCK-STARTUP.md`).

Each item cites the phase or ADR that gates it. Tick as they complete. **No
box is ticked speculatively** — if a claim isn't reproducible from an
artifact in this repo, it's not done.

---

## OSS core (must all be true before public launch)

- [x] Apache-2.0 license, `OJ-Uday/vetlock`, public repo (v0.3.0 shipped 2026-07-12)
- [x] 375+ tests green in CI (baseline v0.3.0; +9 in P1-A → 384)
- [x] NEVER-EXECUTE canary green (`packages/core/test/never-execute-canary.test.ts`)
- [x] Safe-extract (zipslip/tarbomb/symlink) tested (`packages/core/test/extract.test.ts`)
- [ ] **P1-A** pnpm/yarn end-to-end diff tests + F1 no-crash regression guard (in flight — new tests written, yarn-berry `checksum` bug fixed)
- [ ] **P1-B** worker-timeout test (fan-out running)
- [ ] **P1-C** determinism goldens + drift test (fan-out running)
- [ ] **P1-D** CAPABILITY-MAP + coverage gate — soft-warn during P1 backfill, hard-fail after (fan-out running)
- [ ] **P1-E** red-team tail (4 remaining exploits): close where cheap, honest-disclose otherwise (fan-out running)
- [ ] P2 FP study run + published (`docs/FP-STUDY.md`) — top-100 × 5 bumps ≈ 500 diffs, per-detector rate, tuning journey
- [ ] `.npmrc` committed with public registry (verified 2026-07-13; c20a66d — no Artifactory URL in any committed file)
- [ ] `npm publish --provenance` on next release (supply-chain hygiene symmetry — a supply-chain tool ships with provenance)
- [ ] `npx vetlock demo` flawless on a clean machine (already ships bundled Shai-Hulud fixture in `dist/demo-fixture/`; verify from a non-Lilly machine before P9)
- [ ] README final: hero GIF from site scanner, comparison table, quickstart, honesty section, red-team story link
- [ ] GitHub Marketplace listing for the Action (screenshots, category, description, verified org — P9)
- [ ] External PR shows the bot comment (Action dogfooded on vetlock's own PRs)

## Site (companion PACKET-VETLOCK-SITE.md — bar: "awe on sight")

- [x] Live at `https://oj-uday.github.io/`, deployed via GitHub Pages
- [x] Scanner exhibit live (browser → CF Worker → Actions dispatch, ~25 s scan)
- [x] Résumé link now points at `OJ-Uday/resume` repo (single source of truth)
- [ ] Design-system reusable across `oj-uday.github.io` (portfolio) and `vetlock.dev` (product) — per site packet P5
- [ ] Hero watcher visualization (site packet P2 — the signature moment)
- [ ] Show-don't-tell content (site packet P4 — the audit-identified gap)
- [ ] Perf pass: LCP < 2.0 s, no CLS on any interaction, TBT under budget (site packet P6)
- [ ] `vetlock.dev` domain secured (per ADR 0010; do BEFORE any public writeup)
- [ ] `vetlock-dev/vetlock-app` GH org created (post-incorporation only)

## Trust trilogy (packet §7 — publish in this order BEFORE any growth push)

- [ ] `docs/BENCHMARK.md` — public detection benchmark scoreboard, versioned corpus, submission process (P4)
- [ ] `docs/FP-STUDY.md` — false-positive rate, methodology, residuals (P2)
- [ ] `docs/REDTEAM-2026-07-12.md` + follow-up rounds — published, external submission channel open

## Hosted MVP (packet §6 P5/P6/P7 — the commercial core)

- [ ] `vetlock-dev/vetlock-app` repo created (post-incorporation)
- [ ] Hosted API wrapping the OSS engine (POST lockfile pair → findings)
  - [ ] `ephemeral-teardown.test` green (ADR 0008)
  - [ ] `tenant-isolation.test` green (ADR 0008)
  - [ ] `oss-no-network.test` still green on the OSS repo (ADR 0006 D5)
  - [ ] `never-execute-serverside.test` green (ADR 0008)
  - [ ] `docs/PRIVACY-ARCHITECTURE.md` published publicly on `vetlock-app`
- [ ] GitHub App installed on a test org → PR opens with a lockfile bump → Check appears with findings (P6)
  - [ ] `app-permissions-minimal.test` green (ADR 0007)
  - [ ] `app-webhook-pr-check.test` green (ADR 0007)
  - [ ] `app-config-precedence.test` green
  - [ ] Screenshot/GIF captured for the site
- [ ] Org dashboard live at `dash.vetlock.dev` (or equivalent)
  - [ ] Recent scans, findings by severity, per-repo posture
  - [ ] North-star: findings-blocked-per-week (P7)
  - [ ] FP-report button wired
- [ ] GitHub App published to Marketplace (verified org, screenshots, ToS/privacy/security disclosure)

## Company shell (§3 checklist, per STARTUP packet)

- [ ] Landing page (built from the site packet's design system)
- [ ] Docs site (own subdomain — `docs.vetlock.dev`)
- [ ] Pricing page (even if enterprise = "contact us"; team = self-serve)
- [ ] Waitlist for paid tier (demand-capture — pre-launch)
- [ ] SECURITY.md disclosure policy (already exists on `OJ-Uday/vetlock`; add hosted-scope equivalent to `vetlock-app`)
- [ ] Privacy policy (data-processing addendum for lockfile handling)
- [ ] Terms of Service (with the ephemeral-analysis promise as a contractual term)
- [ ] Public status page (`status.vetlock.dev`)
- [ ] Discord or GitHub Discussions for community

## Legal gate (packet §9 — must resolve BEFORE incorporation)

- [x] Employer IP check confirmed clean — vetlock is personal IP, built off-hours on personal hardware (user-confirmed 2026-07-13; documented in private note, NOT in repo)
- [ ] Entity formation (Delaware C-corp OR India Pvt Ltd — user's decision)
- [ ] Trademark search for `VETLOCK` word mark (USPTO / EUIPO / IP-India as scope demands)
- [ ] `SECURITY.md` public disclosure email set up (`security@vetlock.dev` once domain secured)

## Trust trilogy published (§7)

- [ ] Public benchmark repo (`vetlock-dev/vetlock-benchmark`)
  - [ ] Versioned defanged corpus
  - [ ] Scoring harness
  - [ ] vetlock scored (honest self-score, including misses)
  - [ ] At least one competitor scored honestly (OSV-Scanner, npm audit, or similar)
  - [ ] Submission process (PR template for new attacks, defang-guard test)
- [ ] FP study run + published (see OSS section)
- [ ] Red-team status-update section on `docs/REDTEAM-2026-07-12.md` — reflects post-v0.3.0 state (P1-E)

## Launch sequence (P9 — order matters)

- [ ] Trust trilogy published (all three above)
- [ ] Blog post: "I replayed a decade of npm supply-chain attacks and hardened a scanner in public — here's the company" (the Show HN — plan the post BEFORE going live so it drops with real traffic)
- [ ] Show HN + r/netsec + Changelog + GitHub App Marketplace
- [ ] Outreach: Renovate/Dependabot communities, OpenSSF, awesome-supply-chain lists
- [ ] Portfolio/resume/pins updated (`generate.cjs` → rebuild → 1-page verify per resume repo)
- [ ] `oj-uday.github.io` "the vetlock story" in Systems section refreshed for launch mode

---

**When every box above is ticked, the P9 gate is satisfied.** You could take
a customer tomorrow — hosted GitHub App live, dashboard functional, docs
truthful, legal clean, and the trust trilogy is the evidence backing every
claim on the marketing site.

**Non-negotiable:** if a claim on the site or in a blog post cannot be traced
to a test or a published artifact in this repo, the launch is blocked until
the trace exists. (§0 rule 5.)
