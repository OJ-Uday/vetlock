# TODO — road to v1.0 launch

Living checklist, ordered by priority tier. Companion to
[`LAUNCH-CHECKLIST.md`](LAUNCH-CHECKLIST.md) (the full P9-gate tracking doc)
and [`ROADMAP.md`](ROADMAP.md) (feature-shaped, version-numbered plan) — this
file is the "what do I actually do next session" list, cutting across both.
See [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) for the current live-topology
snapshot these items build on.

## P0 (launch blockers — do next session)

- [ ] **Publish `@oj-uday/vetlock@0.8.0` to npm with public access.** Blocks: the
  hosted-scan API path (`vetlock-app`'s `POST /scan`) currently returns
  verdict `"failed"` on every run because `npx @oj-uday/vetlock@latest` inside
  `vetlock-web-scans`' `hosted-scan.yml` gets a 404 — the package has never
  been published. Make the first scoped release manually with a granular npm
  token and `--access public`; local publishing cannot attach provenance.
  Then configure npm Trusted Publishing for `OJ-Uday/vetlock` and
  `.github/workflows/publish.yml` so future tag releases use OIDC provenance.
  Push annotated tag `v0.8.0` at the scoped-name merge commit after publishing;
  the idempotent workflow will test and no-op because the version exists. Verify:
  `npx @oj-uday/vetlock@latest --version` succeeds from a clean machine, and the
  next hosted `/scan` returns a real verdict instead of `"failed"`.
- [ ] **Register `vetlock.dev`** (~$12/yr at Cloudflare Registrar, same
  account as the Worker — `udayojha129`). Unblocks: `app.vetlock.dev`
  routing for the Worker (the commented-out `routes` block in
  `vetlock-app/worker/wrangler.toml` is ready to uncomment),
  `docs.vetlock.dev` for a docs site, `security@vetlock.dev` for the
  disclosure address `vetlock-app/docs/SECURITY.md` currently flags as
  "not live yet," and a professional URL for company launch generally.
- [ ] **Real-repo test of the GitHub App path.** Install the `vetlock`
  GitHub App (github.com/apps/vetlock) on a private repo you own, add
  `.github/workflows/vetlock.yml` from `vetlock-app/workflows/`, set the
  `VETLOCK_INGEST_SECRET` repo secret, open a PR that touches
  `package-lock.json`, and verify: the `vetlock` check-run appears within
  seconds of the PR opening (status `queued` → `in_progress`), and a PR
  comment lands once the scan completes. This is the one piece of the App
  flow that's wired and unit-tested but has never actually run against a
  real GitHub PR — everything to date is webhook-ping-level verification
  (`vetlock-app/DEPLOYED.md`'s "Verified working" section).

## P1 (P3 packet — OSS launch polish)

- [ ] **GitHub Marketplace listing for the action** (`action/` at repo
  root, exposed via `action.yml`). The Marketplace publish button lives at
  github.com/OJ-Uday/vetlock/releases → draft a new release tagged for the
  action and check "Publish this Action to the GitHub Marketplace."
  Requires a category, description, and icon per GitHub's Marketplace
  listing requirements.
- [ ] **`npx @oj-uday/vetlock demo` flawless on a clean machine.** Spin up a fresh
  Docker container (no prior npm cache, no Lilly-network assumptions), run
  `npx @oj-uday/vetlock@latest demo`, and confirm it runs the bundled Shai-Hulud
  fixture end-to-end with no errors. Patch anything that surfaces — this
  is gating item in `LAUNCH-CHECKLIST.md`'s OSS-core section, and depends
  on the P0 npm-publish item above landing first (there's nothing at
  `@oj-uday/vetlock@latest` to demo until then).
- [ ] **README polish pass.** Hero GIF captured from the site scanner
  (oj-uday.github.io's live demo), a comparison table against Snyk/Socket/
  `npm audit`, a tightened quickstart, the honesty section (12/13 corpus,
  the one documented miss), and a link out to the red-team story
  (`docs/REDTEAM-2026-07-12.md`).
- [ ] **Site drift bump.** `oj-uday.github.io` still advertises `v0.4.2` /
  424 tests / 39/48 red-team on its vetlock exhibit. Actual current state
  is `v0.7.0` / 540 tests / GitHub App **live** (App ID `4298344`, Active).
  Every number on that page should trace to an artifact in this repo per
  `LAUNCH-CHECKLIST.md`'s non-negotiable rule — right now several don't.

## P2 (P4c corpus — PyPI fixtures)

- [ ] **Add 5 real known-bad PyPI corpus fixtures**: `ctx@0.2.2` (AWS-cred
  exfil via a malicious `setup.py`), a `jeIlyfish` typosquat (capital-I for
  lowercase-l), a `colorama`-adjacent typo-squat family, `discordpydebug`
  (info-stealer masquerading as a debug helper). Each fixture must be
  **defanged** per this repo's existing convention — RFC-2606 reserved
  domains (`.invalid`/`.example`/`.test`) or loopback only, any executable
  payload guarded by `if(false)` (or the Python equivalent, e.g. a
  provably-false condition), enforced the same way
  `corpus-defanged.test.ts` enforces it for the npm corpus today. Once
  landed, promote the relevant entries among the 8 PyPI
  `soft_warn_no_corpus: true` `CAPABILITY-MAP.md` entries
  (`urllib-first-use`, `socket-first-use`, `os-environ-read`,
  `b64-plus-exec`, `marshal-loads`, `setup-py-cmdclass`,
  `pyproject-entry-points`, `typosquat-underscore-hyphen`) to
  hard-covered by attaching real `corpus_refs[]`.
- [ ] **Run the FP study on top-100 PyPI packages** using the
  Artifactory-proxied `fp-study.ts` (see the `fp-study-use-lilly-artifactory`
  memory for the env-var-only fetch-source setup — never commit an
  Artifactory URL into `.npmrc` or any other committed file). Currently
  `docs/FP-STUDY.md` only reflects an npm-ecosystem run; PyPI has zero FP
  data yet.

## P3 (P7 — org dashboard)

- [ ] **React SPA at `dashboard.vetlock.dev`** (or a subpath on
  `vetlock.dev` if a separate subdomain proves annoying to wire before the
  domain is even registered — see the P0 domain item). Shows: recent
  scans, findings by severity, per-repo posture, and the north-star metric
  (findings-blocked-per-week, per `LAUNCH-CHECKLIST.md`'s P7 note). Auth
  via GitHub OAuth — reuse the App's existing OAuth manifest rather than
  standing up a second auth flow, and cross-check against the
  org-scoped installation-token flow the Worker already has in
  `vetlock-app/worker/worker.js`'s `getInstallationToken`.

## P4 (P8 — enterprise scaffolding)

- [ ] SSO/SAML flag behind an env var.
- [ ] Policy-as-code: `.vetlock-policy.yml` at repo root — e.g. "block any
  new install script," "allowlist these domains."
- [ ] SBOM/VEX export (CycloneDX schema) — see `ROADMAP.md`'s "Someday"
  `sbom` companion item; this is the enterprise-facing version of that.
- [ ] Self-host deployment guide — docker-compose for local use, a Helm
  chart for anyone who wants the Worker path running on their own
  Cloudflare account/K8s instead of ours.
- [ ] Public status page (statuspage.io free tier, or a static HTML page
  on the portfolio site if that's cheaper to stand up before there's real
  traffic to monitor).

## P5 (P9 — company launch)

- [ ] Landing page at `vetlock.dev` — "Scan your lockfile" as the primary
  CTA (currently only reachable at oj-uday.github.io/#scan, a portfolio
  page, not a product page).
- [ ] Pricing page (free tier, team tier, enterprise tier — even if
  enterprise is just "contact us" for now).
- [ ] ToS + Privacy Policy — a security SaaS handling other people's
  lockfiles needs a real DPA, not a placeholder.
- [ ] Waitlist / demand capture (email form on the landing page).
- [ ] Show HN post: "I replayed a decade of npm supply-chain attacks and
  hardened a scanner in public — here's the company." Per
  `LAUNCH-CHECKLIST.md`'s launch-sequence ordering, this should be written
  and ready to go **before** going live, so it can drop with real traffic
  rather than lag it.
- [ ] r/netsec + OpenSSF community outreach.
- [ ] Company legal: entity formation (Delaware C-corp or India Pvt Ltd —
  still an open decision). See `PACKET-VETLOCK-STARTUP.md` §9 — the
  employer-IP check was confirmed clean earlier this session (vetlock is
  personal IP, built off-hours on personal hardware; documented in a
  private note, deliberately **not** in this repo).

## v0.8+ (ADR 0008 hardening)

- [ ] Wire `ScanQueue` → `runScanInSandbox` **by default**. Right now
  `packages/api/src/scan-queue.ts`'s default backend calls straight into
  `@vetlock/core`'s in-process `runDiff` — the subprocess-per-scan sandbox
  (`packages/api/src/sandbox.ts`'s `runScanInSandbox`) exists and is
  tested, but isn't the wire path a real `ScanQueue` consumer gets by
  default yet.
- [ ] `--experimental-permission` on the sandbox subprocess — deferred out
  of v0.7 because Node's permission model is still experimental and the
  flag's exact semantics have shifted across recent Node LTS lines; revisit
  once it stabilizes.
- [ ] Rate-limit key on `cf-connecting-ip` for the hosted-scan API is in
  place (`vetlock-app/worker/worker.js`'s `isHostedScanRateLimited`) but
  has only been exercised at the 5-requests-trips-429 level, not tested
  under real burst/adversarial load. Worth a load-test pass before Path B
  gets any real traffic volume.

## v0.6.1 (PyPI corpus attach)

- [ ] Attach real corpus fixtures to the 8 PyPI `soft_warn_no_corpus: true`
  `CAPABILITY-MAP.md` entries — same underlying work as the P2 item above;
  listed here too because it's also tracked as a version-numbered
  `ROADMAP.md`-adjacent commitment, not just a P2-packet nice-to-have.
