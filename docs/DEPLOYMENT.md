# Vetlock — deployment topology (2026-07-19)

This document is the cross-repo map: what's actually live, how the two
service paths differ, what they cost, and what secrets exist where. It
complements — does not replace — each repo's own docs:

- Scanning engine security posture: [`SECURITY.md`](../SECURITY.md) (this repo)
- Routing-layer security posture: `vetlock-app/docs/SECURITY.md`
- Sequence-by-sequence runtime walkthrough: `vetlock-app/docs/ARCHITECTURE.md`
- Point-in-time deployment snapshot: `vetlock-app/DEPLOYED.md`

If any number below drifts from those files, those files win — this
document is a map, not the source of truth for any single fact.

## What's live now

| Component | Where | Status |
|---|---|---|
| Vetlock OSS repo | github.com/OJ-Uday/vetlock | Public, tag `v0.8.0`, release gate green |
| Vetlock CLI | npmjs.com/package/@oj-uday/vetlock | Public, `latest` = `0.8.0`; registry smoke test passed |
| Vetlock GitHub App | github.com/apps/vetlock (App ID `4298344`) | Registered + Active, not yet installed on a real repo |
| Cloudflare Worker | https://vetlock-app.oj-uday.workers.dev | Deployed, version `5ed5b3f1-e708-449e-b9ab-c7597d27e40c` |
| Runner repo | github.com/OJ-Uday/vetlock-web-scans | Public, unlimited GHA minutes |
| MCP admission server | `packages/mcp` | Source preview; private workspace package, not published |

Verify each independently:

```bash
# Worker liveness
curl -s https://vetlock-app.oj-uday.workers.dev/health
# → {"ok":true,"service":"vetlock-app-worker"}

# GitHub App page and installation route resolve
curl -s -o /dev/null -w '%{http_code}\n' https://github.com/apps/vetlock
# → 200

# Runner repo exists and is public
gh repo view OJ-Uday/vetlock-web-scans --json visibility,url

# Public package and release tag
npm view @oj-uday/vetlock version
# → 0.8.0
git ls-remote --tags https://github.com/OJ-Uday/vetlock.git refs/tags/v0.8.0

# Install URL resolves (302 to GitHub's install-choice page, not a 404)
curl -s -o /dev/null -w '%{http_code}\n' https://github.com/apps/vetlock/installations/new
```

Note the App is registered and the webhook is wired and tested (ping →
`200 {"pong":true}`), but it has **not yet been installed on a real repo**
with a real PR run through it — that's a P0 item in `TODO.md`, not a
"live" claim being made here.

The hosted-scan plumbing completed an end-to-end run before the npm release,
but that run ended in `"failed"` because the CLI did not yet exist on npm.
Now that `@oj-uday/vetlock@0.8.0` is public, one fresh hosted scan is still
required before claiming the post-release payload path is live.

## Architecture — two service paths

Vetlock ships **two independent HTTP entry points into the same underlying
engine** (`packages/core`'s `runDiff`), because they serve two different
audiences with two different trust models:

```
PATH A — GitHub App webhook flow (per-repo checks, per-user compute)
══════════════════════════════════════════════════════════════════════

  Contributor          GitHub               CF Worker            User's own
  opens PR      ───▶   fires             ───▶ /webhook       ───▶ GHA runner
  touching             pull_request            (HMAC-verify         (their org,
  lockfile             webhook                  X-Hub-Signature-     their quota)
                       (HMAC-signed)             256, replay
                                                  guard, mints          │
                                                  installation           │ npx @oj-uday/vetlock diff
                                                  token, creates          │ base.lock head.lock
                                                  check-run:queued,        │
                                                  fires                    ▼
                                                  repository_dispatch    checkout base SHA
                                                       │                 checkout head SHA
                                                       │                 run + verdict
                                                       ▼                     │
                                              check-run appears  ◀──────────┘
                                              in PR UI              POST /result
                                              immediately          (RESULT_INGEST_SECRET
                                                   ▲                 + single-use
                                                   │                 scan_token)
                                                   │
                                          CF Worker PATCHes
                                          check-run: completed
                                          + posts/updates one
                                          sticky PR comment


PATH B — Hosted scan API (anonymous, single-scan, our compute)
══════════════════════════════════════════════════════════════════════

  Anyone           CF Worker            repository_dispatch      vetlock-web-scans
  POST /scan  ───▶  /scan            ───▶  (hosted-scan)     ───▶  (repo WE control)
  { lockfile_       (rate-limited            event, fired            │
    before,          5/min/IP, size-         with                     │ npx @oj-uday/vetlock diff
    lockfile_        capped, gzip+           HOSTED_SCAN_              │ (same OSS code path
    after }          base64'd, KV            DISPATCH_TOKEN             │  as Path A)
                      entry written:                                     ▼
                      status=queued)                              POST /result-scan
                          │                                       (HOSTED_SCAN_INGEST_
                          │                                        SECRET, distinct from
                          ▼                                        RESULT_INGEST_SECRET)
                  GET /scan/:id                                          │
                  (poll loop)        ◀────────────────────────────────────┘
                  → 202 queued/running               KV entry updated:
                  → 200 verdict+findings              status=done|failed,
                    when status=done                  verdict, findings
```

### Why the split exists

**Path A (App)** is the "install once, every repo gets checks" story. The
scan runs on **the installing user's own GitHub Actions runner**, using
**their own compute quota** — vetlock's control plane (the Worker) never
touches lockfile content, never runs a scan, and costs the same whether one
org or ten thousand orgs install it. This is the shape documented in
`vetlock-app/README.md`'s "Why this shape" section and is what
[ADR 0008](adr/0008-ephemeral-analysis.md) means by "ephemeral tenant
isolation, for free" — GitHub's runner fleet is the sandbox, not code we
wrote.

**Path B (hosted API)** exists because Path A has a hard precondition: the
caller must install a GitHub App on a repo they administer. That's the
wrong shape for "let a stranger paste two lockfiles and see a verdict in
under a minute" — a portfolio-site demo, a Slack bot, a CI system that
isn't GitHub Actions. Path B trades that precondition for using **our own**
GitHub Actions quota (`vetlock-web-scans`, a repo we own) instead of the
caller's — which is why it needs its own rate limiter (keyed on
`cf-connecting-ip`, not `installation_id`) and its own ingest secret
(`HOSTED_SCAN_INGEST_SECRET`, never shared with Path A's
`RESULT_INGEST_SECRET`): an anonymous caller is a fundamentally
lower-trust caller than an installed App's own dispatch.

Both paths converge on the exact same `runDiff` call
([ADR 0006](adr/0006-open-core-boundary.md), open-core boundary) — neither
routing layer re-implements or forks any detection logic.

## Cost model

| Resource | Free-tier threshold | Current usage | Cost/mo |
|---|---|---|---|
| CF Worker requests | 100k req/day | Low hundreds/day at most (webhook + `/scan` + polling) | $0 |
| CF KV (`HOSTED_SCANS`) reads | 100k reads/day | Polling-driven; a 60s scan at 3s poll interval ≈ 20 reads/scan | $0 |
| CF KV writes | 1,000 writes/day | 2 writes/scan (create + finalize) | $0 |
| GHA minutes — `vetlock-web-scans` (public repo) | Unlimited | Unmetered | $0 |
| GHA minutes — installer's own repo (Path A) | Not our cost | N/A — billed to the installing org, not us | $0 (to us) |
| Domain (`vetlock.dev`) | — | **Not yet registered** | pending (~$12/yr at Cloudflare Registrar — see `TODO.md` P0) |

**Total current infrastructure cost: $0/mo.** The only place this changes
is if request/scan volume clears the free-tier thresholds above (unlikely
at pre-launch traffic) or once `vetlock.dev` is registered (a one-time/yearly
domain cost, not a scaling cost — routing is still free-tier CF Worker
routes per `worker/wrangler.toml`'s commented-out `routes` block).

## Security invariants (cross-reference SECURITY.md files)

Line numbers below are from `vetlock-app/worker/worker.js` as of version
`5ed5b3f1-e708-449e-b9ab-c7597d27e40c`. See `vetlock-app/docs/SECURITY.md`
for the full prose version of every invariant in this section — this is
the condensed, line-cited cross-reference.

### Path A — GitHub App webhook flow

| Invariant | Enforced at |
|---|---|
| HMAC-SHA256 verified over the **raw** request body before any parsing | `worker.js:476-483` (`handleWebhook` calls `verifyWebhookSignature` before `JSON.parse`) |
| Constant-time signature comparison (no timing leak) | `worker.js:176-188` (`timingSafeEqualHex`), used by `verifyWebhookSignature` at `worker.js:197-208` |
| Replay guard — `X-GitHub-Delivery` id deduped for 5 minutes | `worker.js:438-443` (`isReplay`), called at `worker.js:527` |
| Per-installation rate limit — 100 req/60s | `worker.js:414-432` (`isRateLimited`), called at `worker.js:496` |
| Check-run created **before** dispatch, so a scan_token can bind to a real `check_run_id` | `worker.js:544-559` (comment + `checkRunResult` call precedes the dispatch call at `worker.js:582`) |
| Single-use `scan_token` binds `/result` to the exact `{owner, repo, pr_number, installation_id, check_run_id}` tuple issued at dispatch time — caller-supplied identifiers are never trusted | `worker.js:561-580` (mint + cache), `worker.js:667-682` (`handleResult` reads the *stored* binding, ignores caller-supplied fields) |
| `/result` requires `RESULT_INGEST_SECRET`, checked constant-time | `worker.js:640-645` |
| Token evicted immediately on use — a replay of the same `/result` POST fails as a 404 cache-miss | `worker.js:673-677` |
| JWT lifetime capped at 9 minutes (`iat = now-60`, `exp = now+540`) | `worker.js:332-` (`mintAppJwt`) |
| Installation tokens cached ≤55 minutes regardless of GitHub's stated expiry | `worker.js:381-` (`getInstallationToken`, `TOKEN_CACHE_SAFETY_MARGIN_SECONDS` at `worker.js:28`) |

### Path B — hosted-scan flow

| Invariant | Enforced at |
|---|---|
| Rate limit — 5 req/60s per `cf-connecting-ip`, separate bucket from Path A's rate limiter | `worker.js:453-469` (`isHostedScanRateLimited`), called at `worker.js:763-768` |
| Body-size cap (1 MB) checked on raw bytes **before** `JSON.parse` | `worker.js:773-777` (`HOSTED_SCAN_MAX_BODY_BYTES` at `worker.js:46`) |
| Per-lockfile size cap (500 KB each) | `worker.js:794-803` (`HOSTED_SCAN_MAX_LOCKFILE_BYTES` at `worker.js:45`) |
| gzip+base64 compression checked against GitHub's 65 KB `client_payload` cap (60 KB margin enforced) | `worker.js:805-818` (`HOSTED_SCAN_MAX_COMPRESSED_BYTES` at `worker.js:51`) |
| Dispatch fires on `vetlock-web-scans` (a repo **we** control), using `HOSTED_SCAN_DISPATCH_TOKEN` — never the caller's credentials | `worker.js:822-842` |
| `GET /scan/:id` only accepts `[a-f0-9-]{16,}` ids — anything else is a 400 before any KV lookup | `HOSTED_SCAN_ID_PATTERN` at `worker.js:53`, enforced by the router before `handleHostedScanPoll` is called |
| `/result-scan` requires `HOSTED_SCAN_INGEST_SECRET` — a **different** secret from `RESULT_INGEST_SECRET`, so leaking one never weakens the other | `worker.js:919-924` |
| `/result-scan` fails closed with 404 on any `scan_id` never issued by our own `/scan` — a caller with only the shared ingest secret can't manufacture a result out of thin air | `worker.js:941-951` (`handleHostedScanResult` requires a pre-existing KV entry) |
| Verdict values constrained to a fixed set (`BLOCK`/`WARN`/`INFO`/`CLEAN`/`FAILED`) | `HOSTED_SCAN_VALID_VERDICTS` at `worker.js:52`, checked by `validateHostedScanResultBody` at `worker.js:912-917` |
| KV (not `caches.default`) used for scan state — `caches.default` is region-local and would let `/scan`'s write and `/result-scan`'s read land on different edge PoPs with different data | `worker/wrangler.toml` comment above the `HOSTED_SCANS` binding; `kvGetJson`/`kvPutJson` at `worker.js:143-150` |

Both flows share the underlying invariant that the Worker **never executes
or even parses** lockfile content — see `vetlock`'s own
[`docs/adr/0005-never-execute.md`](adr/0005-never-execute.md). The actual
`runDiff` call happens exclusively inside a GitHub Actions runner (either
the installer's own, for Path A, or `vetlock-web-scans`, for Path B) — never
inside the Worker's control plane.

## Secret inventory

Values are **never** recorded in any committed file — this table lists
only names, where each is stored, what it authorizes, and how to rotate
it. See `vetlock-app/docs/SECURITY.md`'s "Secret rotation" table for the
full step-by-step procedure on the first four; the hosted-scan secrets
follow the same shape and are documented here for completeness.

| Secret | Where stored | What it authorizes | Rotation |
|---|---|---|---|
| `GITHUB_APP_ID` | Worker secret (public value — App ID `4298344`, not actually sensitive) | Identifies which GitHub App the Worker mints JWTs as | Never rotates — it's the App's permanent identifier. Re-set only if migrating to a different App registration entirely. |
| `GITHUB_APP_WEBHOOK_SECRET` | Worker secret + GitHub App's webhook settings (Settings → General → Webhook secret) | Proves an inbound `/webhook` POST actually came from GitHub | Generate new value → set in App settings → `wrangler secret put GITHUB_APP_WEBHOOK_SECRET` (same value) → confirm via a redelivered ping. No overlap window — do both sides back-to-back. |
| `GITHUB_APP_PRIVATE_KEY` | Worker secret only; downloaded once from the App's settings (Settings → General → Private keys) | Signs the JWTs used to mint installation access tokens | Generate a new key from App settings (GitHub allows multiple active keys briefly) → `wrangler secret put GITHUB_APP_PRIVATE_KEY` → confirm a webhook mints a token successfully → revoke the old key. |
| `RESULT_INGEST_SECRET` | Worker secret + baked into the workflow template in `vetlock-app/workflows/` that users copy into their own repos | Authenticates `POST /result` from a user's own GHA runner | Generate new value → `wrangler secret put RESULT_INGEST_SECRET` → cut a new template version → existing installs must re-sync their workflow file. In-flight scans at rotation time fail their `/result` POST (accepted blast radius — check-run just stays `in_progress`, never accepts a forged result). |
| `HOSTED_SCAN_DISPATCH_TOKEN` | Worker secret only | A fine-grained GitHub PAT scoped to `contents:write` on `OJ-Uday/vetlock-web-scans` **only** — used to fire the `repository_dispatch` that starts a hosted scan | Generate a new fine-grained PAT with the same scope from github.com/settings/personal-access-tokens → `wrangler secret put HOSTED_SCAN_DISPATCH_TOKEN` → revoke the old PAT. |
| `HOSTED_SCAN_INGEST_SECRET` | Worker secret + `vetlock-web-scans` repo's GHA secret, named `VETLOCK_HOSTED_INGEST_SECRET` there (different name, same value) | Authenticates `POST /result-scan` from the `hosted-scan.yml` workflow run | Generate new value → `wrangler secret put HOSTED_SCAN_INGEST_SECRET` on the Worker → update the `VETLOCK_HOSTED_INGEST_SECRET` repo secret on `vetlock-web-scans` (Settings → Secrets and variables → Actions) → any in-flight hosted scan at rotation time fails its `/result-scan` POST (same accepted blast radius as `RESULT_INGEST_SECRET`). |

Rotate any of the above immediately on suspected leak (value pasted
somewhere public, Cloudflare account compromise, a departing collaborator
had access). The cost of rotating is a handful of in-flight scans failing
loudly — a strictly better outcome than a forged webhook, a forged result,
or a cross-tenant check-run PATCH being accepted.
