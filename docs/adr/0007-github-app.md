# ADR 0007: GitHub App as the primary hosted-tier entry point

**Status:** Accepted, 2026-07-13

## Context

The OSS core ships as a CLI + a per-repo GitHub Action. The Action is powerful
(SARIF upload, sticky PR comment, `--fail-on` gating) but each repo needs a
YAML file, each org needs a fanout process, and cross-repo aggregation (per-org
"total findings blocked this week" — the north-star metric per §8) is
impossible from a per-repo posture.

The hosted commercial tier needs a *dramatically* lower-friction entry point.
Two candidates:

| Option | Cost to install per repo | Cross-repo | Config |
|---|---|---|---|
| Per-repo GitHub Action + hosted API | one YAML per repo | Manual aggregation | Per-repo |
| GitHub App | Zero (org install covers all repos) | Native | Org-level |

## Decision

**GitHub App is the primary hosted-tier entry point.** Users install one App
on their org; every repo is automatically covered; config is org-level with
per-repo overrides.

### Concrete surface

The App name is `vetlock` (App slug matches; requires GitHub Marketplace publish).
It requires the **minimum viable set** of permissions and events:

| Permission              | Access       | Why                                       |
|-------------------------|--------------|-------------------------------------------|
| `contents`              | Read         | Fetch `package-lock.json` / `yarn.lock` / `pnpm-lock.yaml` from the PR head+base. That is ALL — never any other repo content. |
| `pull_requests`         | Write        | Post sticky comment + PR review comments. |
| `checks`                | Write        | Post the vetlock Check on the PR (green/red/neutral).      |
| `metadata`              | Read         | Mandatory for any App; can't be removed.  |

**Events:**
- `pull_request` (opened, synchronize, reopened)
- `installation` (created, deleted)
- `installation_repositories` (added, removed)

**Nothing else.** In particular, **no**:
- `contents:write` (we never push commits, never open PRs)
- `actions` (we don't dispatch workflows on the user's repo)
- `secrets` (we never read or set secrets)
- `code` full-content webhooks (we only fetch lockfiles; the webhook payload
  only tells us "there's a PR"; the fetch is scoped)

### Flow per PR

1. `pull_request` webhook fires.
2. App verifies the webhook signature (`X-Hub-Signature-256`).
3. App reads `package-lock.json` (or the yarn/pnpm equivalent) from BOTH the
   PR head SHA and the base SHA via the Contents API — nothing else.
4. Payload posted to the hosted queue; scan runs in an ephemeral worker per
   ADR 0008.
5. Findings written back as a Check + sticky comment.

### What the App does NOT do

- Does not run `npm install` — NEVER-EXECUTE holds (ADR 0005).
- Does not fetch or inspect any repo file other than the lockfile(s).
- Does not read or store the PR title/description/comments (only the
  webhook-provided PR number is used, for the check-run response).
- Does not phone the OSS `npx vetlock` code path anywhere — the two paths are
  entirely independent (per ADR 0006 D5).

## Enforcement

- **`app-permissions-minimal.test`**: asserts the App manifest requests
  exactly the permissions/events listed above, and no more. A CI job on the
  `vetlock-app` repo reads `.github/app-manifest.json` and diffs against a
  pinned expected file; any expansion of scope requires an ADR update AND a
  test-fixture update.
- **`app-webhook-pr-check.test`**: integration test that spins up a fake
  GitHub API (via nock or a local mock), posts a synthetic `pull_request`
  event, and asserts (a) the Check API was called with the correct SHA,
  (b) findings came from calling `runAll` in the OSS core (same code path
  as the CLI), (c) NO other GitHub API endpoints were hit.

## Rationale

- **PLG unlock**: one org install vs. N-repo YAML rollouts is the difference
  between "someone might try it" and "the security team ships it to every
  repo tomorrow." Real customers repeatedly cite the per-repo YAML overhead
  as the reason they don't turn on scanners they otherwise like.
- **Native cross-repo aggregation**: the north-star metric
  ("findings-blocked-per-week per active install") needs a hosted layer that
  sees every scan across an org. A GitHub App is the only zero-config way to
  get that.
- **Least-privilege scopes are a genuine differentiator**: "we only read
  lockfiles, nothing else in your repo" is a headline the privacy-first
  moat rests on. This ADR makes that promise enforceable.

## Consequences

- The Marketplace listing IS the marketing surface: security-team buyers
  look at "what permissions does this App want?" as a first-line evaluation
  criterion. We win that eval by asking for the smallest set that works.
- Any future feature that needs a bigger scope (e.g. auto-suggested fix PRs)
  triggers a review of this ADR — it's not automatically OK. The default
  answer is "keep the App minimal; expand via a separate opt-in App if
  needed."
- The Marketplace publish requires: verified GitHub organization, screenshots,
  privacy policy, ToS, listing text, category selection. This is a P9
  launch-blocker item, tracked in `LAUNCH-CHECKLIST.md`.
- Free tier: unlimited scans on public repos, N scans/month on private repos.
  Enforced by the queue layer (a `plan: 'free'` scan gets rate-limited if
  monthly quota exceeded, with a friendly "upgrade for unlimited private-repo
  scans" comment). Details in the pricing ADR (future — ADR 0014, deferred
  until we have data from real users).

## Non-goals

- No GitHub OAuth-only "sign in with GitHub" flow instead of an App. That
  route needs a per-user token or a machine user, both of which require more
  scopes than an App for the same job.
- No cross-provider (GitLab, Bitbucket) launch in v1. GitHub is 90%+ of the
  addressable market; we ship there first. GitLab/Bitbucket App equivalents
  are noted in the STARTUP packet's post-launch roadmap.
