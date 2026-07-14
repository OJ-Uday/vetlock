# ADR 0008: Ephemeral, isolated analysis in the hosted path

**Status:** Accepted, 2026-07-13

## Context

The hosted GitHub App (ADR 0007) accepts lockfiles from customers and runs
vetlock's engine to produce findings. Every architectural choice about how
that scan executes is a customer-visible privacy commitment — because the
alternative to "we never keep your data" is "we keep some of your data," which
is exactly what regulated buyers cannot accept.

The commitment we make publicly (§2 D3 in the STARTUP packet):

> Each scan runs in a fresh sandboxed worker (container/microVM), tears down
> after, persists only findings + metadata (never full source, never
> non-submitted packages).

This ADR is that commitment stated as code-enforceable invariants, plus the
mechanisms that enforce them.

## Decision

Every hosted scan runs under FOUR invariants, each backed by a named test.

### 1. Ephemeral compute — new worker per scan, torn down after

Concretely:
- Each scan gets a fresh container (or Firecracker microVM once we prove it's
  worth the complexity — container first, microVM as a P8 upgrade).
- The worker's writable filesystem is a tmpfs / scratch disk that is
  destroyed at container exit. No mounted host volume, no shared cache.
- The scheduler enforces one-scan-per-worker: workers are marked "dirty" as
  soon as they start a scan and never re-used.

Invariant test: **`ephemeral-teardown.test`** — spins up a real (or emulated)
worker, runs a scan whose lockfile references synthetic package A, then
inspects the worker's filesystem and process list *after* teardown. Assert:
zero traces of A remain (no cached tarball, no extracted files, no snapshot
JSON that mentions A's integrity). Assert: the worker container was deleted
(via the runtime's ID no longer being addressable).

### 2. Ephemeral persistence — findings + metadata only

We persist to durable storage (per ADR D4 — ClickHouse for findings,
Postgres for org/user/config/billing):
- Findings (as JSON — the same shape `--json` outputs).
- Scan metadata: org_id, repo_id (opaque), scan_id, PR number, timestamp,
  vetlock version, duration_ms, verdict summary.
- Config-decision metadata (which detectors were enabled, escalation rules).

We DO NOT persist:
- Full lockfile content (only a content hash for dedup).
- Full source of any analyzed package (only the finding's `evidence` snippet,
  which is capped at 240 chars per the schema in `packages/core/src/finding.ts`).
- Any package that was not in the submitted lockfile pair.
- Any decrypted secret, token, or environment variable.

Invariant test: **`persistence-schema.test`** — asserts the Postgres schema
and ClickHouse schema contain no column that could hold full source, full
lockfile, or non-submitted package data. New columns require an ADR update.

Retention: findings live 90 days by default (configurable per plan); after
that they're aggregated into org-level rollups and the raw rows are dropped.
Full deletion on org-delete or user-request (a `POST /orgs/:id/delete-data`
endpoint that's part of the ToS).

### 3. Tenant isolation

Every request through the hosted API carries an `org_id` derived from the App
installation. All queries are `WHERE org_id = ?`; there is no admin surface
that lets one tenant see another's data.

Invariant test: **`tenant-isolation.test`** — spins two orgs A and B, submits
a scan from each, then asserts (a) A's API queries can only see A's findings,
(b) any deliberate attempt (e.g. injecting a different `org_id` into a query
via a bogus header) fails at the middleware layer with 403. Every route in
the API surface must have this test.

### 4. NEVER-EXECUTE still applies server-side

The hosted worker runs the same OSS engine. ADR 0005's canary
(`never-execute-canary.test`) runs in the worker image's build pipeline.
Additionally:

Invariant test: **`never-execute-serverside.test`** — a hostile fixture is
submitted to a real (or emulated) worker; the worker's syscall log (via
sysdig / seccomp audit / equivalent) is scanned for any `execve` other than
the vetlock binary and its declared subprocesses (node, tar for extraction).
Any other exec = test fails.

## Enforcement

- Each invariant has a named test that runs on every deploy of the
  `vetlock-app` repo.
- The worker's Dockerfile is committed and reviewable; a public checksum is
  published so external auditors can verify the running image matches.
- The privacy architecture is documented publicly at
  `docs/PRIVACY-ARCHITECTURE.md` on the `vetlock-app` repo (the ADR here is
  the internal spec; the public doc restates it in customer-facing terms).
- Security disclosures go through `SECURITY.md` (already exists in the OSS
  repo; add a hosted-scope equivalent to `vetlock-app`).

## Rationale

- **Regulated buyers evaluate this exact question first.** Pharma, finance,
  and gov security teams ask "what happens to our data when it enters your
  system?" as their opening question. A short, technical, testable answer
  with a public architecture doc closes deals no marketing copy can.
- **The privacy promise is the moat.** Losing one incident (e.g. a leak of
  customer dep data) permanently destroys the trust proposition; the tests
  make that failure mode far less likely.
- **Ephemeral compute is cheap now.** Firecracker microVMs are ~125ms cold
  starts; containers on a warm host are ~50ms. The tear-down cost is real
  but far smaller than the marketing/legal cost of a persistent shared cache.

## Consequences

- We accept slightly higher per-scan cost (fresh worker vs. shared cache)
  in exchange for the guarantee. At v1 scale this is not a business concern;
  at 10k+ scans/hour we may need to re-examine (and can — the invariants
  above don't preclude per-tenant caches, only cross-tenant sharing).
- The worker image must be trivially reproducible: Dockerfile committed,
  base image pinned by digest, no ambient credentials, no side-channel
  package installs at runtime. This is a genuine engineering constraint —
  documented in `vetlock-app/docs/WORKER-IMAGE.md` when P5 starts.
- Support debug requests ("my scan reported X, please help") can only ever
  reference the scan_id + findings JSON. Support engineers do not have a
  path to inspect a customer's lockfile. If a customer needs deeper help,
  they send us the lockfile via an out-of-band support channel with their
  explicit consent — and even that flow is logged, TTL'd, and scoped to
  the individual ticket.

## Non-goals

- No "shared analysis cache" at v1 (even within a tenant — we can add
  per-tenant caching later; cross-tenant is banned by construction).
- No log shipping to a third-party observability vendor that could see
  finding contents. Metrics (durations, verdict distributions) are fine;
  finding bodies stay in our storage.
- No opt-in "share your findings to improve the product" toggle at v1.
  That's a real feature (the false-positive-report loop specifically), but
  it needs an explicit consent UI, clear data flow, and its own ADR. Do
  not launch with a hidden data-mining default.
