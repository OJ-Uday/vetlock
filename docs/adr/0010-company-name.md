# ADR 0010: Company Name Posture

**Status:** Accepted, 2026-07-13

## Context

vetlock is transitioning from a personal OSS project to a shippable product with
a potential commercial layer (§PACKET-VETLOCK-STARTUP.md). Before spending on a
domain, forming an entity, or applying for a trademark, we need to lock the name.
This ADR records the availability audit and the resulting decision.

## Availability audit (verified 2026-07-13)

**npm (via a public-npm-proxied registry — Artifactory serves public bytes):**

| Name              | Status                              |
|-------------------|-------------------------------------|
| `vetlock`         | 404 · **available**                 |
| `vetlock-cli`     | 404 · **available**                 |
| `vetlock-scanner` | 404 · **available**                 |
| `vetlock-analyzer`| 404 · **available**                 |
| `vetlock-oss`     | 404 · **available**                 |

**GitHub org:**

| Org           | Status                |
|---------------|-----------------------|
| `vetlock`     | 404 · **available**   |
| `vetlock-dev` | 404 · **available**   |
| `vetlock-hq`  | 404 · **available**   |
| `vetlock-io`  | 404 · **available**   |

**Domain (DNS-only screen; final confirmation at a registrar):**

| Domain         | Status                                    |
|----------------|-------------------------------------------|
| `vetlock.dev`  | No SOA record → **likely available**      |
| `vetlock.io`   | No SOA record → **likely available**      |
| `vetlock.app`  | No SOA record → **likely available**      |
| `vetlock.sh`   | No SOA record → **likely available**      |

## Decision

- **Name:** `vetlock` (kept — it's what the tool ships as today, and it's fully clear).
- **npm:** publish under the bare `vetlock` package name. Scoped names are reserved
  as a fallback (`@vetlock/core`, `@vetlock/detectors`, `@vetlock/cli` are already
  in use inside the workspace).
- **GitHub org (commercial layer):** `vetlock-dev` when we form the entity. The
  OSS repo stays at `OJ-Uday/vetlock` until incorporation; transferring the OSS
  repo INTO the org at that point is a one-command move (`gh repo transfer …`)
  and preserves stars/issues/forks.
- **Primary domain:** `vetlock.dev`. Reasoning:
  - `.dev` is on the HSTS preload list → HTTPS is compulsory, which matches the
    security-tool ethos.
  - `.io` is more crowded and typosquatted; `.dev` positions us with the
    developer-tool crowd (Deno, Bun, Vitest, Vite all use `.dev`).
- **Secondary domains to consider grabbing defensively:** `vetlock.io`,
  `vetlock.sh`, `vetlock.app`. Cheap; prevents mimic-typosquat sites. Skip if
  budget is tight — the primary is enough at launch.

## Trademark posture

- The word mark `VETLOCK` (International Class 42 — "computer software
  for detecting supply-chain vulnerabilities") is worth a USPTO/EUIPO search
  before any public launch that describes vetlock as a product. That search is
  a launch-blocking gate in `§9` of the STARTUP packet and is **not** in scope
  for this ADR — this ADR only certifies that the surface (npm, GH org, DNS) is
  clear enough that the name IS a fair candidate.
- **Do not** file a mark before P9 (company-launch). Marks require use-in-
  commerce; filing a $250 intent-to-use application post-launch, once the
  hosted product has real users, is the right timing.

## Rationale

- Existing OSS repo, npm packages inside the monorepo, GitHub Action listing,
  the portfolio site's live scanner, and the red-team documentation all already
  say "vetlock". Renaming late would waste every artifact of the trust story
  (the red-team narrative is the moat and it's authored under this name).
- The name is short, phonetic, memorable, and semantically accurate ("vet" +
  "lock[file]"). No brand debt to work off.
- All the launch surfaces are available in one aligned bundle — the highest-
  leverage moment to lock a name is when the surfaces still line up.

## Consequences

- Purchase `vetlock.dev` before P9 (and ideally before any public writeup
  linking to the site). Registrar cost ≈ ₹1,200/year (~$15).
- Create the GitHub org `vetlock-dev` at incorporation. Keep OSS at
  `OJ-Uday/vetlock` until then — pre-incorporation, a personal-repo posture
  matches the "personal IP, built off-hours on personal hardware" story
  required by the legal gate.
- When we publish v0.4.0 to npm, publish as `vetlock` (bare name).
- Reserve `@vetlock/*` scope on npm at that time (npm scopes are free and lock
  the whole namespace against typosquats).
