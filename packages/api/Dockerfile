# syntax=docker/dockerfile:1.6
#
# vetlock-api — hosted scan service (ADR 0008)
#
# Multi-stage:
#   1. builder — pulls the whole monorepo, installs with the workspace's
#      pinned pnpm, runs the recursive TypeScript build for the three
#      packages @vetlock/api transitively depends on (core, detectors, api).
#   2. runtime — copies only the compiled dist/ + production deps into a
#      slim node:20-alpine image. Runs as the built-in `node` non-root
#      user. Exposes 8080. HEALTHCHECK hits /health.
#
# Build context is the REPO ROOT (not packages/api/), because we need the
# workspace and every package's package.json to resolve `workspace:*`
# links. Build with:  docker build -f packages/api/Dockerfile -t vetlock-api .
#
# Runtime invariants:
#   - Non-root user (`node`, uid 1000).
#   - Read-only root FS is enforced at deploy-time via `docker run --read-only`
#     or fly.toml; the app writes only to /tmp (which is a tmpfs mount).
#   - No shell in ENTRYPOINT/CMD, so a shell-injection via env vars is
#     structurally impossible.
#   - --experimental-permission is NOT enabled here; see packages/api/src/
#     sandbox.ts for why (Node's permission model is still experimental as
#     of Node 20/22 and its interaction with resolve paths is fragile).
#     Sandboxing is enforced instead by (a) per-scan subprocess with
#     process-group SIGKILL on timeout, (b) empty env passed to the
#     subprocess, (c) mkdtemp'd sandbox dir removed unconditionally.
# =====================================================================
FROM node:20-alpine AS builder

# corepack ships with the node:20 image; enable it so `pnpm` resolves to
# the version this workspace pins in package.json's packageManager field.
RUN corepack enable

WORKDIR /app

# Copy the pnpm workspace descriptor + all package.json files first so
# `pnpm install` layer caches when only source changes. This is the
# standard pnpm-in-Docker pattern.
COPY pnpm-workspace.yaml package.json pnpm-lock.yaml ./
COPY packages/core/package.json ./packages/core/
COPY packages/detectors/package.json ./packages/detectors/
COPY packages/cli/package.json ./packages/cli/
COPY packages/api/package.json ./packages/api/

# Install ALL workspace deps (dev + prod) — needed to build TypeScript.
RUN pnpm install --frozen-lockfile

# Now copy source. Doing this AFTER install means changes to source don't
# re-invalidate the install layer.
COPY tsconfig.base.json ./
COPY packages/core ./packages/core
COPY packages/detectors ./packages/detectors
COPY packages/api ./packages/api
# scripts/copy-demo-fixture.js lives at the CLI's root but core+detectors+
# api don't need it. If we ever wire the CLI into the runtime image, adjust.

# Build the three packages the API needs (recursive build handles order
# via workspace deps: core → detectors → api).
RUN pnpm --filter @vetlock/core --filter @vetlock/detectors --filter @vetlock/api build

# Prune to production-only deps for the runtime copy. This drops dev
# dependencies (typescript, vitest, tsx, @types/*).
RUN pnpm --filter @vetlock/api deploy --prod --legacy /out


# =====================================================================
FROM node:20-alpine AS runtime

# Small, well-known utilities for HEALTHCHECK. Alpine's default doesn't
# ship wget; busybox does, so we use its wget applet — no extra install.
# (`wget` is a busybox symlink on the base node:20-alpine image.)
LABEL org.opencontainers.image.title="vetlock-api"
LABEL org.opencontainers.image.description="vetlock hosted scan API — behavioral supply-chain diff as a service (ADR 0008)"
LABEL org.opencontainers.image.source="https://github.com/OJ-Uday/vetlock"
LABEL org.opencontainers.image.licenses="Apache-2.0"

WORKDIR /app

# Copy the pruned dist tree. `pnpm deploy --legacy` builds a self-contained
# tree at /out with node_modules already hoisted for direct `node` execution.
COPY --from=builder --chown=node:node /out ./

USER node
EXPOSE 8080

# Structural non-shell CMD — argv is passed to execve() directly, so any
# env-var expansion happens in node, not in a shell. NODE_ENV=production
# is set for downstream libs; the api itself doesn't branch on it today
# but many transitive libs do.
ENV NODE_ENV=production
ENV PORT=8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget --spider -q http://127.0.0.1:8080/health || exit 1

CMD ["node", "dist/server.js"]
