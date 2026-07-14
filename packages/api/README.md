# @vetlock/api

The hosted API entrypoint for vetlock — a minimal, zero-dependency HTTP service
that runs the same before/after lockfile diff engine as the CLI (`vetlock`),
over HTTP, for anyone who'd rather POST a lockfile pair than install a CLI.

Built on `node:http` only. No express/fastify/hono: every extra runtime
dependency here is supply-chain surface for a tool whose whole job is
auditing supply-chain surface, so this package stays as small as it can.

## Endpoints

### `POST /scan`

Body (`application/json`):

```json
{
  "lockfile_before": "<lockfile text>",
  "lockfile_after": "<lockfile text>",
  "ecosystem": "npm"
}
```

- `lockfile_before` / `lockfile_after` — required strings, ≤ 500 KB each.
- `ecosystem` — optional, `"npm"` or `"pypi"`. Defaults to auto-detection from
  lockfile content (npm-family JSON/YAML vs. PyPI requirements/poetry/uv).
- Total request body is capped at 1 MB and is rejected with `413` before any
  JSON parsing happens.

Response: `202 Accepted`

```json
{ "scanId": "b3f1...", "statusUrl": "/scan/b3f1..." }
```

### `GET /scan/:scanId`

Poll for a scan's status.

- Still running → `202 Accepted`, `{ "stage": "analyzing", "elapsedMs": 1234 }`
- Done → `200 OK`, `{ "verdict": "BLOCK" | "WARN" | "INFO" | "CLEAN", "findings": [...] }`
- Unknown scanId → `404 Not Found`
- Known but past the 24h retention window → `410 Gone`

### `GET /health`

`200 OK`, `{ "ok": true, "version": "0.6.0" }`

## Running locally

```bash
pnpm --filter @vetlock/api dev     # tsx, no build step, PORT=8080 by default
```

or after building:

```bash
pnpm --filter @vetlock/api build
pnpm --filter @vetlock/api start
```

Override the port with `PORT=<n>`.

## Deploying

### Docker

```dockerfile
FROM node:20-slim
WORKDIR /app
COPY . .
RUN corepack enable && pnpm install --frozen-lockfile --filter @vetlock/api...
RUN pnpm --filter @vetlock/api build
CMD ["node", "packages/api/dist/server.js"]
```

### Fly.io

```bash
fly launch --name vetlock-api --no-deploy
fly deploy
```

`fly.toml` should set `PORT` (Fly injects `8080` by default, which matches
this service's default) and point the health check at `GET /health`.

## Rate limits

5 scans per 60 seconds per client IP, enforced in-memory. Exceeding it returns
`429 Too Many Requests` with a `Retry-After` header (seconds). The limiter
evicts stale timestamps on every request, so memory stays bounded regardless
of traffic volume — there's no unbounded per-IP history.

## Security invariants

- **NEVER-EXECUTE (ADR 0005):** this service only ever receives lockfile
  *text* over HTTP. It never runs `npm install`/`pnpm install`, never invokes
  a package's lifecycle scripts, never `require()`s or `eval`s anything
  extracted from a scanned package, and never spawns a subprocess based on
  request input. All analysis is static (AST parse, string read, byte hash)
  inside `@vetlock/core`.
- **Ephemeral, findings-only persistence (ADR 0008):** scan results (verdict +
  findings) persist for 24 hours so clients can poll; full lockfile contents
  and analyzed package tarballs are never written to durable storage by this
  service.
- **Bounded memory:** both the rate limiter and the scan-result cache evict
  on a schedule (60s window; 24h TTL respectively) so this process's memory
  footprint doesn't grow unbounded under sustained traffic.
