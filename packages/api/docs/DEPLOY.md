# DEPLOY — @vetlock/api

The hosted-scan API (ADR 0008 — ephemeral, isolated analysis). This document
covers the three ways to run it:

1. **Local dev** — `pnpm dev` against `packages/api/src/server.ts` via tsx.
2. **Local Docker** — the same multi-stage Dockerfile Fly uses. Good for
   reproducing production behavior on your laptop before pushing.
3. **Fly.io** — scale-to-zero on the free tier. $0/mo at launch.

---

## 1. Local dev

```bash
# From the repo root:
pnpm install
pnpm --filter @vetlock/api build       # first-time only; tsx dev-mode runs from src/
pnpm --filter @vetlock/api dev         # listens on http://localhost:8080
```

Smoke-test:

```bash
curl -s http://localhost:8080/health
# → {"ok":true,"version":"0.6.0"}

# Submit a scan (npm ecosystem, minimal lockfiles):
curl -s -X POST http://localhost:8080/scan \
     -H 'Content-Type: application/json' \
     -d '{"lockfile_before":"{\"name\":\"x\",\"version\":\"1\",\"lockfileVersion\":3,\"packages\":{\"\":{}}}","lockfile_after":"{\"name\":\"x\",\"version\":\"1\",\"lockfileVersion\":3,\"packages\":{\"\":{}}}"}'
# → {"scanId":"...","statusUrl":"/scan/..."}

curl -s http://localhost:8080/scan/<scanId>
# → {"stage":"analyzing","elapsedMs":234}  or
#   {"verdict":"CLEAN","findings":[],"elapsedMs":1120}  once done
```

---

## 2. Local Docker

The Dockerfile expects the **repo root** as build context (it needs
`pnpm-workspace.yaml` and every package's `package.json` to resolve
`workspace:*`).

```bash
# From the repo root:
docker build -f packages/api/Dockerfile -t vetlock-api .

# Run — expose 8080, drop all capabilities, read-only root FS, tmpfs on
# /tmp (which is where per-scan sandbox dirs live). This mirrors what
# Fly.io + fly.toml enforces at deploy time.
docker run --rm -p 8080:8080 \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=256m \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  vetlock-api
```

Runtime invariants tested at startup:

- Runs as UID 1000 (`node`), not root.
- No shell in the entrypoint (`CMD ["node", ...]`).
- `/health` responds within 10s (HEALTHCHECK grace period).

---

## 3. Fly.io deployment

### First-time setup

```bash
# One-time: install flyctl and log in.
brew install flyctl        # or the official install script from fly.io
flyctl auth login

# One-time per app: register the app name. The 'launch' command reads
# fly.toml + Dockerfile from packages/api/ and prompts for the region.
flyctl launch \
  --copy-config \
  --config packages/api/fly.toml \
  --dockerfile packages/api/Dockerfile \
  --name vetlock-api \
  --no-deploy
```

Adjust `app = "vetlock-api"` in `fly.toml` if that name is already taken
on Fly's global namespace.

### Subsequent deploys

```bash
flyctl deploy \
  --config packages/api/fly.toml \
  --dockerfile packages/api/Dockerfile
```

Fly builds the image on their remote builder (using our Dockerfile) and
rolls the new machines in one at a time.

### Verify

```bash
flyctl status --config packages/api/fly.toml
# Wait for machines: STATE=started

curl -s https://vetlock-api.fly.dev/health
# → {"ok":true,"version":"0.6.0"}
```

---

## Cost curve

Fly.io pricing snapshot (approximate — check
https://fly.io/docs/about/pricing for current):

| Load | Machines active | Compute cost/mo | Total cost/mo |
|---|---|---|---|
| 0 scans/day (idle) | 0 | $0 | **$0** — free tier |
| 10 scans/day @ 5s each | 0 → occasional wake | negligible | **$0** — free tier |
| 100 scans/day @ 5s each | ~1 briefly per hour | ~$1 | **$0-$1** — free tier still covers |
| 1000 scans/day @ 5s each | 1 always-on | ~$5 | **~$5** — free tier exhausted, small VM billed |
| 10k scans/day | 2-3 machines autoscaling | ~$20 | **~$20-30** |
| 100k scans/day | 10+ machines, may need bigger VM class | ~$150 | **enterprise tier** — offer paid plan |

The free tier gives 3 shared-cpu-1x machines running 24/7 (~$5/mo of
compute) for free. `min_machines_running = 0` means we consume $0 of that
allowance while idle.

---

## Environment variables

| Var | Default | Purpose |
|---|---|---|
| `PORT` | 8080 | HTTP listen port |
| `NODE_ENV` | production | Standard; enables prod-mode paths in transitive deps |
| `MAX_CONCURRENT_SCANS` | (default in server.ts) | Cap on in-flight sandbox subprocesses |
| `SCAN_TTL_MS` | 86400000 (24h) | How long completed scan results are queryable |
| `RATE_LIMIT_PER_MINUTE` | 5 | Per-IP soft cap on POST /scan |
| `SCAN_TIMEOUT_MS` | 60000 | Wall-clock timeout for the sandbox subprocess |

Set on Fly with:

```bash
flyctl secrets set MAX_CONCURRENT_SCANS=8 --config packages/api/fly.toml
```

(Use `secrets` for values you don't want in the repo; use `[env]` in
fly.toml for non-sensitive defaults.)

---

## Security invariants

See `packages/api/src/sandbox.ts` for the full argument. Summary:

- **NEVER-EXECUTE (ADR 0005):** no scan artifact (tarball, wheel, sdist)
  is executed. Vetlock's static analyzer parses lockfiles, fetches
  tarballs, extracts them as files, and text-scans/AST-walks them. Nothing
  in the API layer changes that.
- **Sandbox subprocess per scan (ADR 0008):** every scan runs in a fresh
  Node subprocess spawned with `spawn(process.execPath, ...)`, empty env,
  no shell, wall-clock timeout enforced by the parent (SIGKILL to the
  whole process group).
- **Ephemeral filesystem:** each scan's temp dir is `mkdtemp`'d under
  `os.tmpdir()` and `rm -rf`'d in a `finally` block. No caller can leave
  state on disk.
- **No PII in logs:** structured JSON logs on stderr include only
  `{ ts, level, msg, scanId, verdict, findings_count }`. Never lockfile
  contents.
- **Rate limit:** per-IP, in-memory Map keyed on the request's remote
  address. On Fly the remote address is Fly's edge, so add `Fly-Client-IP`
  header parsing when scaling past single-region.

---

## Cleanup

```bash
# Tear down a Fly app entirely:
flyctl apps destroy vetlock-api

# Locally remove the Docker image + any built layers:
docker rmi vetlock-api
docker builder prune -f
```
