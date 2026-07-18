#!/usr/bin/env bash
# vetlock-api Fly.io deploy — one-shot script.
#
# Prereqs already satisfied on this box:
#   - flyctl installed via Homebrew (v0.4.70).
#   - colima installed (v0.9.1) but not currently running.
#   - vetlock repo at ~/personal/vetlock with packages/api/ compiled + tested.
#
# What this script does:
#   1. Runs `flyctl auth login` if not already authed (browser one-time).
#   2. Starts colima (Docker daemon) if not running — Fly builds remotely
#      but flyctl launch sometimes probes for a local daemon anyway.
#   3. Runs `flyctl launch --no-deploy` to register the app.
#   4. Runs `flyctl deploy --remote-only` to build+push to Fly's remote builder.
#   5. Curls the deployed /health.
#
# If the app name `vetlock-api` is already claimed globally, this script
# will fail at the launch step — you'll need to edit APP_NAME below or add
# a suffix.

set -euo pipefail

APP_NAME="vetlock-api"
REGION="iad"
REPO_ROOT="$HOME/personal/vetlock"

# --- sanity checks -------------------------------------------------------
if [[ ! -d "$REPO_ROOT" ]]; then
  echo "ERROR: vetlock repo not at $REPO_ROOT" >&2
  exit 1
fi
if ! command -v flyctl >/dev/null 2>&1; then
  echo "ERROR: flyctl not on PATH. Run: brew install flyctl" >&2
  exit 1
fi

cd "$REPO_ROOT"

# --- 1. Fly auth (browser, one-time) -------------------------------------
if ! flyctl auth whoami >/dev/null 2>&1; then
  echo ">>> Not logged in to Fly. Running 'flyctl auth login' (opens browser)…"
  flyctl auth login
else
  echo ">>> Already logged in to Fly as: $(flyctl auth whoami)"
fi

# --- 2. Colima (Docker daemon) — only needed for local build fallback ---
# Fly's --remote-only should skip the local daemon entirely, but some
# flyctl launch codepaths probe for it. Start colima if not running.
if command -v colima >/dev/null 2>&1; then
  if ! colima status >/dev/null 2>&1; then
    echo ">>> Starting colima (Docker daemon)…"
    colima start
  else
    echo ">>> colima already running."
  fi
fi

# --- 3. Launch (no deploy) -----------------------------------------------
# --copy-config uses the existing packages/api/fly.toml verbatim.
# --auto-confirm skips the "Would you like to…" prompts where possible;
# flyctl still may prompt for org selection if the account has multiple.
echo ""
echo ">>> flyctl launch --no-deploy…"
if flyctl status --app "$APP_NAME" >/dev/null 2>&1; then
  echo "    App '$APP_NAME' already exists on Fly — skipping launch step."
else
  flyctl launch \
    --copy-config \
    --config packages/api/fly.toml \
    --dockerfile packages/api/Dockerfile \
    --name "$APP_NAME" \
    --region "$REGION" \
    --no-deploy
fi

# --- 4. Deploy -----------------------------------------------------------
echo ""
echo ">>> flyctl deploy --remote-only…"
flyctl deploy \
  --config packages/api/fly.toml \
  --dockerfile packages/api/Dockerfile \
  --remote-only

# --- 5. Verify -----------------------------------------------------------
URL="https://${APP_NAME}.fly.dev"
echo ""
echo ">>> Deployed URL: $URL"
echo ">>> Waiting 5s for the machine to start (scale-to-zero cold start)…"
sleep 5
echo ">>> Curling /health…"
HEALTH=$(curl -sS "$URL/health" || true)
echo "    $HEALTH"

if echo "$HEALTH" | grep -q '"ok":true'; then
  echo ""
  echo "✓ API deployed + healthy at $URL"
else
  echo "" >&2
  echo "WARN: /health didn't return {\"ok\":true,...}. Machine may still be" >&2
  echo "starting up — retry in 10-30 sec:  curl -sS $URL/health" >&2
fi
