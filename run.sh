#!/usr/bin/env bash
# Bootstrap a venv, install deps, and start the scanner + widget server.
set -euo pipefail
cd "$(dirname "$0")"

PYTHON="${PYTHON:-python3}"
PORT="${PORT:-8000}"
# Loopback by default: nothing on the LAN (or beyond) can reach the API unless you
# opt in with HOST=0.0.0.0 — ideally alongside NDM_API_TOKEN (see .env.example).
HOST="${HOST:-127.0.0.1}"
# Set RELOAD=1 for development (auto-restart on code edits).
RELOAD="${RELOAD:-}"

# Load UniFi (and any other) settings from a local .env if present.
if [ -f .env ]; then
  echo "→ Loading .env"
  set -a; # shellcheck disable=SC1091
  source .env; set +a
fi

if [ ! -d ".venv" ]; then
  echo "→ Creating virtual environment…"
  "$PYTHON" -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate

echo "→ Installing dependencies…"
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt

echo "→ Starting on http://${HOST}:${PORT}  (Ctrl-C to stop)"
exec uvicorn backend.server:app --host "$HOST" --port "$PORT" ${RELOAD:+--reload}
