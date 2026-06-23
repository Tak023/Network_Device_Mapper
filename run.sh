#!/usr/bin/env bash
# Bootstrap a venv, install deps, and start the scanner + widget server.
set -euo pipefail
cd "$(dirname "$0")"

PYTHON="${PYTHON:-python3}"
PORT="${PORT:-8000}"

if [ ! -d ".venv" ]; then
  echo "→ Creating virtual environment…"
  "$PYTHON" -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate

echo "→ Installing dependencies…"
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt

echo "→ Starting on http://127.0.0.1:${PORT}  (Ctrl-C to stop)"
exec uvicorn backend.server:app --host 0.0.0.0 --port "$PORT"
