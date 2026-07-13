#!/usr/bin/env bash
# Build the standalone desktop app with PyInstaller.
#   macOS   -> dist/Network Device Mapper.app   (drag to /Applications)
#   Windows -> dist/Network Device Mapper/Network Device Mapper.exe
#   Linux   -> dist/Network Device Mapper/Network Device Mapper
set -euo pipefail
cd "$(dirname "$0")"

PYTHON="${PYTHON:-python3}"

if [ ! -d ".venv" ]; then
  echo "→ Creating virtual environment…"
  "$PYTHON" -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate

echo "→ Installing dependencies…"
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt -r requirements-desktop.txt

# PyInstaller's --add-data separator is ";" on Windows, ":" elsewhere.
SEP=":"
case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) SEP=";";; esac

# App icon: generated from assets/icon.png (1024x1024) when present.
# (plain string, not an array: macOS bash 3.2 + `set -u` rejects empty arrays)
ICON_ARGS=""
if [ -f assets/icon.png ] && [ "$(uname -s)" = "Darwin" ]; then
  if [ ! -f assets/icon.icns ] || [ assets/icon.png -nt assets/icon.icns ]; then
    echo "→ Generating assets/icon.icns from assets/icon.png…"
    rm -rf assets/icon.iconset && mkdir -p assets/icon.iconset
    for size in 16 32 128 256 512; do
      sips -z "$size" "$size" assets/icon.png --out "assets/icon.iconset/icon_${size}x${size}.png" >/dev/null
      sips -z "$((size*2))" "$((size*2))" assets/icon.png --out "assets/icon.iconset/icon_${size}x${size}@2x.png" >/dev/null
    done
    iconutil -c icns assets/icon.iconset -o assets/icon.icns
    rm -rf assets/icon.iconset
  fi
  ICON_ARGS="--icon assets/icon.icns"
fi

echo "→ Building with PyInstaller…"
# shellcheck disable=SC2086  # ICON_ARGS is intentionally word-split
pyinstaller --noconfirm --clean --windowed --name "Network Device Mapper" \
  $ICON_ARGS \
  --add-data "frontend${SEP}frontend" \
  --hidden-import uvicorn.logging \
  --hidden-import uvicorn.loops.auto \
  --hidden-import uvicorn.protocols.http.auto \
  --hidden-import uvicorn.protocols.http.h11_impl \
  --hidden-import uvicorn.protocols.websockets.auto \
  --hidden-import uvicorn.lifespan.on \
  --hidden-import uvicorn.lifespan.off \
  desktop.py

echo
echo "→ Done. Output in dist/"
ls -d dist/*
