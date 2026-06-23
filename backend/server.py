"""FastAPI server: exposes the scan as JSON and serves the embeddable widget.

Endpoints:
  GET /api/scan        -> JSON scan result (cached briefly to avoid hammering)
  GET /api/health      -> liveness probe
  GET /                -> the widget (table + topology)

CORS is open so the widget can be embedded on a different origin (your website).
Tighten `allow_origins` for anything beyond local/trusted use.
"""

from __future__ import annotations

import logging
import threading
import time
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import discovery

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("server")

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"
CACHE_TTL_S = 30  # serve cached results within this window

app = FastAPI(title="Network Device Mapper", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET"],
    allow_headers=["*"],
)

# Simple time-based cache guarded by a lock so concurrent requests don't trigger
# overlapping sweeps.
# Cache keyed by target ("" == auto-detected local LAN) so switching ranges doesn't
# return a stale result for a different network.
_cache: dict[str, dict] = {}
_lock = threading.Lock()


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/api/scan")
def api_scan(force: bool = False, target: str | None = None) -> JSONResponse:
    key = (target or "").strip()
    now = time.monotonic()
    with _lock:
        entry = _cache.get(key)
        fresh = entry is not None and (now - entry["ts"]) < CACHE_TTL_S
        if not force and fresh:
            return JSONResponse(entry["data"])

        logger.info("Running scan (target=%r, force=%s)", key or "local", force)
        try:
            data = discovery.scan(key or None).to_dict()
        except ValueError as exc:  # invalid/oversized target from parse_target
            return JSONResponse({"error": str(exc)}, status_code=400)
        _cache[key] = {"ts": now, "data": data}
        # Never let the browser cache a scan result; our own TTL cache handles reuse.
        return JSONResponse(data, headers={"Cache-Control": "no-store"})


@app.get("/")
def index() -> FileResponse:
    # no-cache forces the browser to revalidate, so widget updates take effect on reload.
    return FileResponse(
        FRONTEND_DIR / "index.html", headers={"Cache-Control": "no-cache"}
    )


# Serve any other static assets (kept after routes so "/" resolves above).
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")
