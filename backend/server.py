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
_cache: dict = {"ts": 0.0, "data": None}
_lock = threading.Lock()


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/api/scan")
def api_scan(force: bool = False) -> JSONResponse:
    now = time.monotonic()
    with _lock:
        fresh = _cache["data"] is not None and (now - _cache["ts"]) < CACHE_TTL_S
        if force or not fresh:
            logger.info("Running network scan (force=%s)", force)
            _cache["data"] = discovery.scan().to_dict()
            _cache["ts"] = now
        return JSONResponse(_cache["data"])


@app.get("/")
def index() -> FileResponse:
    return FileResponse(FRONTEND_DIR / "index.html")


# Serve any other static assets (kept after routes so "/" resolves above).
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")
