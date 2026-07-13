"""FastAPI server: exposes the scan as JSON and serves the embeddable widget.

Endpoints:
  GET /api/scan         -> JSON scan result (cached briefly to avoid hammering)
  GET /api/scan/stream  -> same scan as Server-Sent Events with live progress
  GET /api/health       -> liveness probe
  GET /                 -> the widget (table + topology)

Security posture (all opt-in via env / .env):
  NDM_API_TOKEN        when set, /api/scan* require it (X-API-Token header or
                       ?token= query param)
  NDM_CORS_ORIGINS     comma-separated origins allowed to call the API cross-origin
                       (default: none — same-origin only; "*" restores open CORS)
  NDM_ALLOWED_TARGETS  comma-separated CIDRs the ?target= parameter may scan
                       (default: unrestricted). The auto-detected local LAN is
                       always allowed.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import queue
import secrets
import sys
import threading
import time
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import discovery, history, wol
from .topology import load_dotenv

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("server")

load_dotenv()  # NDM_* settings work from .env even without run.sh

# In a PyInstaller bundle the frontend is unpacked under sys._MEIPASS.
_BUNDLE_ROOT = getattr(sys, "_MEIPASS", None)
FRONTEND_DIR = (
    Path(_BUNDLE_ROOT) / "frontend"
    if _BUNDLE_ROOT
    else Path(__file__).resolve().parent.parent / "frontend"
)
CACHE_TTL_S = 30      # serve cached results within this window
MAX_CACHE_ENTRIES = 32  # cap growth from many distinct ?target= values

app = FastAPI(title="Network Device Mapper", version="1.1.0")


def _cors_origins() -> list[str]:
    raw = os.environ.get("NDM_CORS_ORIGINS", "").strip()
    if raw == "*":
        return ["*"]
    return [o.strip() for o in raw.split(",") if o.strip()]


# Same-origin use (the served widget) needs no CORS at all; cross-origin embedding
# is opt-in so a random website can't read scan results out of the local API.
if _cors_origins():
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins(),
        allow_methods=["GET", "POST"],
        allow_headers=["X-API-Token", "Content-Type"],
    )


def _require_token(request: Request) -> None:
    """401 unless the request carries NDM_API_TOKEN (no-op when unset)."""
    token = os.environ.get("NDM_API_TOKEN", "").strip()
    if not token:
        return
    supplied = request.headers.get("x-api-token") or request.query_params.get("token") or ""
    if not secrets.compare_digest(supplied, token):
        raise HTTPException(status_code=401, detail="Missing or invalid API token.")


def _validate_target(key: str) -> None:
    """Reject malformed targets and, if NDM_ALLOWED_TARGETS is set, out-of-scope ones.

    Raises ValueError with a user-facing message (mapped to HTTP 400 by callers).
    """
    if not key:
        return  # auto-detected local LAN is always allowed
    hosts, _net = discovery.parse_target(key)  # ValueError on malformed/oversized
    raw = os.environ.get("NDM_ALLOWED_TARGETS", "").strip()
    if not raw:
        return
    allowed = []
    for spec in raw.split(","):
        spec = spec.strip()
        if not spec:
            continue
        try:
            allowed.append(ipaddress.ip_network(spec, strict=False))
        except ValueError:
            logger.warning("Ignoring invalid NDM_ALLOWED_TARGETS entry %r", spec)
    if not allowed:
        return
    for host in hosts:
        addr = ipaddress.ip_address(host)
        if not any(addr in net for net in allowed):
            raise ValueError(
                f"Target {key} is outside the allowed scan ranges ({raw})."
            )


# ---------------------------------------------------------------------------
# Cache: per-target TTL entries with per-target scan locks, so a slow sweep of
# one range never blocks cached reads (or scans) of another.
# ---------------------------------------------------------------------------

_cache: dict[str, dict] = {}
_scan_locks: dict[str, threading.Lock] = {}
_meta_lock = threading.Lock()  # guards the two dicts above, never held during a scan


def _lock_for(key: str) -> threading.Lock:
    with _meta_lock:
        # Opportunistically drop idle locks for evicted cache keys.
        if len(_scan_locks) > 2 * MAX_CACHE_ENTRIES:
            for k in list(_scan_locks):
                if k != key and k not in _cache and not _scan_locks[k].locked():
                    del _scan_locks[k]
        return _scan_locks.setdefault(key, threading.Lock())


def _cached(key: str, newer_than: float | None = None) -> dict | None:
    with _meta_lock:
        entry = _cache.get(key)
    if entry is None:
        return None
    fresh = (time.monotonic() - entry["ts"]) < CACHE_TTL_S
    if newer_than is not None:  # "force" only accepts results produced after request start
        return entry["data"] if entry["ts"] >= newer_than else None
    return entry["data"] if fresh else None


def _store(key: str, data: dict) -> None:
    with _meta_lock:
        _cache[key] = {"ts": time.monotonic(), "data": data}
        while len(_cache) > MAX_CACHE_ENTRIES:
            del _cache[min(_cache, key=lambda k: _cache[k]["ts"])]


def _run_scan(key: str, force: bool, progress=None) -> dict:
    """Return a scan result for `key`, via cache or a fresh (locked) sweep."""
    started = time.monotonic()
    if not force:
        data = _cached(key)
        if data is not None:
            return data
    with _lock_for(key):
        # Re-check: another request may have scanned while we waited on the lock.
        data = _cached(key, newer_than=started if force else None)
        if data is not None:
            return data
        logger.info("Running scan (target=%r, force=%s)", key or "local", force)
        data = discovery.scan(key or None, progress).to_dict()
        history.annotate(data)  # first_seen / is_new / missing_devices
        _store(key, data)
        return data


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/api/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/api/scan")
def api_scan(
    force: bool = False,
    target: str | None = None,
    _auth: None = Depends(_require_token),
) -> JSONResponse:
    key = (target or "").strip()
    try:
        _validate_target(key)
        data = _run_scan(key, force)
    except ValueError as exc:  # invalid/oversized/disallowed target
        return JSONResponse({"error": str(exc)}, status_code=400)
    # Never let the browser cache a scan result; our own TTL cache handles reuse.
    return JSONResponse(data, headers={"Cache-Control": "no-store"})


@app.get("/api/scan/stream")
def api_scan_stream(
    force: bool = False,
    target: str | None = None,
    _auth: None = Depends(_require_token),
) -> StreamingResponse:
    """Same scan as /api/scan, streamed as SSE with live progress events.

    Events (one JSON object per `data:` line):
      {"event": "progress", "phase": "sweep|enrich|topology", "done": n, "total": n}
      {"event": "done", "result": {...scan result...}}
      {"event": "error", "message": "..."}
    """
    key = (target or "").strip()
    try:
        _validate_target(key)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    events: queue.Queue = queue.Queue()

    def progress(phase, done, total):
        events.put({"event": "progress", "phase": phase, "done": done, "total": total})

    def work():
        try:
            data = _run_scan(key, force, progress)
            events.put({"event": "done", "result": data})
        except ValueError as exc:
            events.put({"event": "error", "message": str(exc)})
        except Exception:
            logger.exception("Scan failed (target=%r)", key or "local")
            events.put({"event": "error", "message": "Scan failed unexpectedly."})
        finally:
            events.put(None)  # sentinel: close the stream

    threading.Thread(target=work, daemon=True).start()

    def gen():
        while (item := events.get()) is not None:
            yield f"data: {json.dumps(item)}\n\n"

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
    )


class MetaUpdate(BaseModel):
    key: str                 # device identity: MAC when known, else IP
    custom_name: str = ""
    notes: str = ""


@app.post("/api/device-meta")
def api_device_meta(body: MetaUpdate, _auth: None = Depends(_require_token)) -> dict:
    """Set (or clear, with empty strings) a user-supplied device name/notes."""
    if not body.key.strip():
        raise HTTPException(status_code=400, detail="Missing device key.")
    if not history.set_meta(body.key, body.custom_name, body.notes):
        raise HTTPException(
            status_code=503,
            detail="Device names need the history DB; it is disabled (NDM_DB=off).",
        )
    # Cached scan results embed the old label; drop them so the next fetch is right.
    with _meta_lock:
        _cache.clear()
    return {"ok": True}


class WolRequest(BaseModel):
    mac: str


@app.post("/api/wol")
def api_wol(body: WolRequest, _auth: None = Depends(_require_token)) -> dict:
    """Broadcast a Wake-on-LAN magic packet for the given MAC."""
    try:
        wol.wake(body.mac)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"Send failed: {exc}") from exc
    return {"ok": True}


@app.get("/")
def index() -> FileResponse:
    # no-cache forces the browser to revalidate, so widget updates take effect on reload.
    return FileResponse(
        FRONTEND_DIR / "index.html", headers={"Cache-Control": "no-cache"}
    )


# Serve any other static assets (kept after routes so "/" resolves above).
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")
