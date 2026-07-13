"""Standalone desktop app: the scanner + widget in a native window.

Runs the existing FastAPI backend on a random loopback port in a background
thread, then opens the UI in a native window via pywebview (WKWebView on macOS,
WebView2 on Windows, GTK/QT WebKit on Linux). No browser, no exposed port —
the server is reachable only from this machine and dies with the window.

Run from source:   python3 -m backend.desktop
Build a bundle:    ./build_app.sh   ->  dist/Network Device Mapper.app / .exe

Configuration works like the server: environment variables, or a `.env` file
placed next to the app, in the working directory, or in the user data dir
(e.g. ~/Library/Application Support/Network Device Mapper/.env on macOS).
The scan-history DB also lives in that data dir unless NDM_DB overrides it.
"""

from __future__ import annotations

import logging
import os
import socket
import sys
import threading
import time
import urllib.request
from pathlib import Path

from .topology import load_dotenv

logger = logging.getLogger("desktop")

APP_NAME = "Network Device Mapper"


def user_data_dir() -> Path:
    """Per-user application data directory, by platform convention."""
    home = Path.home()
    if sys.platform == "darwin":
        return home / "Library" / "Application Support" / APP_NAME
    if os.name == "nt":
        return Path(os.environ.get("APPDATA", str(home))) / APP_NAME
    return Path(os.environ.get("XDG_DATA_HOME", str(home / ".local" / "share"))) / APP_NAME


def _env_candidates() -> list[Path]:
    """Places a desktop user might put a `.env`, in priority order."""
    candidates: list[Path] = []
    if getattr(sys, "frozen", False):  # PyInstaller bundle
        exe = Path(sys.executable).resolve()
        candidates.append(exe.parent / ".env")
        if sys.platform == "darwin":
            # Contents/MacOS/<exe> -> alongside the .app bundle itself.
            candidates.append(exe.parent.parent.parent.parent / ".env")
    candidates += [Path.cwd() / ".env", user_data_dir() / ".env"]
    return candidates


def _load_user_env() -> None:
    """Load the first `.env` found; say where to put one if none exists.

    Without it the app still works, but SNMP/UniFi topology (whose credentials
    live in .env) silently falls back to the logical L3 view — the log hint
    makes that discoverable instead of mysterious.
    """
    for path in _env_candidates():
        if path.is_file():
            logger.info("Loading settings from %s", path)
            load_dotenv(path)
            return
    logger.info(
        "No .env found (looked in: %s). Scans work without it; for SNMP/UniFi "
        "switch topology, copy your .env to %s",
        ", ".join(str(p.parent) for p in _env_candidates()),
        user_data_dir() / ".env",
    )


def _extend_path() -> None:
    """Add common tool locations to PATH.

    Apps launched from Finder/Dock inherit a minimal PATH (/usr/bin:/bin:...),
    which hides Homebrew/MacPorts installs of the net-snmp CLI that the SNMP
    topology provider shells out to.
    """
    extra = ["/opt/homebrew/bin", "/usr/local/bin", "/opt/local/bin"]
    current = os.environ.get("PATH", "").split(os.pathsep)
    missing = [d for d in extra if d not in current and Path(d).is_dir()]
    if missing:
        os.environ["PATH"] = os.pathsep.join(current + missing)


def free_port() -> int:
    """An OS-assigned free TCP port on loopback."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def start_server(port: int) -> threading.Thread:
    """Run uvicorn in a daemon thread (dies automatically when the window closes)."""
    import uvicorn

    from . import server

    config = uvicorn.Config(server.app, host="127.0.0.1", port=port, log_level="info")
    thread = threading.Thread(
        target=uvicorn.Server(config).run, name="uvicorn", daemon=True
    )
    thread.start()
    return thread


def wait_healthy(port: int, timeout: float = 15.0) -> bool:
    """Poll /api/health until the server answers (or the timeout passes)."""
    url = f"http://127.0.0.1:{port}/api/health"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1) as resp:
                if resp.status == 200:
                    return True
        except OSError:
            time.sleep(0.15)
    return False


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    _extend_path()
    _load_user_env()
    data_dir = user_data_dir()
    data_dir.mkdir(parents=True, exist_ok=True)
    # Keep scan history in the user data dir (a frozen app's own dir is read-only
    # or ephemeral); an explicit NDM_DB — from env or .env above — still wins.
    os.environ.setdefault("NDM_DB", str(data_dir / "scan_history.db"))

    # Random loopback port by default; NDM_PORT pins it (useful for debugging).
    port = int(os.environ.get("NDM_PORT", "0") or "0") or free_port()
    start_server(port)
    if not wait_healthy(port):
        raise SystemExit("Backend failed to start; see log output above.")
    logger.info("Backend ready on 127.0.0.1:%d", port)

    import webview  # imported late: not needed for tests / server-only use

    webview.create_window(
        APP_NAME,
        f"http://127.0.0.1:{port}/",
        width=1280,
        height=860,
        min_size=(900, 600),
    )
    webview.start()  # blocks until the window closes; daemon threads then exit


if __name__ == "__main__":
    main()
