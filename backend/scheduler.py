"""Background watch: periodic scans with new/missing-device notifications.

A single daemon thread wakes every POLL_S seconds, re-reads its config (so UI
changes apply without a restart), and runs a scan when one is due. Each run
reuses the normal pipeline (discovery.scan -> history.annotate), keeping NEW
flags, custom names, and the sightings log consistent with manual scans.

Config precedence: built-in defaults <- environment <- settings table (UI).
Missing-device alerts are opt-in and fire only for devices that vanished since
the *previous watch run* — the full historical missing-list would be noise.
"""

from __future__ import annotations

import logging
import os
import threading
import time

from . import discovery, history, notify

logger = logging.getLogger("scheduler")

POLL_S = 15  # config re-check cadence; scans run only when due

DEFAULTS = {
    "enabled": "false",
    "interval_min": "15",
    "target": "",            # "" = auto-detected local LAN
    "notify_new": "true",
    "notify_missing": "false",
    "webhook_url": "",
}

_ENV = {
    "enabled": "NDM_WATCH_ENABLED",
    "interval_min": "NDM_WATCH_INTERVAL_MIN",
    "target": "NDM_WATCH_TARGET",
    "notify_new": "NDM_WATCH_NOTIFY_NEW",
    "notify_missing": "NDM_WATCH_NOTIFY_MISSING",
    "webhook_url": "NDM_WEBHOOK_URL",
}

_TRUE = {"1", "true", "yes", "on"}


def _as_bool(v: str) -> bool:
    return str(v).strip().lower() in _TRUE


def get_config() -> dict:
    """Effective watch config: defaults <- env <- persisted settings."""
    raw = dict(DEFAULTS)
    for key, env in _ENV.items():
        val = os.environ.get(env, "").strip()
        if val:
            raw[key] = val
    stored = history.get_settings()
    for key in DEFAULTS:
        if f"watch_{key}" in stored:
            raw[key] = stored[f"watch_{key}"]
    try:
        interval = max(1, int(float(raw["interval_min"])))
    except ValueError:
        interval = int(DEFAULTS["interval_min"])
    return {
        "enabled": _as_bool(raw["enabled"]),
        "interval_min": interval,
        "target": raw["target"].strip(),
        "notify_new": _as_bool(raw["notify_new"]),
        "notify_missing": _as_bool(raw["notify_missing"]),
        "webhook_url": raw["webhook_url"].strip(),
    }


class Watch:
    def __init__(self) -> None:
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._scanning = False
        self.last_run: float | None = None
        self.last_summary: str | None = None
        self._prev_missing: set[str] | None = None  # None = no baseline yet

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="watch", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _loop(self) -> None:
        while not self._stop.wait(POLL_S):
            try:
                cfg = get_config()
                if not cfg["enabled"]:
                    continue
                due = (
                    self.last_run is None
                    or time.time() - self.last_run >= cfg["interval_min"] * 60
                )
                if due:
                    self.run_once(cfg)
            except Exception:  # the loop must survive anything
                logger.exception("Watch iteration failed")

    # -- one scan ----------------------------------------------------------

    def run_once(self, cfg: dict | None = None) -> dict:
        """Run one watch scan; returns the annotated scan dict."""
        cfg = cfg or get_config()
        self._scanning = True
        try:
            logger.info("Watch scan (target=%r)", cfg["target"] or "local")
            data = discovery.scan(cfg["target"] or None).to_dict()
            history.annotate(data)
        finally:
            self._scanning = False
        self.last_run = time.time()

        devices = data.get("devices") or []
        new = [d for d in devices if d.get("is_new")]
        missing_now = {
            (m.get("mac") or m.get("ip") or "").lower()
            for m in data.get("missing_devices") or []
        }

        if cfg["notify_new"] and new:
            notify.send(
                "New device on the network",
                _device_lines(new),
                cfg["webhook_url"],
            )
        if cfg["notify_missing"] and self._prev_missing is not None:
            newly_missing = missing_now - self._prev_missing
            if newly_missing:
                gone = [
                    m for m in data.get("missing_devices") or []
                    if (m.get("mac") or m.get("ip") or "").lower() in newly_missing
                ]
                notify.send("Device went missing", _device_lines(gone), cfg["webhook_url"])
        self._prev_missing = missing_now

        self.last_summary = (
            f"{len(devices)} devices, {len(new)} new, "
            f"{len(missing_now)} missing"
        )
        logger.info("Watch scan done: %s", self.last_summary)
        return data

    # -- status ------------------------------------------------------------

    def status(self) -> dict:
        cfg = get_config()
        next_run = None
        if cfg["enabled"]:
            next_run = (self.last_run or time.time()) + (
                cfg["interval_min"] * 60 if self.last_run else 0
            )
        return {
            **cfg,
            "scanning": self._scanning,
            "last_run": self.last_run,
            "last_summary": self.last_summary,
            "next_run": next_run,
        }


def _device_lines(devices: list[dict], cap: int = 4) -> str:
    lines = [
        f"{d.get('label') or d.get('ip') or d.get('mac')} ({d.get('ip') or d.get('mac')})"
        for d in devices[:cap]
    ]
    if len(devices) > cap:
        lines.append(f"…and {len(devices) - cap} more")
    return "\n".join(lines)


# Module-level singleton; the server starts/stops it via its lifespan.
watch = Watch()
