"""Scan persistence + diffing: which devices are new, which went missing.

Every completed scan is recorded in a small SQLite file (one row per device per
network). That history lets the UI answer the questions a live scan can't:

  * "Is this device NEW?"       -> first_seen == this scan
  * "What disappeared?"         -> seen on this network before, absent now

Devices are identified by MAC when known (survives DHCP renumbering), else by IP.
History is keyed per network (CIDR/target string) so scanning a second subnet
doesn't mark everything on the first one missing.

The DB location defaults to <project root>/scan_history.db; override with NDM_DB.
Set NDM_DB=off to disable persistence entirely. All best-effort: any sqlite error
logs and leaves the scan result un-annotated rather than failing the request.
"""

from __future__ import annotations

import logging
import os
import sqlite3
import time
from pathlib import Path

logger = logging.getLogger("history")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    network    TEXT NOT NULL,   -- network_cidr / target the scan covered
    key        TEXT NOT NULL,   -- MAC when known, else IP
    ip         TEXT,
    mac        TEXT,
    label      TEXT,
    first_seen REAL NOT NULL,   -- unix timestamps
    last_seen  REAL NOT NULL,
    PRIMARY KEY (network, key)
);
"""


def _db_path() -> Path | None:
    configured = os.environ.get("NDM_DB", "").strip()
    if configured.lower() == "off":
        return None
    if configured:
        return Path(configured)
    return Path(__file__).resolve().parent.parent / "scan_history.db"


def _connect(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(path, timeout=5)
    conn.execute(_SCHEMA)
    return conn


def _device_key(dev: dict) -> str | None:
    return (dev.get("mac") or "").lower() or dev.get("ip") or None


def annotate(data: dict) -> None:
    """Record this scan and annotate `data` (a ScanResult dict) in place.

    Adds per-device `first_seen` (unix ts) and `is_new`, plus a top-level
    `missing_devices` list of devices previously seen on this network but absent
    from this scan. No-op (and never raises) if persistence is disabled or broken.
    """
    path = _db_path()
    network = data.get("network_cidr")
    devices = data.get("devices") or []
    if path is None or not network or not devices:
        return

    now = time.time()
    try:
        with _connect(path) as conn:
            known = {
                key: (first, last)
                for key, first, last in conn.execute(
                    "SELECT key, first_seen, last_seen FROM devices WHERE network = ?",
                    (network,),
                )
            }

            present: set[str] = set()
            for dev in devices:
                key = _device_key(dev)
                if not key:
                    continue
                present.add(key)
                first_seen = known.get(key, (now, now))[0]
                dev["first_seen"] = first_seen
                dev["is_new"] = key not in known
                conn.execute(
                    """INSERT INTO devices (network, key, ip, mac, label, first_seen, last_seen)
                       VALUES (?, ?, ?, ?, ?, ?, ?)
                       ON CONFLICT (network, key) DO UPDATE SET
                         ip = excluded.ip, mac = excluded.mac, label = excluded.label,
                         last_seen = excluded.last_seen""",
                    (network, key, dev.get("ip"), dev.get("mac"),
                     dev.get("label"), first_seen, now),
                )

            missing = [
                {"ip": ip, "mac": mac, "label": label, "last_seen": last}
                for key, ip, mac, label, last in conn.execute(
                    "SELECT key, ip, mac, label, last_seen FROM devices WHERE network = ?",
                    (network,),
                )
                if key not in present and last < now  # absent from this scan
            ]
            missing.sort(key=lambda m: m["last_seen"], reverse=True)
            data["missing_devices"] = missing
    except sqlite3.Error as exc:
        logger.warning("Scan history unavailable (%s); continuing without it.", exc)
