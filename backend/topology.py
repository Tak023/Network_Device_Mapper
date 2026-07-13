"""Pluggable physical-topology providers.

A passive ping/ARP scan can't see switches or which port a device is on. Real
Layer-2 wiring must come from the infrastructure itself. This module defines the
common node model and a dispatcher that selects a provider:

  * snmp  -- vendor-neutral, LLDP-MIB + Bridge-MIB over SNMP (any managed switch)
  * unifi -- UniFi controller API (optional convenience for UniFi networks)

Each provider returns ``{mac: TopoNode}`` describing parent/child adjacency. All
credentials are supplied by the user at runtime (env / .env) -- nothing is baked in,
so the app is safe to share. If no provider is configured or reachable, the caller
falls back to the L3 hub-and-spoke view.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger("topology")

_dotenv_loaded = False


@dataclass
class TopoNode:
    mac: str
    name: str | None
    ip: str | None
    role: str                       # gateway | switch | ap | client | router
    uplink_mac: str | None       # MAC of the parent (what this connects up to)
    model: str | None = None
    port: str | None = None      # parent's port this node hangs off, if known
    is_infra: bool = False          # True for managed gear (gateway/switch/ap)


def load_dotenv(env_path: Path | None = None) -> None:
    """Load KEY=VALUE pairs from a .env file into os.environ.

    With no argument, loads the project-root .env (once — repeat calls no-op).
    An explicit `env_path` always loads; the desktop app uses this for .env files
    next to the packaged binary. Existing environment variables always win, so
    this never clobbers an explicit override.
    """
    global _dotenv_loaded
    if env_path is None:
        if _dotenv_loaded:
            return
        _dotenv_loaded = True
        env_path = Path(__file__).resolve().parent.parent / ".env"
    if not env_path.exists():
        return
    # Collect pairs first; on duplicate keys, a non-empty value wins (so a populated
    # line beats a leftover empty template line regardless of order).
    pairs: dict[str, str] = {}
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip().strip('"').strip("'")
        if value or key not in pairs:
            pairs[key] = value
    for key, value in pairs.items():
        os.environ.setdefault(key, value)  # real env vars still override .env


def fetch_topology(
    device_macs: dict[str, str] | None = None,
    gateway_ip: str | None = None,
) -> tuple[dict[str, TopoNode] | None, str | None]:
    """Return (nodes, source) from the first configured provider, else (None, None).

    `device_macs` maps discovered IP -> MAC (from the scan); the SNMP provider uses it
    to identify which hosts to probe and to resolve infra MACs. `gateway_ip` roots the
    hierarchy. `source` is "snmp" or "unifi" for the UI to label the view.
    """
    load_dotenv()

    # SNMP first: vendor-neutral and the intended primary path.
    if os.environ.get("SNMP_COMMUNITY") or os.environ.get("SNMP_TARGETS"):
        try:
            from . import snmp
            nodes = snmp.fetch_topology(device_macs or {}, gateway_ip)
            if nodes:
                return nodes, "snmp"
        except Exception as exc:  # never let a provider error break the scan
            logger.warning("SNMP provider failed: %s", exc)

    # UniFi: optional convenience for UniFi networks.
    if os.environ.get("UNIFI_URL"):
        try:
            from . import unifi
            nodes = unifi.fetch_topology()
            if nodes:
                return nodes, "unifi"
        except Exception as exc:
            logger.warning("UniFi provider failed: %s", exc)

    return None, None
