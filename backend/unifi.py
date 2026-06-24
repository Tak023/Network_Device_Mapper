"""UniFi Network controller integration for real Layer-2 topology.

A passive ping/ARP scan can't see switches or which port a device is on (a switch is
transparent at L3). The UniFi controller already computes physical adjacency from
LLDP/CDP, so we read it and draw "gateway -> switch -> devices" correctly.

Two auth methods are supported (API key preferred):

  1. Official Integration API (API key) -- modern, stateless, recommended.
       UNIFI_URL        e.g. https://10.1.1.1
       UNIFI_API_KEY    created in Network app: Settings -> Control Plane ->
                        Integrations (or the "API Keys" tab) on Network 10.1.84+.
       Base path: {UNIFI_URL}/proxy/network/integration/v1
       Auth header: X-API-KEY

  2. Local-admin API (username/password) -- legacy fallback for older setups.
       UNIFI_USERNAME / UNIFI_PASSWORD  (a local read-only admin)

  Common:
       UNIFI_SITE       site name (default: "default")
       UNIFI_VERIFY_TLS "true" to verify TLS (default false; controllers self-sign)

Everything here is best-effort: any failure returns None so the caller falls back to
the L3 star view rather than erroring.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Optional

from .topology import TopoNode, load_dotenv

logger = logging.getLogger("unifi")

INTEGRATION_BASE = "/proxy/network/integration/v1"

# UniFi nodes are just TopoNodes; alias keeps the rest of this module readable.
UnifiNode = TopoNode
_load_dotenv = load_dotenv


@dataclass
class _Config:
    url: str
    site: str
    verify_tls: bool
    api_key: Optional[str]
    username: Optional[str]
    password: Optional[str]

    @classmethod
    def from_env(cls) -> "Optional[_Config]":
        url = os.environ.get("UNIFI_URL", "").strip().rstrip("/")
        if not url:
            return None
        api_key = os.environ.get("UNIFI_API_KEY", "").strip() or None
        user = os.environ.get("UNIFI_USERNAME", "").strip() or None
        pwd = os.environ.get("UNIFI_PASSWORD", "") or None
        if not api_key and not (user and pwd):
            return None  # need at least one auth method
        return cls(
            url=url,
            site=os.environ.get("UNIFI_SITE", "default").strip() or "default",
            verify_tls=os.environ.get("UNIFI_VERIFY_TLS", "false").lower() == "true",
            api_key=api_key,
            username=user,
            password=pwd,
        )


def _norm_mac(mac: Optional[str]) -> Optional[str]:
    return mac.lower() if mac else None


def _role_from_features(d: dict) -> Optional[str]:
    """Infer role from a device's `features`, which may be a dict or a list."""
    feats = d.get("features")
    keys = set()
    if isinstance(feats, dict):
        keys = {k for k, v in feats.items() if v}
    elif isinstance(feats, list):
        keys = set(feats)
    if "switching" in keys:
        return "switch"
    if "accessPoint" in keys:
        return "ap"
    return None


# --------------------------------------------------------------------------- #
# Official Integration API (API key)
# --------------------------------------------------------------------------- #

class _OfficialApi:
    def __init__(self, cfg: _Config, session):
        self.cfg = cfg
        self.s = session
        self.s.headers.update({"X-API-KEY": cfg.api_key, "Accept": "application/json"})

    def _get(self, path: str) -> list[dict]:
        """GET a (possibly paginated) Integration API collection -> flat list."""
        out: list[dict] = []
        offset, limit = 0, 200
        while True:
            r = self.s.get(
                f"{self.cfg.url}{INTEGRATION_BASE}{path}",
                params={"offset": offset, "limit": limit},
                verify=self.cfg.verify_tls, timeout=10,
            )
            r.raise_for_status()
            body = r.json()
            data = body.get("data", body if isinstance(body, list) else [])
            out.extend(data)
            total = body.get("totalCount")
            count = body.get("count", len(data))
            if total is None or offset + count >= total or not data:
                break
            offset += count
        return out

    def _site_id(self) -> Optional[str]:
        sites = self._get("/sites")
        if not sites:
            return None
        want = self.cfg.site.lower()
        for s in sites:
            if want in {str(s.get(k, "")).lower() for k in ("name", "internalReference", "id")}:
                return s.get("id")
        return sites[0].get("id")  # single-site setups: just use the first

    def fetch(self) -> Optional[dict[str, UnifiNode]]:
        site_id = self._site_id()
        if not site_id:
            logger.warning("No UniFi site found via Integration API.")
            return None

        raw_devices = self._get(f"/sites/{site_id}/devices")
        # The list endpoint may omit `uplink`; fetch details when it's missing.
        devices: list[dict] = []
        for d in raw_devices:
            if "uplink" not in d and d.get("id"):
                try:
                    r = self.s.get(
                        f"{self.cfg.url}{INTEGRATION_BASE}/sites/{site_id}/devices/{d['id']}",
                        verify=self.cfg.verify_tls, timeout=10,
                    )
                    if r.ok:
                        d = {**d, **r.json()}
                except Exception:
                    pass
            devices.append(d)

        # deviceId -> MAC, so uplink.deviceId references resolve to a MAC.
        id_to_mac = {d.get("id"): _norm_mac(d.get("macAddress")) for d in devices}

        nodes: dict[str, UnifiNode] = {}
        for d in devices:
            mac = _norm_mac(d.get("macAddress"))
            if not mac:
                continue
            uplink = d.get("uplink") or {}
            parent_mac = id_to_mac.get(uplink.get("deviceId")) if uplink else None
            role = _role_from_features(d) or ("gateway" if not parent_mac else "switch")
            nodes[mac] = UnifiNode(
                mac=mac, name=d.get("name") or d.get("model"), ip=d.get("ipAddress"),
                role=role, uplink_mac=parent_mac, model=d.get("model"),
                port=(uplink.get("portIdx") if uplink else None), is_infra=True,
            )

        for c in self._get(f"/sites/{site_id}/clients"):
            mac = _norm_mac(c.get("macAddress"))
            if not mac or mac in nodes:
                continue
            # Client -> parent device. Field name varies by firmware; try the usual ones.
            parent_id = (c.get("uplinkDeviceId") or (c.get("uplink") or {}).get("deviceId")
                         or c.get("lastUplinkDeviceId"))
            nodes[mac] = UnifiNode(
                mac=mac, name=c.get("name") or c.get("hostname"), ip=c.get("ipAddress"),
                role="client", uplink_mac=id_to_mac.get(parent_id), is_infra=False,
            )
        logger.info("UniFi Integration API: %d nodes (site %s)", len(nodes), site_id)
        return nodes


# --------------------------------------------------------------------------- #
# Legacy local-admin API (cookie auth)
# --------------------------------------------------------------------------- #

_LEGACY_ROLE = {"ugw": "gateway", "udm": "gateway", "uxg": "gateway",
                "usw": "switch", "uap": "ap"}


class _LegacyApi:
    def __init__(self, cfg: _Config, session):
        self.cfg = cfg
        self.s = session
        self.prefix = ""

    def login(self) -> bool:
        import requests
        for path, prefix in (("/api/auth/login", "/proxy/network"), ("/api/login", "")):
            try:
                r = self.s.post(
                    f"{self.cfg.url}{path}",
                    json={"username": self.cfg.username, "password": self.cfg.password},
                    verify=self.cfg.verify_tls, timeout=8,
                )
                if r.status_code == 200:
                    token = r.headers.get("X-CSRF-Token")
                    if token:
                        self.s.headers["X-CSRF-Token"] = token
                    self.prefix = prefix
                    return True
            except requests.RequestException as exc:
                logger.debug("Legacy login %s failed: %s", path, exc)
        logger.warning("UniFi legacy login failed.")
        return False

    def _get(self, path: str) -> list[dict]:
        r = self.s.get(
            f"{self.cfg.url}{self.prefix}/api/s/{self.cfg.site}{path}",
            verify=self.cfg.verify_tls, timeout=10,
        )
        r.raise_for_status()
        return r.json().get("data", [])

    def fetch(self) -> Optional[dict[str, UnifiNode]]:
        if not self.login():
            return None
        nodes: dict[str, UnifiNode] = {}
        for d in self._get("/stat/device"):
            mac = _norm_mac(d.get("mac"))
            if not mac:
                continue
            role = _LEGACY_ROLE.get(d.get("type", ""), "switch")
            uplink = d.get("uplink") or {}
            parent = None if role == "gateway" else _norm_mac(uplink.get("uplink_mac"))
            nodes[mac] = UnifiNode(
                mac=mac, name=d.get("name") or d.get("model"), ip=d.get("ip"),
                role=role, uplink_mac=parent, model=d.get("model"),
                port=uplink.get("uplink_remote_port"), is_infra=True,
            )
        for c in self._get("/stat/sta"):
            mac = _norm_mac(c.get("mac"))
            if not mac or mac in nodes:
                continue
            parent = c.get("sw_mac") if c.get("is_wired") else c.get("ap_mac")
            nodes[mac] = UnifiNode(
                mac=mac, name=c.get("name") or c.get("hostname"), ip=c.get("ip"),
                role="client", uplink_mac=_norm_mac(parent or c.get("uplink_mac")),
                port=c.get("sw_port"), is_infra=False,
            )
        logger.info("UniFi legacy API: %d nodes", len(nodes))
        return nodes


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #

def fetch_topology() -> Optional[dict[str, UnifiNode]]:
    """Return {mac: UnifiNode} of the controller's L2 adjacency, or None if unavailable.

    Prefers the official API key; falls back to local-admin credentials. None means
    "not configured or unreachable" -> caller uses the L3 fallback.
    """
    _load_dotenv()
    cfg = _Config.from_env()
    if not cfg:
        logger.debug("UniFi not configured (set UNIFI_URL + UNIFI_API_KEY).")
        return None
    try:
        import requests
    except ImportError:
        logger.warning("`requests` not installed; cannot query UniFi (pip install requests).")
        return None

    session = requests.Session()
    try:
        if cfg.api_key:
            return _OfficialApi(cfg, session).fetch()
        return _LegacyApi(cfg, session).fetch()
    except requests.RequestException as exc:
        logger.warning("UniFi topology fetch failed: %s", exc)
        return None


if __name__ == "__main__":
    import json
    import sys

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    _load_dotenv()

    cfg = _Config.from_env()
    if cfg is None:
        print("UniFi not configured. Is .env present with UNIFI_URL + UNIFI_API_KEY?")
        raise SystemExit(1)
    print(f"Config: url={cfg.url}  auth={'api-key' if cfg.api_key else 'local-admin'}"
          f"  site={cfg.site}  verify_tls={cfg.verify_tls}")

    # --raw dumps the unparsed API payloads so we can confirm field names per firmware.
    if "--raw" in sys.argv:
        import requests
        s = requests.Session()
        api = _OfficialApi(cfg, s)
        sid = api._site_id()
        print("site id:", sid)
        print("\n=== devices (first) ===")
        devs = api._get(f"/sites/{sid}/devices")
        print(json.dumps(devs[:1], indent=2))
        print("\n=== clients (first) ===")
        print(json.dumps(api._get(f"/sites/{sid}/clients")[:1], indent=2))
        raise SystemExit(0)

    topo = fetch_topology()
    if topo is None:
        print("No topology returned. Check UNIFI_URL / UNIFI_API_KEY and connectivity.")
        raise SystemExit(1)
    print(f"\n{len(topo)} nodes from UniFi:\n")
    for mac, n in sorted(topo.items(), key=lambda kv: (kv[1].role, kv[1].name or "")):
        parent = topo.get(n.uplink_mac)
        parent_str = f"-> {parent.name or parent.mac}" if parent else "(root)"
        port = f" port {n.port}" if n.port else ""
        print(f"  [{n.role:<7}] {(n.name or n.mac):<26} {n.ip or '':<15} {parent_str}{port}")
