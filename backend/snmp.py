"""Vendor-neutral Layer-2 topology via SNMP (LLDP-MIB + Bridge-MIB).

This is the standard way every NMS (LibreNMS, Netdisco, OpenNMS) builds physical
topology, and it works across vendors (Cisco, Aruba, Netgear, MikroTik, UniFi, ...):

  * LLDP-MIB (lldpRemTable)        -> infra<->infra links (which switch port faces
                                      which neighbouring switch/router)
  * Bridge-MIB (dot1q/dot1d FDB)   -> which MAC is learned on which switch port
  * dot1dBasePortIfIndex / IF-MIB  -> bridge-port <-> ifIndex mapping

Correlation: a port that faces another managed switch is an *uplink*; end devices are
attached to the switch/port where they're learned on a NON-uplink (edge) port.

Requirements (user-supplied at runtime, nothing baked in):
  * net-snmp CLI tools installed (`snmpbulkwalk`, `snmpget`):
        macOS: brew install net-snmp   Debian/Ubuntu: apt install snmp
  * SNMP enabled on the switches + a read community string.

Environment:
  SNMP_COMMUNITY   read community (e.g. "public"); required to activate this provider
  SNMP_VERSION     "2c" (default) or "1"
  SNMP_TARGETS     optional comma-separated switch IPs to poll; if unset, every
                   discovered host is probed and SNMP responders are used
  SNMP_TIMEOUT     per-request seconds (default 2)

Best-effort: returns None on any hard failure so the caller uses the L3 fallback.
"""

from __future__ import annotations

import concurrent.futures
import logging
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Optional

from .topology import TopoNode

logger = logging.getLogger("snmp")

# Numeric OIDs (kept numeric so we don't depend on installed MIB files).
OID = {
    "sysName":          "1.3.6.1.2.1.1.5.0",
    "sysDescr":         "1.3.6.1.2.1.1.1.0",
    "lldpLocChassisId": "1.0.8802.1.1.2.1.3.2.0",
    "lldpLocSysName":   "1.0.8802.1.1.2.1.3.3.0",
    "lldpRemChassisId": "1.0.8802.1.1.2.1.4.1.1.5",
    "lldpRemPortId":    "1.0.8802.1.1.2.1.4.1.1.7",
    "lldpRemSysName":   "1.0.8802.1.1.2.1.4.1.1.9",
    "lldpRemSysCap":    "1.0.8802.1.1.2.1.4.1.1.12",  # enabled capabilities bitmask
    "basePortIfIndex":  "1.3.6.1.2.1.17.1.4.1.2",
    "dot1qFdbPort":     "1.3.6.1.2.1.17.7.1.2.2.1.2",
    "dot1dFdbPort":     "1.3.6.1.2.1.17.4.3.1.2",
}

PROBE_WORKERS = 32


@dataclass
class _Config:
    community: str
    version: str
    targets: list[str]
    timeout: int

    @classmethod
    def from_env(cls) -> "Optional[_Config]":
        community = os.environ.get("SNMP_COMMUNITY", "").strip()
        targets = [t.strip() for t in os.environ.get("SNMP_TARGETS", "").split(",") if t.strip()]
        if not community and not targets:
            return None
        return cls(
            community=community or "public",
            version="1" if os.environ.get("SNMP_VERSION", "2c").strip() == "1" else "2c",
            targets=targets,
            timeout=int(os.environ.get("SNMP_TIMEOUT", "2") or "2"),
        )


@dataclass
class _Switch:
    ip: str
    mac: Optional[str]
    name: Optional[str] = None
    chassis_id: Optional[str] = None         # normalized MAC when chassis subtype is MAC
    neighbors: dict[str, dict] = field(default_factory=dict)  # localPort -> {chassis,sysname,port}
    fdb: dict[str, str] = field(default_factory=dict)         # device MAC -> bridgePort
    port_ifindex: dict[str, str] = field(default_factory=dict)  # bridgePort -> ifIndex

    def identities(self) -> set[str]:
        ids = set()
        if self.mac:
            ids.add(self.mac)
        if self.chassis_id:
            ids.add(self.chassis_id)
        if self.name:
            ids.add(self.name.lower())
        return ids


# --------------------------------------------------------------------------- #
# SNMP plumbing (net-snmp CLI)
# --------------------------------------------------------------------------- #

def _tools_available() -> bool:
    return bool(shutil.which("snmpbulkwalk") and shutil.which("snmpget"))


def _base_args(cfg: _Config, hexval: bool = False) -> list[str]:
    # q=quick n=numeric-OID U=no-units; x=hex octet strings (for MAC/chassis values).
    fmt = "-OqnUx" if hexval else "-OqnU"
    return ["-v", cfg.version, "-c", cfg.community, "-t", str(cfg.timeout), "-r", "1", fmt]


def _run(cmd: list[str], timeout: int) -> Optional[str]:
    """Run an snmp* command, decoding bytes defensively (SNMP values carry raw binary
    that isn't valid UTF-8 — never let that crash us)."""
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return None
    if p.returncode != 0:
        return None
    return p.stdout.decode("utf-8", errors="replace")


def _snmpget(cfg: _Config, host: str, oid: str, hexval: bool = False) -> Optional[str]:
    out = _run(["snmpget", *_base_args(cfg, hexval), host, oid], cfg.timeout + 2)
    if not out or not out.strip():
        return None
    # -Oqn prints "<numeric-oid> <value>"; we want only the value.
    _oid, _, value = out.strip().partition(" ")
    return _value(value) if value else None


def _snmpwalk(cfg: _Config, host: str, base_oid: str, hexval: bool = False) -> list[tuple[str, str]]:
    """Return [(index_suffix, value)] for an OID subtree, or [] on failure."""
    raw = _run(["snmpbulkwalk", *_base_args(cfg, hexval), "-Cr40", host, base_oid], cfg.timeout + 8)
    if raw is None:
        return []
    out: list[tuple[str, str]] = []
    prefix = "." + base_oid + "."
    for line in raw.splitlines():
        line = line.strip()
        if not line or " " not in line:
            continue
        oid, _, value = line.partition(" ")
        # -On prints a leading dot; normalize both forms.
        full = oid if oid.startswith(".") else "." + oid
        if full.startswith(prefix):
            out.append((full[len(prefix):], _value(value)))
    return out


def _value(raw: str) -> str:
    """Strip net-snmp value decorations (quotes, STRING:/Hex-STRING: are off with -Oq)."""
    return raw.strip().strip('"')


def _mac_from_value(value: str) -> Optional[str]:
    """Extract a MAC from an SNMP octet-string value (hex pairs in any separator)."""
    import re
    hexes = re.findall(r"[0-9A-Fa-f]{2}", value)
    if len(hexes) >= 6:
        return ":".join(h.lower() for h in hexes[:6])
    return None


def _mac_from_oid_octets(octets: list[str]) -> Optional[str]:
    """The last 6 decimal components of an FDB OID index encode the MAC."""
    if len(octets) < 6:
        return None
    try:
        return ":".join(f"{int(o):02x}" for o in octets[-6:])
    except ValueError:
        return None


def _cap_octet(cap_hex: Optional[str]) -> int:
    """LLDP sysCapEnabled bits, OR-ed across all octets (0 if absent/unparseable).

    The capability byte's position varies by vendor (some put it in the 2nd octet of
    the 2-octet BITS value), so we OR every octet. Relevant bits: bridge 0x20,
    wlanAP 0x10, router 0x08 -> infra mask 0x38.
    """
    import re
    bits = 0
    for h in re.findall(r"[0-9A-Fa-f]{2}", cap_hex or ""):
        try:
            bits |= int(h, 16)
        except ValueError:
            pass
    return bits


# --------------------------------------------------------------------------- #
# Per-switch collection
# --------------------------------------------------------------------------- #

def _collect(cfg: _Config, ip: str, mac: Optional[str]) -> Optional[_Switch]:
    """Probe one host; return a populated _Switch if it speaks SNMP, else None."""
    name = _snmpget(cfg, ip, OID["sysName"])
    if name is None:
        return None  # no SNMP here
    sw = _Switch(ip=ip, mac=mac, name=name)
    # Chassis/MAC OIDs carry binary octet strings -> request hex so they parse cleanly.
    sw.chassis_id = _mac_from_value(_snmpget(cfg, ip, OID["lldpLocChassisId"], hexval=True) or "")

    # LLDP neighbours keyed by local port number (2nd component of the index).
    rem_chassis = dict(_snmpwalk(cfg, ip, OID["lldpRemChassisId"], hexval=True))
    rem_sysname = dict(_snmpwalk(cfg, ip, OID["lldpRemSysName"]))
    rem_port = dict(_snmpwalk(cfg, ip, OID["lldpRemPortId"]))
    rem_cap = dict(_snmpwalk(cfg, ip, OID["lldpRemSysCap"], hexval=True))
    for idx, chassis in rem_chassis.items():
        parts = idx.split(".")
        local_port = parts[1] if len(parts) >= 2 else parts[0]
        cap = _cap_octet(rem_cap.get(idx))
        sw.neighbors[local_port] = {
            "chassis": _mac_from_value(chassis) or chassis.lower(),
            "sysname": (rem_sysname.get(idx) or "").strip().lower(),
            "port": rem_port.get(idx),
            "infra": bool(cap & 0x38),   # bridge | wlanAP | router
            "ap": bool(cap & 0x10),      # wlanAP
        }

    # Bridge port -> ifIndex.
    for bp, ifx in _snmpwalk(cfg, ip, OID["basePortIfIndex"]):
        sw.port_ifindex[bp] = ifx

    # Forwarding DB: prefer Q-BRIDGE (VLAN-aware), fall back to plain BRIDGE.
    fdb = _snmpwalk(cfg, ip, OID["dot1qFdbPort"]) or _snmpwalk(cfg, ip, OID["dot1dFdbPort"])
    for idx, bridge_port in fdb:
        dmac = _mac_from_oid_octets(idx.split("."))
        if dmac and bridge_port:
            sw.fdb[dmac] = bridge_port

    logger.info("SNMP %s (%s): %d neighbours, %d FDB entries",
                ip, name, len(sw.neighbors), len(sw.fdb))
    return sw


# --------------------------------------------------------------------------- #
# Correlation -> TopoNodes
# --------------------------------------------------------------------------- #

def _match_switch(neighbor: dict, switches: list[_Switch]) -> Optional[_Switch]:
    """Resolve an LLDP neighbour to one of our polled devices (by chassis/sysname).

    Chassis-id and the management-interface MAC often differ (e.g. a UDM advertises a
    base MAC ending :55 but ARPs as :5f), so we also match on sysName.
    """
    chassis, sysname = neighbor.get("chassis"), neighbor.get("sysname")
    for sw in switches:
        ids = sw.identities()
        if (chassis and chassis in ids) or (sysname and sysname in ids):
            return sw
    return None


def _build_nodes(switches: list[_Switch], gateway_ip: Optional[str]) -> dict[str, TopoNode]:
    """Correlate FDB + LLDP across polled switches into a parent/child tree.

    Infra = the gateway, devices with a forwarding DB (real switches), and LLDP
    neighbours whose capabilities say bridge/AP/router. Everything else is an end
    device, attached to the switch/port where it's learned — unless that port faces a
    child AP/switch (then it's placed under that child) or the parent (then skipped).
    """
    by_ip = {sw.ip: sw for sw in switches}
    gateway = by_ip.get(gateway_ip) if gateway_ip else None
    fdb_switches = [sw for sw in switches if sw.fdb]

    def node_id(sw: _Switch) -> str:
        return sw.mac or sw.ip

    # 1. Register infra nodes: gateway + real switches (have FDB).
    infra_meta: dict[str, dict] = {}

    def reg(nid: str, name, ip, role) -> str:
        m = infra_meta.setdefault(nid, {"name": None, "ip": None, "role": role})
        m["name"] = m["name"] or name
        m["ip"] = m["ip"] or ip
        return nid

    for sw in switches:
        if sw is gateway or sw.fdb:
            reg(node_id(sw), sw.name, sw.ip, "gateway" if sw is gateway else "switch")

    # 2. Walk each switch's LLDP for infra neighbours (other switches / APs / router).
    #    Build undirected adjacency, remembering which local port faces each neighbour.
    adjacency: dict[str, set[str]] = {}
    facing_port: dict[tuple[str, str], str] = {}

    for sw in fdb_switches:
        sid = node_id(sw)
        for lp, nb in sw.neighbors.items():
            if not nb.get("infra"):
                continue
            match = _match_switch(nb, switches)
            if match:
                nid = node_id(match)
                role = "gateway" if match is gateway else ("ap" if nb.get("ap") else "switch")
                reg(nid, match.name, match.ip, role)
            else:  # an infra neighbour we couldn't poll (e.g. an AP) — still draw it
                nid = nb["chassis"]
                reg(nid, nb["sysname"] or None, None, "ap" if nb.get("ap") else "switch")
            adjacency.setdefault(sid, set()).add(nid)
            adjacency.setdefault(nid, set()).add(sid)
            facing_port[(sid, nid)] = lp

    # 3. Root the infra tree at the gateway (BFS over LLDP adjacency).
    root = node_id(gateway) if gateway else (node_id(fdb_switches[0]) if fdb_switches else None)
    parent: dict[str, str] = {}
    if root:
        seen, queue = {root}, [root]
        while queue:
            cur = queue.pop(0)
            for nb in adjacency.get(cur, ()):
                if nb not in seen:
                    seen.add(nb)
                    parent[nb] = cur
                    queue.append(nb)

    nodes: dict[str, TopoNode] = {}
    for nid, m in infra_meta.items():
        nodes[nid] = TopoNode(
            mac=nid, name=m["name"], ip=m["ip"], role=m["role"],
            uplink_mac=parent.get(nid), is_infra=True,
        )

    # 4. Place end devices. A FDB MAC on switch S, bridge-port bp (-> ifIndex ifx):
    #      * ifx faces S's parent  -> upstream, skip (placed by a switch above)
    #      * ifx faces a child AP  -> attach under that child
    #      * otherwise (edge port) -> attach to S
    #    Dedup across switches by fewest MACs on the port (closest switch wins).
    infra_ids = set(infra_meta)
    port_load: dict[tuple[str, str], int] = {}
    for sw in fdb_switches:
        for bp in sw.fdb.values():
            port_load[(node_id(sw), bp)] = port_load.get((node_id(sw), bp), 0) + 1

    best: dict[str, tuple[int, str, str]] = {}  # mac -> (load, parent_id, bridge_port)
    for sw in fdb_switches:
        sid = node_id(sw)
        up_port = facing_port.get((sid, parent.get(sid)))
        child_by_port = {
            facing_port[(sid, c)]: c
            for c in adjacency.get(sid, ())
            if parent.get(c) == sid and (sid, c) in facing_port
        }
        for dmac, bp in sw.fdb.items():
            if dmac in infra_ids:
                continue
            ifx = sw.port_ifindex.get(bp, bp)
            if up_port and ifx == up_port:
                continue
            parent_id = child_by_port.get(ifx, sid)
            load = port_load.get((sid, bp), 1)
            if dmac not in best or load < best[dmac][0]:
                best[dmac] = (load, parent_id, bp)

    for dmac, (_load, parent_id, bp) in best.items():
        if dmac in nodes:
            continue
        nodes[dmac] = TopoNode(
            mac=dmac, name=None, ip=None, role="client",
            uplink_mac=parent_id, port=bp, is_infra=False,
        )
    return nodes


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #

def fetch_topology(
    device_macs: dict[str, str],
    gateway_ip: Optional[str] = None,
    targets: Optional[list[str]] = None,
) -> Optional[dict[str, TopoNode]]:
    """Return {mac: TopoNode} from SNMP, or None if unavailable.

    `device_macs` maps discovered IP -> MAC. `targets` (explicit override) wins; else
    SNMP_TARGETS; else every discovered host is probed and SNMP responders are used.
    """
    cfg = _Config.from_env()
    if not cfg:
        return None
    if not _tools_available():
        logger.warning("net-snmp CLI not found (install: brew install net-snmp / "
                       "apt install snmp); skipping SNMP topology.")
        return None

    targets = targets or cfg.targets or list(device_macs.keys())
    if not targets:
        return None
    logger.info("Probing %d host(s) over SNMP...", len(targets))

    switches: list[_Switch] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=PROBE_WORKERS) as pool:
        futures = {pool.submit(_collect, cfg, ip, device_macs.get(ip)): ip for ip in targets}
        for fut in concurrent.futures.as_completed(futures):
            sw = fut.result()
            if sw:
                switches.append(sw)

    if not switches:
        logger.info("No SNMP-capable switches responded.")
        return None
    logger.info("%d SNMP switch(es) responded.", len(switches))
    return _build_nodes(switches, gateway_ip)


if __name__ == "__main__":
    import sys
    from . import topology

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    topology.load_dotenv()
    cfg = _Config.from_env()
    if not cfg:
        print("SNMP not configured. Set SNMP_COMMUNITY (and optionally SNMP_TARGETS) in .env.")
        raise SystemExit(1)
    if not _tools_available():
        print("net-snmp CLI missing. Install:  brew install net-snmp  (or: apt install snmp)")
        raise SystemExit(1)

    import re

    diag = "--diag" in sys.argv
    cli_ips = [a for a in sys.argv[1:] if not a.startswith("-")]

    community_src = "set" if os.environ.get("SNMP_COMMUNITY", "").strip() else "DEFAULT 'public'"
    print(f"Config: community={community_src} version={cfg.version} "
          f"SNMP_TARGETS={cfg.targets or '(none)'} timeout={cfg.timeout}s")

    # Guard the classic mistake: community string typed into SNMP_TARGETS.
    bad = [t for t in cfg.targets if not re.match(r"^[0-9.]+$|^[\w.-]+\.[\w.-]+$", t)]
    if bad:
        print(f"⚠️  SNMP_TARGETS contains {bad} — that doesn't look like an IP/hostname.")
        print("    Did you mean SNMP_COMMUNITY? Put the community string there, and put")
        print("    switch IPs (or nothing) in SNMP_TARGETS.")

    # Command-line IPs win, so `python3 -m backend.snmp 10.1.1.1` always tests that host.
    test_targets = cli_ips or cfg.targets
    if not test_targets:
        print("Pass one or more switch IPs to test, e.g.:  python3 -m backend.snmp 10.1.1.1")
        raise SystemExit(1)
    print(f"Testing: {test_targets}\n")

    if diag:
        # Raw walk dump for tuning the parser against your gear.
        host = test_targets[0]
        for label, oid in OID.items():
            rows = _snmpwalk(cfg, host, oid) if not oid.endswith(".0") else \
                   [("", _snmpget(cfg, host, oid) or "(no response)")]
            print(f"--- {label} ({oid}) ---")
            for idx, val in rows[:20]:
                print(f"  {idx or '(scalar)'} = {val}")
            print()
        raise SystemExit(0)

    nodes = fetch_topology({ip: None for ip in test_targets},
                           gateway_ip=test_targets[0], targets=test_targets)
    if not nodes:
        print("No topology returned (no SNMP responders, or no LLDP/Bridge data).")
        print("Check: is SNMP enabled on the switch? Is the community correct? Try --diag.")
        raise SystemExit(1)
    print(f"{len(nodes)} nodes:\n")
    for mac, n in sorted(nodes.items(), key=lambda kv: (kv[1].role, kv[1].name or "")):
        parent = nodes.get(n.uplink_mac)
        ps = f"-> {parent.name or parent.mac}" if parent else "(root)"
        port = f" port {n.port}" if n.port else ""
        print(f"  [{n.role:<7}] {(n.name or mac):<26} {n.ip or '':<15} {ps}{port}")
