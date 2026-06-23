"""Local-network device discovery.

Strategy (no root required on macOS/Linux):
  1. Determine this host's primary IP, subnet, and default gateway.
  2. Concurrent ICMP ping-sweep across the subnet to populate the kernel ARP cache.
  3. Read the system ARP table to map IP -> MAC.
  4. Best-effort reverse-DNS and MAC-vendor lookups for human-readable names.

This intentionally avoids raw sockets / scapy so it runs unprivileged. The trade-off
is that it discovers reachable layer-3 hosts only -- it cannot infer physical switch
wiring (that requires LLDP/CDP/SNMP against managed switches).
"""

from __future__ import annotations

import concurrent.futures
import ipaddress
import logging
import os
import re
import socket
import subprocess
import sys
from dataclasses import dataclass, field, asdict
from typing import Optional

logger = logging.getLogger("discovery")

# Per-host ping timeout (seconds) and sweep concurrency. 254 hosts / 128 workers
# at a 1s timeout completes a /24 in a few seconds.
PING_TIMEOUT_S = 1.0
MAX_WORKERS = 128

# Upper bound on hosts per scan. Guards against someone sweeping a /8 (16M hosts),
# which would hang for hours. 4096 == a /20, comfortably covers any home/SMB subnet.
MAX_SCAN_HOSTS = 4096

_MAC_RE = re.compile(r"(([0-9a-fA-F]{1,2}:){5}[0-9a-fA-F]{1,2})")


@dataclass
class Device:
    ip: str
    mac: Optional[str] = None
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    is_gateway: bool = False
    is_self: bool = False

    @property
    def label(self) -> str:
        """Best human-readable name for a node/table row."""
        if self.hostname:
            return self.hostname
        if self.vendor:
            return f"{self.vendor} device"
        return self.ip


@dataclass
class ScanResult:
    gateway_ip: Optional[str]
    self_ip: Optional[str]
    network_cidr: Optional[str]
    devices: list[Device] = field(default_factory=list)
    reachable: bool = True          # False == no route / network appears unreachable
    note: Optional[str] = None      # human-readable status for the UI

    def to_dict(self) -> dict:
        d = asdict(self)
        # Attach the computed label so the frontend stays dumb.
        for dev_dict, dev in zip(d["devices"], self.devices):
            dev_dict["label"] = dev.label
        return d


# --------------------------------------------------------------------------- #
# Network topology of *this* host
# --------------------------------------------------------------------------- #

def _primary_ip() -> Optional[str]:
    """Local IP of the interface used to reach the internet (no traffic sent)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))  # UDP connect just sets the route; no packets.
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


def _enumerate_ipv4() -> list[tuple[str, ipaddress.IPv4Network]]:
    """All (ip, network) IPv4 candidates from `ifconfig`, in interface order.

    macOS reports the mask as hex (0xffffff00); Linux as a dotted quad. Both handled.
    Point-to-point/overlay interfaces (Tailscale, WireGuard, VPNs) typically present a
    /32 and are filtered out later by the LAN-selection logic.
    """
    try:
        out = subprocess.run(
            ["ifconfig"], capture_output=True, text=True, timeout=5
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return []

    candidates: list[tuple[str, ipaddress.IPv4Network]] = []
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("inet ") or "netmask" not in line:
            continue
        parts = line.split()
        try:
            ip = parts[1]
            mask = parts[parts.index("netmask") + 1]
        except (ValueError, IndexError):
            continue
        if mask.startswith("0x"):
            mask = str(ipaddress.IPv4Address(int(mask, 16)))
        try:
            net = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
        except ValueError:
            continue
        candidates.append((ip, net))
    return candidates


# 100.64.0.0/10 is CGNAT space used by Tailscale and carrier-grade NAT -- not a LAN.
_CGNAT = ipaddress.ip_network("100.64.0.0/10")


def _is_real_lan(ip: str, net: ipaddress.IPv4Network) -> bool:
    """A usable LAN candidate: private, routable subnet -- not loopback/VPN/link-local."""
    addr = ipaddress.ip_address(ip)
    return (
        addr.is_private
        and not addr.is_loopback
        and not addr.is_link_local
        and addr not in _CGNAT
        and net.prefixlen <= 30  # /31, /32 point-to-point links carry no host range
    )


def _default_gateway() -> Optional[str]:
    """Default gateway via `route` (macOS/BSD) or `ip route` (Linux)."""
    if sys.platform == "darwin":
        try:
            out = subprocess.run(
                ["route", "-n", "get", "default"],
                capture_output=True, text=True, timeout=5,
            ).stdout
            for line in out.splitlines():
                if "gateway:" in line:
                    return line.split(":", 1)[1].strip()
        except (OSError, subprocess.SubprocessError):
            return None
    else:
        try:
            out = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True, text=True, timeout=5,
            ).stdout
            m = re.search(r"default via (\S+)", out)
            if m:
                return m.group(1)
        except (OSError, subprocess.SubprocessError):
            return None
    return None


def _local_network() -> tuple[Optional[str], Optional[str], Optional[ipaddress.IPv4Network]]:
    """Return (self_ip, gateway_ip, network) for the real LAN to scan.

    Selection order:
      1. ``NDM_SUBNET`` env override (e.g. "192.168.1.0/24") -- explicit wins.
      2. The interface whose subnet contains the default gateway (strongest signal).
      3. The first private, non-VPN LAN candidate.
      4. Fallback: primary-IP heuristic as a /24.
    """
    gateway = _default_gateway()
    candidates = _enumerate_ipv4()
    lan = [(ip, net) for ip, net in candidates if _is_real_lan(ip, net)]

    # 1. Explicit override.
    override = os.environ.get("NDM_SUBNET")
    if override:
        try:
            net = ipaddress.ip_network(override, strict=False)
            self_ip = next((ip for ip, n in lan if ipaddress.ip_address(ip) in net), None)
            return self_ip, gateway, net
        except ValueError:
            logger.warning("Ignoring invalid NDM_SUBNET=%r", override)

    # 2. Interface that can actually reach the gateway.
    if gateway:
        gw = ipaddress.ip_address(gateway)
        for ip, net in lan:
            if gw in net:
                return ip, gateway, net

    # 3. First plausible private LAN.
    if lan:
        ip, net = lan[0]
        return ip, gateway, net

    # 4. Last resort.
    self_ip = _primary_ip()
    if self_ip:
        return self_ip, gateway, ipaddress.ip_network(f"{self_ip}/24", strict=False)
    return None, gateway, None


# --------------------------------------------------------------------------- #
# Sweep + ARP
# --------------------------------------------------------------------------- #

def _ping(ip: str) -> Optional[str]:
    """Send one ICMP echo. Returns the ip on reply, else None."""
    # -c 1: one packet. macOS/BSD use -t for total timeout (s); Linux uses -W (s).
    timeout_flag = "-t" if sys.platform == "darwin" else "-W"
    try:
        proc = subprocess.run(
            ["ping", "-c", "1", timeout_flag, "1", ip],
            capture_output=True,
            timeout=PING_TIMEOUT_S + 1.0,
        )
        return ip if proc.returncode == 0 else None
    except subprocess.TimeoutExpired:
        return None
    except OSError:
        return None


def _ping_sweep(hosts: list[str]) -> set[str]:
    alive: set[str] = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        for result in pool.map(_ping, hosts):
            if result:
                alive.add(result)
    return alive


def _arp_table() -> dict[str, str]:
    """IP -> MAC from the system ARP cache via `arp -an`."""
    mapping: dict[str, str] = {}
    try:
        out = subprocess.run(
            ["arp", "-an"], capture_output=True, text=True, timeout=5
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return mapping

    # Lines look like: `? (192.168.1.1) at a4:5e:60:... on en0 ifscope [ethernet]`
    for line in out.splitlines():
        ip_match = re.search(r"\(([\d.]+)\)", line)
        mac_match = _MAC_RE.search(line)
        if ip_match and mac_match:
            mac = _normalize_mac(mac_match.group(1))
            if mac != "00:00:00:00:00:00":  # incomplete entries
                mapping[ip_match.group(1)] = mac
    return mapping


def _normalize_mac(mac: str) -> str:
    parts = mac.lower().split(":")
    return ":".join(p.zfill(2) for p in parts)


# --------------------------------------------------------------------------- #
# Enrichment (best-effort, never fatal)
# --------------------------------------------------------------------------- #

def _hostname(ip: str) -> Optional[str]:
    try:
        name = socket.gethostbyaddr(ip)[0]
        return name.rstrip(".").removesuffix(".local")
    except (socket.herror, socket.gaierror, OSError):
        return None


def _vendor_lookup_factory():
    """Return a mac->vendor function. Uses mac_vendor_lookup if installed, else no-op."""
    try:
        from mac_vendor_lookup import MacLookup  # type: ignore

        lookup = MacLookup()
        try:
            lookup.load_vendors()  # use bundled/cached DB; no network call here
        except Exception:  # pragma: no cover - cache may be absent on first run
            pass

        def _lookup(mac: str) -> Optional[str]:
            try:
                return lookup.lookup(mac)
            except Exception:
                return None

        return _lookup
    except Exception:
        return lambda _mac: None


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #

def parse_target(spec: str) -> tuple[list[str], Optional[ipaddress.IPv4Network]]:
    """Parse a user-supplied target into (host_ips, network).

    Accepts:
      * CIDR            -> "192.168.1.0/24"
      * single IP       -> "10.0.0.5"
      * explicit range  -> "192.168.1.10-192.168.1.50"
      * shorthand range -> "192.168.1.10-50"  (end inherits the start's /24 prefix)

    Raises ValueError on malformed input or a range exceeding MAX_SCAN_HOSTS.
    """
    spec = spec.strip()
    if not spec:
        raise ValueError("Empty target.")

    # Dash range (not a CIDR).
    if "-" in spec and "/" not in spec:
        start_s, end_s = (p.strip() for p in spec.split("-", 1))
        start = ipaddress.ip_address(start_s)
        if "." not in end_s and ":" not in end_s:  # shorthand: reuse start's prefix
            end_s = f"{start_s.rsplit('.', 1)[0]}.{end_s}"
        end = ipaddress.ip_address(end_s)
        if int(end) < int(start):
            raise ValueError("Range end is before its start.")
        count = int(end) - int(start) + 1
        if count > MAX_SCAN_HOSTS:
            raise ValueError(f"Range too large ({count} hosts); max is {MAX_SCAN_HOSTS}.")
        hosts = [str(ipaddress.ip_address(i)) for i in range(int(start), int(end) + 1)]
        return hosts, None

    # CIDR or single address.
    net = ipaddress.ip_network(spec, strict=False)
    if net.num_addresses > MAX_SCAN_HOSTS:
        raise ValueError(
            f"Network too large ({net.num_addresses} hosts); max is {MAX_SCAN_HOSTS}."
        )
    if net.prefixlen >= 31:  # /31, /32 carry no usable host range
        return [str(net.network_address)], net
    return [str(h) for h in net.hosts()], net


def _is_on_link(network: Optional[ipaddress.IPv4Network]) -> bool:
    """True if `network` overlaps a directly-connected interface subnet (same L2).

    A directly-connected target is reachable by definition; if it's *not* on-link and
    nothing answers, we treat it as unreachable rather than "empty".
    """
    if network is None:
        return False
    for _ip, net in _enumerate_ipv4():
        if net.prefixlen <= 30 and network.overlaps(net):
            return True
    return False


def scan(target: Optional[str] = None) -> ScanResult:
    """Discover devices on the local subnet, or on an explicit `target` range.

    `target` accepts any form understood by :func:`parse_target`. When omitted,
    the primary LAN is auto-detected.
    """
    self_ip = _primary_ip()

    if target:
        hosts, network = parse_target(target)  # may raise ValueError
        gateway = None  # not our default route; inferred below if a .1 answers
        host_set = set(hosts)
    else:
        self_ip, gateway, network = _local_network()
        host_set = {str(h) for h in network.hosts()} if network else set()

    result = ScanResult(
        gateway_ip=gateway,
        self_ip=self_ip,
        network_cidr=str(network) if network else (target or None),
    )
    if not host_set:
        logger.warning("No hosts to scan (target=%r); aborting.", target)
        return result

    logger.info("Sweeping %d hosts (%s)", len(host_set), result.network_cidr)
    alive = _ping_sweep(sorted(host_set, key=lambda x: ipaddress.ip_address(x)))

    arp = _arp_table()
    # Union of ping replies and ARP entries: some devices answer ARP but drop ICMP.
    discovered_ips = (alive | set(arp)) & host_set
    if self_ip and self_ip in host_set:  # only when our own IP is within the target
        discovered_ips.add(self_ip)

    # The default route may exit a different interface (VPN/overlay) than the subnet we
    # scanned, leaving gateway unknown. Fall back to the conventional first host (.1)
    # when it was actually discovered, so the topology has a real hub. Only meaningful
    # for CIDR-shaped targets (a dash-range has no canonical network address).
    if network and (not gateway or gateway not in host_set) and discovered_ips:
        first_host = str(next(network.hosts()))
        if first_host in discovered_ips:
            gateway = first_host
            result.gateway_ip = gateway
            logger.info("Gateway not on default route; inferred gateway %s", gateway)

    vendor_of = _vendor_lookup_factory()
    devices: list[Device] = []
    for ip in sorted(discovered_ips, key=lambda x: ipaddress.ip_address(x)):
        mac = arp.get(ip)
        dev = Device(
            ip=ip,
            mac=mac,
            hostname=_hostname(ip),
            vendor=vendor_of(mac) if mac else None,
            is_gateway=(ip == gateway),
            is_self=(ip == self_ip),
        )
        devices.append(dev)

    result.devices = devices

    # Distinguish "reachable but empty" from "unreachable". A directly-connected
    # subnet (or the auto-detected local LAN) that returns nothing is simply empty;
    # an off-link target that returns nothing has no route from this host.
    if not devices:
        on_link = (target is None) or _is_on_link(network)
        if on_link:
            result.note = f"No devices responded on {result.network_cidr}."
        else:
            result.reachable = False
            result.note = (
                f"{result.network_cidr} appears unreachable from this host "
                f"(no route, or no devices responded)."
            )

    logger.info(
        "Discovered %d devices (reachable=%s)", len(devices), result.reachable
    )
    return result


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    target_arg = sys.argv[1] if len(sys.argv) > 1 else None
    res = scan(target_arg)
    print(f"\nNetwork: {res.network_cidr}  Gateway: {res.gateway_ip}")
    print(f"Reachable: {res.reachable}" + (f"  ({res.note})" if res.note else "") + "\n")
    for d in res.devices:
        tags = " ".join(t for t in ("gateway" if d.is_gateway else "",
                                    "self" if d.is_self else "") if t)
        print(f"  {d.ip:<15} {d.label:<28} {d.mac or '':<18} {tags}")
