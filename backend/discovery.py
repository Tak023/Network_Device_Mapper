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
from collections.abc import Callable
from dataclasses import asdict, dataclass, field

logger = logging.getLogger("discovery")

# Optional progress callback: (phase, done, total). Phases: "sweep", "enrich",
# "topology". `done`/`total` are None for phases without a meaningful count.
ProgressFn = Callable[[str, int | None, int | None], None]

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
    mac: str | None = None
    hostname: str | None = None
    vendor: str | None = None
    latency_ms: float | None = None  # ICMP round-trip; None if ARP-only discovery
    is_gateway: bool = False
    is_self: bool = False
    # Physical topology (populated from UniFi when available).
    uplink_mac: str | None = None   # MAC of the device this connects up to
    role: str | None = None         # gateway | switch | ap | client
    unifi_name: str | None = None   # controller-assigned name (e.g. "Office Switch")

    @property
    def label(self) -> str:
        """Best human-readable name for a node/table row."""
        if self.unifi_name:
            return self.unifi_name
        if self.hostname:
            return self.hostname
        if self.vendor:
            return f"{self.vendor} device"
        return self.ip


@dataclass
class ScanResult:
    gateway_ip: str | None
    self_ip: str | None
    network_cidr: str | None
    devices: list[Device] = field(default_factory=list)
    reachable: bool = True          # False == no route / network appears unreachable
    note: str | None = None      # human-readable status for the UI
    topology_source: str = "l3-star"  # "unifi" when real L2 adjacency is available

    def to_dict(self) -> dict:
        d = asdict(self)
        # Attach the computed label so the frontend stays dumb.
        for dev_dict, dev in zip(d["devices"], self.devices, strict=True):
            dev_dict["label"] = dev.label
        return d


# --------------------------------------------------------------------------- #
# Network topology of *this* host
# --------------------------------------------------------------------------- #

def _primary_ip() -> str | None:
    """Local IP of the interface used to reach the internet (no traffic sent)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))  # UDP connect just sets the route; no packets.
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


def _run_first(*commands: list[str], timeout: int = 5) -> str | None:
    """Run commands in order; return the first non-empty stdout, else None.

    Lets us prefer the traditional tool but fall back where it's absent
    (`ifconfig`/`arp` are net-tools, not installed on modern Linux distros).
    """
    for cmd in commands:
        try:
            out = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout
            ).stdout
        except (OSError, subprocess.SubprocessError):
            continue
        if out and out.strip():
            return out
    return None


def _parse_ifconfig(out: str) -> list[tuple[str, ipaddress.IPv4Network]]:
    """Parse `ifconfig` output into (ip, network) candidates.

    macOS reports the mask as hex (0xffffff00); Linux as a dotted quad. Both handled.
    """
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


_IP_ADDR_RE = re.compile(r"\binet ([\d.]+)/(\d+)")


def _parse_ip_addr(out: str) -> list[tuple[str, ipaddress.IPv4Network]]:
    """Parse `ip -4 -o addr` output (`2: eth0    inet 192.168.1.5/24 brd ...`)."""
    candidates: list[tuple[str, ipaddress.IPv4Network]] = []
    for m in _IP_ADDR_RE.finditer(out):
        try:
            net = ipaddress.ip_network(f"{m.group(1)}/{m.group(2)}", strict=False)
        except ValueError:
            continue
        candidates.append((m.group(1), net))
    return candidates


def _enumerate_ipv4() -> list[tuple[str, ipaddress.IPv4Network]]:
    """All (ip, network) IPv4 candidates, in interface order.

    Tries `ifconfig` (macOS/BSD, Linux with net-tools) then `ip -4 -o addr`
    (iproute2, the default on modern Linux). Point-to-point/overlay interfaces
    (Tailscale, WireGuard, VPNs) typically present a /32 and are filtered out
    later by the LAN-selection logic.
    """
    out = _run_first(["ifconfig"])
    if out:
        parsed = _parse_ifconfig(out)
        if parsed:
            return parsed
    out = _run_first(["ip", "-4", "-o", "addr"])
    return _parse_ip_addr(out) if out else []


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


def _default_gateway() -> str | None:
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


def _local_network() -> tuple[str | None, str | None, ipaddress.IPv4Network | None]:
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

# `64 bytes from 10.1.1.1: icmp_seq=0 ttl=64 time=1.234 ms` (macOS and Linux)
_PING_TIME_RE = re.compile(r"time[=<]\s*([\d.]+)\s*ms")


def _extract_latency(output: str) -> float | None:
    m = _PING_TIME_RE.search(output)
    return float(m.group(1)) if m else None


def _ping(ip: str) -> tuple[str, float | None] | None:
    """Send one ICMP echo. Returns (ip, latency_ms) on reply, else None.

    Latency comes from ping's own `time=` report, not our subprocess wall time —
    process spawn adds 10-30ms of noise that would swamp LAN round-trips.
    """
    # -c 1: one packet. macOS/BSD use -t for total timeout (s); Linux uses -W (s).
    timeout_flag = "-t" if sys.platform == "darwin" else "-W"
    try:
        proc = subprocess.run(
            ["ping", "-c", "1", timeout_flag, "1", ip],
            capture_output=True,
            timeout=PING_TIMEOUT_S + 1.0,
        )
        if proc.returncode != 0:
            return None
        return ip, _extract_latency(proc.stdout.decode("utf-8", errors="replace"))
    except subprocess.TimeoutExpired:
        return None
    except OSError:
        return None


def _ping_sweep(
    hosts: list[str], progress: ProgressFn | None = None
) -> dict[str, float | None]:
    """{ip: latency_ms} for every host that answered ICMP."""
    alive: dict[str, float | None] = {}
    total = len(hosts)
    done = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        for result in pool.map(_ping, hosts):
            done += 1
            if result:
                alive[result[0]] = result[1]
            # Every ~5% is plenty for a UI; avoids thousands of callbacks on a /20.
            if progress and (done % max(1, total // 20) == 0 or done == total):
                progress("sweep", done, total)
    return alive


def _parse_neighbors(out: str) -> dict[str, str]:
    """IP -> MAC from neighbor-table output; handles both known formats:

      arp -an:    `? (192.168.1.1) at a4:5e:60:... on en0 ifscope [ethernet]`
      ip neigh:   `192.168.1.1 dev eth0 lladdr a4:5e:60:... REACHABLE`
    """
    mapping: dict[str, str] = {}
    for line in out.splitlines():
        line = line.strip()
        ip_match = re.search(r"\(([\d.]+)\)", line) or re.match(r"([\d.]+)\s", line)
        mac_match = _MAC_RE.search(line)
        if ip_match and mac_match:
            mac = _normalize_mac(mac_match.group(1))
            if mac != "00:00:00:00:00:00":  # incomplete entries
                mapping[ip_match.group(1)] = mac
    return mapping


def _arp_table() -> dict[str, str]:
    """IP -> MAC from the system neighbor cache.

    `arp -an` first (macOS/BSD, Linux net-tools), then `ip neigh show` (iproute2 —
    the only one present on most modern Linux distros).
    """
    out = _run_first(["arp", "-an"], ["ip", "neigh", "show"])
    return _parse_neighbors(out) if out else {}


def _normalize_mac(mac: str) -> str:
    parts = mac.lower().split(":")
    return ":".join(p.zfill(2) for p in parts)


# --------------------------------------------------------------------------- #
# Enrichment (best-effort, never fatal)
# --------------------------------------------------------------------------- #

def _hostname(ip: str) -> str | None:
    try:
        name = socket.gethostbyaddr(ip)[0]
        return name.rstrip(".").removesuffix(".local")
    except (socket.herror, socket.gaierror, OSError):
        return None


def _resolve_hostnames(
    ips: list[str], progress: ProgressFn | None = None
) -> dict[str, str]:
    """Best-effort name resolution for many IPs: parallel reverse-DNS, then one
    batched mDNS query for whatever DNS couldn't name.

    Parallelism matters: `gethostbyaddr` on an IP with no PTR record blocks for the
    full resolver timeout (often ~5s), so resolving 40 devices serially could add
    minutes to a scan that swept the subnet in seconds.
    """
    names: dict[str, str] = {}
    total = len(ips)
    done = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
        for ip, name in zip(ips, pool.map(_hostname, ips), strict=True):
            done += 1
            if name:
                names[ip] = name
            if progress and (done % max(1, total // 10) == 0 or done == total):
                progress("enrich", done, total)

    # mDNS/Bonjour picks up Apple/IoT devices that never register PTR records.
    unresolved = [ip for ip in ips if ip not in names]
    if unresolved:
        try:
            from . import mdns
            names.update(mdns.reverse_lookup(unresolved))
        except Exception:  # best-effort, never fatal
            logger.debug("mDNS lookup failed", exc_info=True)
    return names


def _vendor_lookup_factory():
    """Return a mac->vendor function. Uses mac_vendor_lookup if installed, else no-op."""
    try:
        from mac_vendor_lookup import MacLookup  # type: ignore

        lookup = MacLookup()
        try:
            lookup.load_vendors()  # use bundled/cached DB; no network call here
        except Exception:  # pragma: no cover - cache may be absent on first run
            pass

        def _lookup(mac: str) -> str | None:
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

def parse_target(spec: str) -> tuple[list[str], ipaddress.IPv4Network | None]:
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


def _is_on_link(network: ipaddress.IPv4Network | None) -> bool:
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


def _apply_topology(devices: list[Device], result: ScanResult) -> None:
    """Overlay real L2 adjacency from a topology provider (SNMP/UniFi), in place.

    - Matches discovered devices to provider nodes by MAC and sets uplink_mac/role/name.
    - Adds infra (switches/APs/gateway) the ping sweep missed, so a device's parent
      always exists in the graph.
    - Leaves everything untouched (L3-star fallback) when no provider is configured.
    """
    try:
        from . import topology
    except ImportError:
        return

    device_macs = {d.ip: d.mac for d in devices if d.mac and d.ip}
    nodes, source = topology.fetch_topology(device_macs, result.gateway_ip)
    if not nodes:
        return

    by_mac = {d.mac.lower(): d for d in devices if d.mac}

    # 1. Enrich discovered devices.
    for mac, node in nodes.items():
        dev = by_mac.get(mac)
        if dev:
            dev.uplink_mac = node.uplink_mac
            dev.role = node.role
            if node.name:
                dev.unifi_name = node.name
            if node.role == "gateway":
                dev.is_gateway = True

    # 2. Add infra nodes the sweep didn't find (e.g. an AP on another VLAN), so a
    #    device's parent always exists in the graph.
    referenced = {n.uplink_mac for n in nodes.values() if n.uplink_mac}
    present = set(by_mac)
    for mac, node in nodes.items():
        need = node.is_infra or mac in referenced
        if need and mac not in present:
            devices.append(Device(
                ip=node.ip or mac,
                mac=mac,
                role=node.role,
                uplink_mac=node.uplink_mac,
                unifi_name=node.name,
                is_gateway=(node.role == "gateway"),
            ))
            present.add(mac)

    result.topology_source = source
    if result.gateway_ip is None:
        gw = next((n for n in nodes.values() if n.role == "gateway" and n.ip), None)
        if gw:
            result.gateway_ip = gw.ip


def scan(
    target: str | None = None, progress: ProgressFn | None = None
) -> ScanResult:
    """Discover devices on the local subnet, or on an explicit `target` range.

    `target` accepts any form understood by :func:`parse_target`. When omitted,
    the primary LAN is auto-detected. `progress`, if given, is called with
    (phase, done, total) as the scan advances — used by the server's SSE stream.
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
    alive = _ping_sweep(
        sorted(host_set, key=lambda x: ipaddress.ip_address(x)), progress
    )

    arp = _arp_table()
    # Union of ping replies and ARP entries: some devices answer ARP but drop ICMP.
    discovered_ips = (set(alive) | set(arp)) & host_set
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

    ordered_ips = sorted(discovered_ips, key=lambda x: ipaddress.ip_address(x))
    hostnames = _resolve_hostnames(ordered_ips, progress)

    vendor_of = _vendor_lookup_factory()
    devices: list[Device] = []
    for ip in ordered_ips:
        mac = arp.get(ip)
        dev = Device(
            ip=ip,
            mac=mac,
            hostname=hostnames.get(ip),
            vendor=vendor_of(mac) if mac else None,
            latency_ms=alive.get(ip),
            is_gateway=(ip == gateway),
            is_self=(ip == self_ip),
        )
        devices.append(dev)

    # Enrich with real Layer-2 topology from a provider (SNMP/UniFi), if configured.
    if progress:
        progress("topology", None, None)
    _apply_topology(devices, result)

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
