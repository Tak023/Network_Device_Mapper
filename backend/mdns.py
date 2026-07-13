"""Reverse mDNS (Bonjour) lookups, dependency-free.

Many home/IoT devices (Apple gear especially) never register PTR records with the
router's DNS, so reverse-DNS can't name them — but they *do* answer multicast DNS on
the local link. This module sends reverse PTR queries (`d.c.b.a.in-addr.arpa`) to the
mDNS multicast group and collects whatever answers within a short window.

Pure sockets + hand-rolled DNS encode/decode (the packets involved are tiny), so no
extra dependency. Strictly best-effort and link-local: off-subnet IPs simply never
answer and cost nothing beyond the shared wait window.
"""

from __future__ import annotations

import logging
import socket
import struct
import time

logger = logging.getLogger("mdns")

MDNS_ADDR = "224.0.0.251"
MDNS_PORT = 5353
TYPE_PTR = 12
CLASS_IN = 1
UNICAST_RESPONSE = 0x8000  # "QU" bit: please reply unicast to the querier


def _encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        raw = label.encode("ascii")
        out += struct.pack("B", len(raw)) + raw
    return out + b"\x00"


def _ptr_name(ip: str) -> str:
    return ".".join(reversed(ip.split("."))) + ".in-addr.arpa"


def _build_query(ip: str) -> bytes:
    # Header: id=0 (mDNS convention), no flags, one question.
    header = struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0)
    question = _encode_name(_ptr_name(ip)) + struct.pack(
        ">HH", TYPE_PTR, CLASS_IN | UNICAST_RESPONSE
    )
    return header + question


def _decode_name(data: bytes, offset: int, depth: int = 0) -> tuple[str, int]:
    """Decode a (possibly compressed) DNS name. Returns (name, next_offset)."""
    if depth > 10:  # compression-loop guard
        raise ValueError("DNS name compression too deep")
    labels: list[str] = []
    while True:
        if offset >= len(data):
            raise ValueError("Truncated DNS name")
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:  # compression pointer
            if offset + 1 >= len(data):
                raise ValueError("Truncated compression pointer")
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            suffix, _ = _decode_name(data, pointer, depth + 1)
            if suffix:
                labels.append(suffix)
            offset += 2
            break
        offset += 1
        labels.append(data[offset : offset + length].decode("ascii", errors="replace"))
        offset += length
    return ".".join(labels), offset


def _parse_ptr_answers(data: bytes) -> dict[str, str]:
    """Extract {question_name_lower: target_name} for PTR answers in a response."""
    out: dict[str, str] = {}
    try:
        _id, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", data[:12])
        if not flags & 0x8000:  # not a response
            return out
        offset = 12
        for _ in range(qd):  # skip questions
            _, offset = _decode_name(data, offset)
            offset += 4
        for _ in range(an + ns + ar):
            name, offset = _decode_name(data, offset)
            rtype, rclass, _ttl, rdlen = struct.unpack(
                ">HHIH", data[offset : offset + 10]
            )
            offset += 10
            if rtype == TYPE_PTR:
                target, _ = _decode_name(data, offset)
                out[name.lower()] = target
            offset += rdlen
    except (ValueError, struct.error):
        pass  # malformed/truncated packet — ignore it entirely
    return out


def reverse_lookup(ips: list[str], timeout: float = 1.5) -> dict[str, str]:
    """Resolve IPs to mDNS hostnames. Returns {ip: name} for whatever answered.

    All queries go out at once from a single socket; then we listen for `timeout`
    seconds total, so the cost is one flat wait regardless of how many IPs.
    """
    if not ips:
        return {}
    want = {_ptr_name(ip).lower(): ip for ip in ips}
    names: dict[str, str] = {}

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        sock.settimeout(0.2)
        for ip in ips:
            try:
                sock.sendto(_build_query(ip), (MDNS_ADDR, MDNS_PORT))
            except OSError:
                return names  # no multicast route (e.g. VPN-only host)

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline and len(names) < len(ips):
            try:
                data, _addr = sock.recvfrom(4096)
            except TimeoutError:
                continue
            except OSError:
                break
            for qname, target in _parse_ptr_answers(data).items():
                ip = want.get(qname)
                if ip and ip not in names:
                    names[ip] = _clean(target)
    finally:
        sock.close()

    if names:
        logger.info("mDNS named %d of %d unresolved device(s)", len(names), len(ips))
    return names


def _clean(name: str) -> str | None:
    return name.rstrip(".").removesuffix(".local") or None


if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    targets = sys.argv[1:]
    if not targets:
        print("Usage: python3 -m backend.mdns <ip> [ip...]")
        raise SystemExit(1)
    for ip, name in reverse_lookup(targets).items():
        print(f"  {ip:<15} {name}")
