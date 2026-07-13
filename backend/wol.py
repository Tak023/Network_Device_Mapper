"""Wake-on-LAN: send a standard magic packet to a sleeping device.

The magic packet is 6 bytes of 0xFF followed by the target MAC repeated 16
times, broadcast over UDP (conventionally port 9, "discard"). The NIC itself
listens for the pattern while the host sleeps — no cooperation from the OS
needed, but WoL must be enabled in the device's firmware/OS settings.
"""

from __future__ import annotations

import logging
import re
import socket

logger = logging.getLogger("wol")

_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")

BROADCAST = "255.255.255.255"
PORT = 9
REPEATS = 3  # UDP broadcast is fire-and-forget; a few copies cost nothing


def magic_packet(mac: str) -> bytes:
    """Build the 102-byte magic packet for `mac` (colon or dash separated)."""
    mac = mac.strip()
    if not _MAC_RE.match(mac):
        raise ValueError(f"Invalid MAC address: {mac!r}")
    raw = bytes.fromhex(mac.replace(":", "").replace("-", ""))
    return b"\xff" * 6 + raw * 16


def _broadcast_addresses() -> list[str]:
    """Subnet-directed broadcasts for each LAN, then the global broadcast.

    macOS (and some multi-homed Linux hosts) rejects 255.255.255.255 with
    EADDRNOTAVAIL unless the socket is bound to a specific interface; the
    subnet broadcast (e.g. 10.1.1.255) routes fine — so we try those first.
    """
    addrs: list[str] = []
    try:
        from . import discovery

        for ip, net in discovery._enumerate_ipv4():
            if discovery._is_real_lan(ip, net):
                addrs.append(str(net.broadcast_address))
    except Exception:  # enumeration is best-effort; global broadcast remains
        pass
    addrs.append(BROADCAST)
    return list(dict.fromkeys(addrs))  # dedupe, keep order


def wake(mac: str) -> None:
    """Broadcast the magic packet on every LAN. Raises ValueError on a bad MAC,
    OSError if no destination accepted the send."""
    packet = magic_packet(mac)
    sent: list[str] = []
    errors: list[str] = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        for dest in _broadcast_addresses():
            try:
                for _ in range(REPEATS):
                    sock.sendto(packet, (dest, PORT))
                sent.append(dest)
            except OSError as exc:
                errors.append(f"{dest}: {exc}")
    if not sent:
        raise OSError("; ".join(errors) or "no broadcast route available")
    logger.info("Sent WoL magic packet for %s via %s", mac, ", ".join(sent))


if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    if len(sys.argv) != 2:
        print("Usage: python3 -m backend.wol <mac>")
        raise SystemExit(1)
    wake(sys.argv[1])
