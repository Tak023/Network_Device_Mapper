"""Wake-on-LAN magic packet construction (pure function; no sockets)."""

import pytest

from backend.wol import magic_packet


def test_packet_structure():
    pkt = magic_packet("a4:5e:60:aa:bb:cc")
    assert len(pkt) == 102
    assert pkt[:6] == b"\xff" * 6
    mac_bytes = bytes.fromhex("a45e60aabbcc")
    assert pkt[6:] == mac_bytes * 16


def test_dash_separator_and_case():
    assert magic_packet("A4-5E-60-AA-BB-CC") == magic_packet("a4:5e:60:aa:bb:cc")


def test_whitespace_tolerated():
    assert magic_packet("  a4:5e:60:aa:bb:cc ") == magic_packet("a4:5e:60:aa:bb:cc")


@pytest.mark.parametrize("bad", [
    "", "not-a-mac", "a4:5e:60:aa:bb", "a4:5e:60:aa:bb:cc:dd",
    "g4:5e:60:aa:bb:cc", "a45e60aabbcc",
])
def test_invalid_mac_rejected(bad):
    with pytest.raises(ValueError):
        magic_packet(bad)
