"""parse_target: every accepted format plus the guard rails."""

import pytest

from backend.discovery import MAX_SCAN_HOSTS, parse_target


def test_cidr():
    hosts, net = parse_target("192.168.1.0/30")
    assert hosts == ["192.168.1.1", "192.168.1.2"]
    assert str(net) == "192.168.1.0/30"


def test_single_ip():
    hosts, net = parse_target("10.0.0.5")
    assert hosts == ["10.0.0.5"]
    assert str(net) == "10.0.0.5/32"


def test_explicit_range():
    hosts, net = parse_target("192.168.1.10-192.168.1.12")
    assert hosts == ["192.168.1.10", "192.168.1.11", "192.168.1.12"]
    assert net is None


def test_shorthand_range():
    hosts, _ = parse_target("192.168.1.10-12")
    assert hosts == ["192.168.1.10", "192.168.1.11", "192.168.1.12"]


def test_range_spanning_octets():
    hosts, _ = parse_target("10.0.0.254-10.0.1.1")
    assert hosts == ["10.0.0.254", "10.0.0.255", "10.0.1.0", "10.0.1.1"]


def test_whitespace_tolerated():
    hosts, _ = parse_target("  192.168.1.10 - 12 ")
    assert len(hosts) == 3


def test_reversed_range_rejected():
    with pytest.raises(ValueError, match="before its start"):
        parse_target("192.168.1.50-192.168.1.10")


def test_oversized_cidr_rejected():
    with pytest.raises(ValueError, match="too large"):
        parse_target("10.0.0.0/8")


def test_oversized_range_rejected():
    with pytest.raises(ValueError, match="too large"):
        parse_target("10.0.0.0-10.1.0.0")


def test_max_size_cidr_allowed():
    hosts, _ = parse_target("10.0.0.0/20")  # 4096 addresses == the cap
    assert len(hosts) == MAX_SCAN_HOSTS - 2  # minus network + broadcast


def test_empty_rejected():
    with pytest.raises(ValueError, match="Empty"):
        parse_target("   ")


def test_garbage_rejected():
    with pytest.raises(ValueError):
        parse_target("not-an-ip")
