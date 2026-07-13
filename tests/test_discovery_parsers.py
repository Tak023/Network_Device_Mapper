"""Output parsers for the system tools discovery shells out to.

These formats vary by OS (and by which of net-tools/iproute2 is installed), so we
pin fixtures for each one we claim to support.
"""

from backend.discovery import (
    _is_real_lan,
    _normalize_mac,
    _parse_ifconfig,
    _parse_ip_addr,
    _parse_neighbors,
)

MACOS_IFCONFIG = """\
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
	inet 127.0.0.1 netmask 0xff000000
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	inet 192.168.1.23 netmask 0xffffff00 broadcast 192.168.1.255
utun4: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1280
	inet 100.101.102.103 netmask 0xffffffff
"""

LINUX_IFCONFIG = """\
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.1.2.3  netmask 255.255.252.0  broadcast 10.1.3.255
lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
"""

LINUX_IP_ADDR = """\
1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever
2: eth0    inet 10.1.2.3/22 brd 10.1.3.255 scope global dynamic eth0\\       valid_lft 60s preferred_lft 60s
3: wg0    inet 100.64.0.7/32 scope global wg0\\       valid_lft forever preferred_lft forever
"""

MACOS_ARP = """\
? (192.168.1.1) at a4:5e:60:aa:bb:cc on en0 ifscope [ethernet]
? (192.168.1.50) at 0:11:22:3:44:5 on en0 ifscope [ethernet]
? (192.168.1.99) at (incomplete) on en0 ifscope [ethernet]
? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]
"""

LINUX_IP_NEIGH = """\
192.168.1.1 dev eth0 lladdr a4:5e:60:aa:bb:cc REACHABLE
192.168.1.50 dev eth0 lladdr 00:11:22:03:44:05 STALE
192.168.1.99 dev eth0  FAILED
fe80::1 dev eth0 lladdr a4:5e:60:aa:bb:cc router REACHABLE
"""


def test_parse_ifconfig_macos_hex_masks():
    got = {(ip, str(net)) for ip, net in _parse_ifconfig(MACOS_IFCONFIG)}
    assert ("192.168.1.23", "192.168.1.0/24") in got
    assert ("127.0.0.1", "127.0.0.0/8") in got
    assert ("100.101.102.103", "100.101.102.103/32") in got  # filtered later, parsed here


def test_parse_ifconfig_linux_dotted_masks():
    got = {(ip, str(net)) for ip, net in _parse_ifconfig(LINUX_IFCONFIG)}
    assert ("10.1.2.3", "10.1.0.0/22") in got


def test_parse_ip_addr():
    got = {(ip, str(net)) for ip, net in _parse_ip_addr(LINUX_IP_ADDR)}
    assert ("10.1.2.3", "10.1.0.0/22") in got
    assert ("100.64.0.7", "100.64.0.7/32") in got


def test_lan_filter_rejects_loopback_vpn_cgnat():
    for out, parse in ((MACOS_IFCONFIG, _parse_ifconfig), (LINUX_IP_ADDR, _parse_ip_addr)):
        lan = [(ip, net) for ip, net in parse(out) if _is_real_lan(ip, net)]
        ips = {ip for ip, _ in lan}
        assert "127.0.0.1" not in ips
        assert not any(ip.startswith("100.") for ip in ips)  # CGNAT/Tailscale/WireGuard


def test_parse_neighbors_arp_format():
    mapping = _parse_neighbors(MACOS_ARP)
    assert mapping["192.168.1.1"] == "a4:5e:60:aa:bb:cc"
    assert mapping["192.168.1.50"] == "00:11:22:03:44:05"  # short octets zero-padded
    assert "192.168.1.99" not in mapping  # incomplete entry


def test_parse_neighbors_ip_neigh_format():
    mapping = _parse_neighbors(LINUX_IP_NEIGH)
    assert mapping["192.168.1.1"] == "a4:5e:60:aa:bb:cc"
    assert mapping["192.168.1.50"] == "00:11:22:03:44:05"
    assert "192.168.1.99" not in mapping  # FAILED entry has no lladdr


def test_normalize_mac_pads_octets():
    assert _normalize_mac("0:1:2:A:BB:C") == "00:01:02:0a:bb:0c"
