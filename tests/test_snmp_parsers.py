"""SNMP value parsing + the FDB/LLDP correlation that builds the topology tree."""

from backend.snmp import (
    _build_nodes,
    _cap_octet,
    _mac_from_oid_octets,
    _mac_from_value,
    _Switch,
)


def test_mac_from_hex_string_variants():
    assert _mac_from_value("A4 5E 60 AA BB CC") == "a4:5e:60:aa:bb:cc"
    assert _mac_from_value("a4:5e:60:aa:bb:cc") == "a4:5e:60:aa:bb:cc"
    assert _mac_from_value('"A4 5E 60 AA BB CC "') == "a4:5e:60:aa:bb:cc"
    assert _mac_from_value("not a mac") is None


def test_mac_from_fdb_oid_octets():
    # dot1qTpFdbPort index: <vlan>.<6 decimal MAC octets> — MAC is the last 6.
    assert _mac_from_oid_octets(["1", "164", "94", "96", "170", "187", "204"]) == "a4:5e:60:aa:bb:cc"
    assert _mac_from_oid_octets(["164", "94"]) is None
    assert _mac_from_oid_octets(["1", "x", "0", "0", "0", "0", "0"]) is None


def test_cap_octet_ors_all_octets():
    assert _cap_octet("28 00") == 0x28          # capability byte first
    assert _cap_octet("00 28") == 0x28          # ...or second (vendor-dependent)
    assert _cap_octet(None) == 0
    assert _cap_octet("zz") == 0
    assert bool(_cap_octet("20 00") & 0x38)     # bridge counts as infra


def _gateway_and_switch():
    """Fixture: gateway <-> switch on port 1, one client on switch port 5."""
    gw = _Switch(ip="10.0.0.1", mac="aa:00:00:00:00:01", name="gw",
                 chassis_id="aa:00:00:00:00:01")
    sw = _Switch(ip="10.0.0.2", mac="aa:00:00:00:00:02", name="sw1",
                 chassis_id="aa:00:00:00:00:02")
    sw.neighbors["1"] = {"chassis": "aa:00:00:00:00:01", "sysname": "gw",
                         "port": "3", "infra": True, "ap": False}
    sw.port_ifindex = {"1": "1", "5": "5"}
    sw.fdb = {
        "bb:00:00:00:00:10": "5",  # client on an edge port
        "bb:00:00:00:00:11": "1",  # MAC learned on the uplink -> must be skipped
    }
    return gw, sw


def test_build_nodes_tree():
    gw, sw = _gateway_and_switch()
    nodes = _build_nodes([gw, sw], gateway_ip="10.0.0.1")

    assert nodes["aa:00:00:00:00:01"].role == "gateway"
    assert nodes["aa:00:00:00:00:01"].uplink_mac is None

    assert nodes["aa:00:00:00:00:02"].role == "switch"
    assert nodes["aa:00:00:00:00:02"].uplink_mac == "aa:00:00:00:00:01"

    client = nodes["bb:00:00:00:00:10"]
    assert client.role == "client"
    assert client.uplink_mac == "aa:00:00:00:00:02"
    assert client.port == "5"

    # The MAC seen on the uplink port belongs upstream — not attached to this switch.
    assert "bb:00:00:00:00:11" not in nodes


def test_build_nodes_client_deduped_to_closest_switch():
    gw, sw = _gateway_and_switch()
    # The gateway also "sees" the client (plus lots of others) through its port to
    # the switch; fewest-MACs-on-port must win, attaching it to the edge switch.
    gw.port_ifindex = {"3": "3"}
    gw.fdb = {
        "bb:00:00:00:00:10": "3",
        "bb:00:00:00:00:99": "3",
        "aa:00:00:00:00:02": "3",
    }
    nodes = _build_nodes([gw, sw], gateway_ip="10.0.0.1")
    assert nodes["bb:00:00:00:00:10"].uplink_mac == "aa:00:00:00:00:02"
