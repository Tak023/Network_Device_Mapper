"""Scan history: first_seen/is_new annotation and missing-device diffing."""

from backend import history


def _scan(devices):
    return {"network_cidr": "192.168.1.0/24", "devices": devices}


def _dev(ip, mac=None, label=None):
    return {"ip": ip, "mac": mac, "label": label or ip}


def test_first_scan_marks_everything_new(tmp_path, monkeypatch):
    monkeypatch.setenv("NDM_DB", str(tmp_path / "h.db"))
    data = _scan([_dev("192.168.1.1", "aa:aa:aa:aa:aa:01"), _dev("192.168.1.2")])
    history.annotate(data)
    assert all(d["is_new"] for d in data["devices"])
    assert all("first_seen" in d for d in data["devices"])
    assert data["missing_devices"] == []


def test_second_scan_detects_known_and_missing(tmp_path, monkeypatch):
    monkeypatch.setenv("NDM_DB", str(tmp_path / "h.db"))
    history.annotate(_scan([
        _dev("192.168.1.1", "aa:aa:aa:aa:aa:01", "router"),
        _dev("192.168.1.50", "aa:aa:aa:aa:aa:50", "printer"),
    ]))

    data = _scan([
        _dev("192.168.1.1", "aa:aa:aa:aa:aa:01", "router"),   # still here
        _dev("192.168.1.60", "aa:aa:aa:aa:aa:60", "new-phone"),  # newcomer
    ])
    history.annotate(data)

    by_ip = {d["ip"]: d for d in data["devices"]}
    assert by_ip["192.168.1.1"]["is_new"] is False
    assert by_ip["192.168.1.60"]["is_new"] is True
    assert [m["label"] for m in data["missing_devices"]] == ["printer"]


def test_mac_identity_survives_dhcp_renumbering(tmp_path, monkeypatch):
    monkeypatch.setenv("NDM_DB", str(tmp_path / "h.db"))
    history.annotate(_scan([_dev("192.168.1.50", "aa:aa:aa:aa:aa:50", "laptop")]))

    data = _scan([_dev("192.168.1.77", "aa:aa:aa:aa:aa:50", "laptop")])  # new lease
    history.annotate(data)
    assert data["devices"][0]["is_new"] is False
    assert data["missing_devices"] == []


def test_networks_are_isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("NDM_DB", str(tmp_path / "h.db"))
    history.annotate(_scan([_dev("192.168.1.1", "aa:aa:aa:aa:aa:01", "router")]))

    other = {"network_cidr": "10.0.0.0/24", "devices": [_dev("10.0.0.1")]}
    history.annotate(other)
    assert other["missing_devices"] == []  # 192.168.1.1 isn't "missing" from 10.0.0.0/24


def test_disabled_via_env(tmp_path, monkeypatch):
    monkeypatch.setenv("NDM_DB", "off")
    data = _scan([_dev("192.168.1.1")])
    history.annotate(data)
    assert "is_new" not in data["devices"][0]
    assert "missing_devices" not in data


def test_custom_name_overrides_label(tmp_path, monkeypatch):
    monkeypatch.setenv("NDM_DB", str(tmp_path / "h.db"))
    assert history.set_meta("aa:aa:aa:aa:aa:50", "Living Room TV", "on the credenza")

    data = _scan([_dev("192.168.1.50", "AA:AA:AA:AA:AA:50", "Samsung device")])
    history.annotate(data)
    dev = data["devices"][0]
    assert dev["label"] == "Living Room TV"
    assert dev["custom_name"] == "Living Room TV"
    assert dev["notes"] == "on the credenza"

    # The stored history label carries the custom name into the missing-list.
    data2 = _scan([_dev("192.168.1.1", "aa:aa:aa:aa:aa:01")])
    history.annotate(data2)
    assert [m["label"] for m in data2["missing_devices"]] == ["Living Room TV"]


def test_clearing_meta_restores_derived_label(tmp_path, monkeypatch):
    monkeypatch.setenv("NDM_DB", str(tmp_path / "h.db"))
    history.set_meta("aa:aa:aa:aa:aa:50", "Temp Name")
    history.set_meta("aa:aa:aa:aa:aa:50", "", "")  # empty both -> delete

    data = _scan([_dev("192.168.1.50", "aa:aa:aa:aa:aa:50", "Samsung device")])
    history.annotate(data)
    assert data["devices"][0]["label"] == "Samsung device"
    assert "custom_name" not in data["devices"][0]


def test_set_meta_disabled_returns_false(monkeypatch):
    monkeypatch.setenv("NDM_DB", "off")
    assert history.set_meta("aa:aa:aa:aa:aa:50", "x") is False
