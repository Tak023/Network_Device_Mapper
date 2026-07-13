"""API behavior: auth, target allow-listing, caching. Scans are stubbed out."""

import json

import pytest
from fastapi.testclient import TestClient

from backend import server


class _FakeResult:
    def __init__(self, note="stub"):
        self.note = note

    def to_dict(self):
        return {
            "network_cidr": None,  # None -> history.annotate() no-ops
            "devices": [],
            "reachable": True,
            "note": self.note,
        }


@pytest.fixture()
def client(monkeypatch):
    calls = []

    def fake_scan(target=None, progress=None):
        calls.append(target)
        if progress:
            progress("sweep", 1, 1)
        return _FakeResult()

    monkeypatch.setattr(server.discovery, "scan", fake_scan)
    monkeypatch.setenv("NDM_DB", "off")
    monkeypatch.delenv("NDM_API_TOKEN", raising=False)
    monkeypatch.delenv("NDM_ALLOWED_TARGETS", raising=False)
    with server._meta_lock:
        server._cache.clear()
        server._scan_locks.clear()
    c = TestClient(server.app)
    c.scan_calls = calls
    return c


def test_health(client):
    assert client.get("/api/health").json() == {"status": "ok"}


def test_scan_ok_and_no_store(client):
    r = client.get("/api/scan")
    assert r.status_code == 200
    assert r.headers["cache-control"] == "no-store"


def test_scan_cached_within_ttl(client):
    client.get("/api/scan")
    client.get("/api/scan")
    assert len(client.scan_calls) == 1  # second request served from cache


def test_force_bypasses_cache(client):
    client.get("/api/scan")
    client.get("/api/scan?force=1")
    assert len(client.scan_calls) == 2


def test_invalid_target_400(client):
    r = client.get("/api/scan?target=10.0.0.0/8")
    assert r.status_code == 400
    assert "too large" in r.json()["error"]


def test_token_required_when_set(client, monkeypatch):
    monkeypatch.setenv("NDM_API_TOKEN", "sekrit")
    assert client.get("/api/scan").status_code == 401
    assert client.get("/api/scan", headers={"X-API-Token": "wrong"}).status_code == 401
    assert client.get("/api/scan", headers={"X-API-Token": "sekrit"}).status_code == 200
    assert client.get("/api/scan?token=sekrit").status_code == 200
    assert client.get("/api/health").status_code == 200  # liveness stays open


def test_allowed_targets_enforced(client, monkeypatch):
    monkeypatch.setenv("NDM_ALLOWED_TARGETS", "192.168.1.0/24, 10.0.0.0/16")
    assert client.get("/api/scan?target=192.168.1.0/28").status_code == 200
    assert client.get("/api/scan?target=10.0.5.1-9").status_code == 200
    r = client.get("/api/scan?target=172.16.0.0/24")
    assert r.status_code == 400
    assert "outside the allowed" in r.json()["error"]
    assert client.get("/api/scan").status_code == 200  # local LAN always allowed


def test_stream_emits_progress_then_done(client):
    with client.stream("GET", "/api/scan/stream?force=1") as r:
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/event-stream")
        events = []
        for line in r.iter_lines():
            if line.startswith("data: "):
                events.append(json.loads(line[6:]))
    kinds = [e["event"] for e in events]
    assert kinds[-1] == "done"
    assert "progress" in kinds
    assert events[-1]["result"]["note"] == "stub"


def test_stream_rejects_bad_target(client):
    r = client.get("/api/scan/stream?target=not-an-ip")
    assert r.status_code == 400


def test_device_meta_roundtrip(client, monkeypatch, tmp_path):
    monkeypatch.setenv("NDM_DB", str(tmp_path / "h.db"))
    r = client.post("/api/device-meta", json={
        "key": "aa:aa:aa:aa:aa:50", "custom_name": "Office printer", "notes": "3rd floor",
    })
    assert r.status_code == 200 and r.json() == {"ok": True}

    from backend import history
    data = {"network_cidr": "10.0.0.0/24",
            "devices": [{"ip": "10.0.0.5", "mac": "aa:aa:aa:aa:aa:50", "label": "x"}]}
    history.annotate(data)
    assert data["devices"][0]["label"] == "Office printer"


def test_device_meta_requires_key(client, monkeypatch, tmp_path):
    monkeypatch.setenv("NDM_DB", str(tmp_path / "h.db"))
    assert client.post("/api/device-meta", json={"key": "  "}).status_code == 400


def test_device_meta_503_when_history_disabled(client):
    # fixture sets NDM_DB=off
    r = client.post("/api/device-meta", json={"key": "aa:aa:aa:aa:aa:50", "custom_name": "x"})
    assert r.status_code == 503


def test_device_meta_clears_scan_cache(client, monkeypatch, tmp_path):
    monkeypatch.setenv("NDM_DB", str(tmp_path / "h.db"))
    client.get("/api/scan")
    client.post("/api/device-meta", json={"key": "aa:aa:aa:aa:aa:50", "custom_name": "x"})
    client.get("/api/scan")  # would be a cache hit if the rename hadn't cleared it
    assert len(client.scan_calls) == 2


def test_wol_sends_packet(client, monkeypatch):
    sent = []
    monkeypatch.setattr(server.wol, "wake", lambda mac: sent.append(mac))
    r = client.post("/api/wol", json={"mac": "a4:5e:60:aa:bb:cc"})
    assert r.status_code == 200
    assert sent == ["a4:5e:60:aa:bb:cc"]


def test_wol_rejects_bad_mac(client):
    r = client.post("/api/wol", json={"mac": "not-a-mac"})
    assert r.status_code == 400


def test_post_endpoints_require_token_when_set(client, monkeypatch):
    monkeypatch.setenv("NDM_API_TOKEN", "sekrit")
    assert client.post("/api/wol", json={"mac": "a4:5e:60:aa:bb:cc"}).status_code == 401
    assert client.post("/api/device-meta", json={"key": "x"}).status_code == 401
    assert client.post("/api/scheduler", json={"enabled": True}).status_code == 401


def test_scheduler_get_and_update(client, monkeypatch, tmp_path):
    monkeypatch.setenv("NDM_DB", str(tmp_path / "h.db"))
    for env in ("NDM_WATCH_ENABLED", "NDM_WATCH_INTERVAL_MIN"):
        monkeypatch.delenv(env, raising=False)
    assert client.get("/api/scheduler").json()["enabled"] is False

    r = client.post("/api/scheduler", json={"enabled": True, "interval_min": 5})
    st = r.json()
    assert r.status_code == 200 and st["enabled"] is True and st["interval_min"] == 5
    # Persisted across a fresh status read.
    assert client.get("/api/scheduler").json()["interval_min"] == 5


def test_scheduler_rejects_bad_input(client, monkeypatch, tmp_path):
    monkeypatch.setenv("NDM_DB", str(tmp_path / "h.db"))
    assert client.post("/api/scheduler", json={"interval_min": 0}).status_code == 400
    assert client.post("/api/scheduler", json={"target": "10.0.0.0/8"}).status_code == 400


def test_device_history_endpoint(client, monkeypatch, tmp_path):
    monkeypatch.setenv("NDM_DB", str(tmp_path / "h.db"))
    from backend import history
    history.annotate({"network_cidr": "10.0.0.0/24",
                      "devices": [{"ip": "10.0.0.5", "mac": "aa:aa:aa:aa:aa:50", "label": "x"}]})
    r = client.get("/api/device-history?key=aa:aa:aa:aa:aa:50&network=10.0.0.0/24")
    assert r.status_code == 200
    assert r.json()["availability"] == 1.0


def test_device_history_503_when_disabled(client):
    r = client.get("/api/device-history?key=x&network=y")
    assert r.status_code == 503
