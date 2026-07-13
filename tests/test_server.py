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
