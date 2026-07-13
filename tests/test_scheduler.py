"""Background watch: config merging and one-scan behavior (scan/notify stubbed)."""

import pytest

from backend import history, scheduler


class _FakeResult:
    def __init__(self, devices):
        self._devices = devices

    def to_dict(self):
        return {"network_cidr": "192.168.1.0/24", "devices": self._devices}


def _dev(ip, mac):
    return {"ip": ip, "mac": mac, "label": ip}


@pytest.fixture()
def watch(monkeypatch, tmp_path):
    monkeypatch.setenv("NDM_DB", str(tmp_path / "h.db"))
    for env in scheduler._ENV.values():
        monkeypatch.delenv(env, raising=False)
    return scheduler.Watch()


def test_config_defaults(watch):
    cfg = scheduler.get_config()
    assert cfg == {
        "enabled": False, "interval_min": 15, "target": "",
        "notify_new": True, "notify_missing": False, "webhook_url": "",
    }


def test_config_env_then_db_precedence(watch, monkeypatch):
    monkeypatch.setenv("NDM_WATCH_INTERVAL_MIN", "30")
    assert scheduler.get_config()["interval_min"] == 30
    history.set_settings({"watch_interval_min": "5", "watch_enabled": "true"})
    cfg = scheduler.get_config()
    assert cfg["interval_min"] == 5   # DB (UI) wins over env
    assert cfg["enabled"] is True


def test_config_bad_interval_falls_back(watch, monkeypatch):
    monkeypatch.setenv("NDM_WATCH_INTERVAL_MIN", "banana")
    assert scheduler.get_config()["interval_min"] == 15


def test_run_once_notifies_new_devices(watch, monkeypatch):
    sent = []
    monkeypatch.setattr(scheduler.notify, "send",
                        lambda title, msg, hook="": sent.append((title, msg, hook)))
    monkeypatch.setattr(scheduler.discovery, "scan",
                        lambda target=None, progress=None: _FakeResult(
                            [_dev("192.168.1.9", "aa:aa:aa:aa:aa:09")]))

    watch.run_once({**scheduler.get_config(), "notify_new": True, "webhook_url": "http://x"})
    assert len(sent) == 1
    title, msg, hook = sent[0]
    assert "New device" in title and "192.168.1.9" in msg and hook == "http://x"
    assert watch.last_run is not None
    assert "1 new" in watch.last_summary

    # Same device again: known now, no notification.
    watch.run_once({**scheduler.get_config(), "notify_new": True})
    assert len(sent) == 1


def test_run_once_notifies_newly_missing_only(watch, monkeypatch):
    sent = []
    monkeypatch.setattr(scheduler.notify, "send",
                        lambda title, msg, hook="": sent.append(title))
    results = [
        _FakeResult([_dev("192.168.1.9", "aa:aa:aa:aa:aa:09"),
                     _dev("192.168.1.10", "aa:aa:aa:aa:aa:10")]),
        _FakeResult([_dev("192.168.1.9", "aa:aa:aa:aa:aa:09")]),   # .10 vanishes
        _FakeResult([_dev("192.168.1.9", "aa:aa:aa:aa:aa:09")]),   # still gone: no repeat
    ]
    monkeypatch.setattr(scheduler.discovery, "scan",
                        lambda target=None, progress=None: results.pop(0))

    cfg = {**scheduler.get_config(), "notify_new": False, "notify_missing": True}
    watch.run_once(cfg)
    assert sent == []                    # first run: baseline only
    watch.run_once(cfg)
    assert sent == ["Device went missing"]
    watch.run_once(cfg)
    assert sent == ["Device went missing"]  # not re-notified


def test_status_shape(watch):
    st = watch.status()
    assert st["enabled"] is False
    assert st["scanning"] is False
    assert st["last_run"] is None and st["next_run"] is None
