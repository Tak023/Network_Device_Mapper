"""Notification plumbing (all transports stubbed)."""

import subprocess

from backend import notify


def test_desktop_macos_command(monkeypatch):
    calls = []
    monkeypatch.setattr(notify.sys, "platform", "darwin")
    monkeypatch.setattr(subprocess, "run", lambda cmd, **kw: calls.append(cmd))
    notify.send("Title", 'He said "hi"\nline2')
    assert calls and calls[0][0] == "osascript"
    script = calls[0][2]
    assert 'with title "Title"' in script
    assert '\\"hi\\"' in script  # quotes escaped for AppleScript


def test_webhook_posts_json(monkeypatch):
    posted = {}

    class _Resp:
        ok = True
        status_code = 200

    def fake_post(url, json=None, timeout=None):
        posted.update({"url": url, "json": json})
        return _Resp()

    import requests
    monkeypatch.setattr(requests, "post", fake_post)
    monkeypatch.setattr(notify, "_desktop", lambda *a: None)
    notify.send("T", "M", webhook_url="http://example.test/hook")
    assert posted == {"url": "http://example.test/hook", "json": {"title": "T", "message": "M"}}


def test_send_never_raises(monkeypatch):
    def boom(*a, **kw):
        raise OSError("no gui")
    monkeypatch.setattr(subprocess, "run", boom)
    import requests
    monkeypatch.setattr(requests, "post", boom)
    notify.send("T", "M", webhook_url="http://x")  # must not raise
