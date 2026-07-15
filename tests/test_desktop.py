"""Desktop launcher plumbing (no window is opened — webview import is lazy)."""

import socket
import urllib.request

from backend import desktop


def test_free_port_is_bindable():
    port = desktop.free_port()
    assert 1024 < port < 65536
    with socket.socket() as s:  # the port it returned is actually free
        s.bind(("127.0.0.1", port))


def test_user_data_dir_is_absolute_and_named():
    d = desktop.user_data_dir()
    assert d.is_absolute()
    assert desktop.APP_NAME in str(d)


def test_wait_healthy_times_out_fast_on_dead_port():
    port = desktop.free_port()  # nothing listening on it
    assert desktop.wait_healthy(port, timeout=0.5) is False


def _stub_webview(monkeypatch):
    """Inject a minimal fake `webview` so save_file imports cleanly in CI."""
    import sys
    import types

    stub = types.ModuleType("webview")
    stub.SAVE_DIALOG = 20
    monkeypatch.setitem(sys.modules, "webview", stub)


def test_jsapi_save_file_writes(tmp_path, monkeypatch):
    _stub_webview(monkeypatch)
    target = tmp_path / "export.csv"

    class FakeWindow:
        def create_file_dialog(self, dialog, save_filename=None):
            self.requested = save_filename
            return str(target)

    api = desktop._JsApi()
    api.window = FakeWindow()
    import base64

    res = api.save_file("export.csv", base64.b64encode(b"hello,world").decode())
    assert res["ok"] is True
    assert target.read_bytes() == b"hello,world"
    assert api.window.requested == "export.csv"


def test_jsapi_save_file_cancelled(tmp_path, monkeypatch):
    _stub_webview(monkeypatch)

    class FakeWindow:
        def create_file_dialog(self, dialog, save_filename=None):
            return None  # user hit Cancel

    api = desktop._JsApi()
    api.window = FakeWindow()
    res = api.save_file("x.png", "")
    assert res == {"ok": False, "cancelled": True}


def test_jsapi_save_file_no_window():
    assert desktop._JsApi().save_file("x", "")["ok"] is False


def test_server_thread_boots_and_serves(monkeypatch):
    """End-to-end: the exact code path main() uses to start the backend."""
    monkeypatch.setenv("NDM_DB", "off")
    port = desktop.free_port()
    thread = desktop.start_server(port)
    assert desktop.wait_healthy(port, timeout=10)
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=2) as resp:
        assert resp.status == 200
        assert b"Network Device Mapper" in resp.read()
    assert thread.daemon  # dies with the process / window
