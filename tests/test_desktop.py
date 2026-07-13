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
