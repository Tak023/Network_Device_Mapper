"""User notifications for the background watch. All strictly best-effort.

Channels:
  * macOS   -- `osascript display notification` (works from the .app and CLI)
  * Linux   -- `notify-send` when present
  * Webhook -- JSON POST {"title", "message"} to a user-supplied URL
               (ntfy, Slack/Discord bridges, Home Assistant, ...)

Failures are logged and swallowed: a broken notification channel must never
take down the watch loop.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import sys

logger = logging.getLogger("notify")


def send(title: str, message: str, webhook_url: str = "") -> None:
    """Deliver on every configured/available channel; never raises."""
    _desktop(title, message)
    if webhook_url:
        _webhook(webhook_url, title, message)


def _desktop(title: str, message: str) -> None:
    try:
        if sys.platform == "darwin":
            # json.dumps produces AppleScript-compatible quoted strings.
            script = (
                f"display notification {json.dumps(message, ensure_ascii=False)} "
                f"with title {json.dumps(title, ensure_ascii=False)}"
            )
            subprocess.run(["osascript", "-e", script], capture_output=True, timeout=10)
        elif shutil.which("notify-send"):
            subprocess.run(["notify-send", title, message], capture_output=True, timeout=10)
    except (OSError, subprocess.SubprocessError) as exc:
        logger.debug("Desktop notification failed: %s", exc)


def _webhook(url: str, title: str, message: str) -> None:
    try:
        import requests

        r = requests.post(url, json={"title": title, "message": message}, timeout=5)
        if not r.ok:
            logger.warning("Webhook returned HTTP %d", r.status_code)
    except Exception as exc:
        logger.warning("Webhook notification failed: %s", exc)
