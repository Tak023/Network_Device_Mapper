# Tier 2 — background watch, notifications, presence history

Turns the app from a scanner you open occasionally into a monitor that quietly
watches the network and taps you on the shoulder.

## 1. Background watch (scheduler)

- `backend/scheduler.py`: a daemon thread started with the server (FastAPI
  lifespan) — so it runs in **both** the browser/server mode and the desktop app
  (for as long as the app/server is running).
- Poll loop wakes every 15s, re-reads config, and runs a scan when one is due.
  Config lives in the history DB's `settings` table (editable from the UI at
  runtime), with env vars as initial defaults:
  `NDM_WATCH_ENABLED`, `NDM_WATCH_INTERVAL_MIN`, `NDM_WATCH_TARGET`,
  `NDM_WATCH_NOTIFY_NEW`, `NDM_WATCH_NOTIFY_MISSING`, `NDM_WEBHOOK_URL`.
- Each run reuses the normal pipeline (`discovery.scan` → `history.annotate`),
  so NEW/missing flags, custom names, and the sightings log all stay consistent
  with manual scans.
- API: `GET /api/scheduler` (config + last/next run), `POST /api/scheduler`
  (partial update, persisted). UI: "Watch" dialog in the header.

## 2. Notifications

- `backend/notify.py`, all best-effort:
  - **macOS**: `osascript display notification` (works from the .app and the CLI)
  - **Linux**: `notify-send` when available
  - **Webhook**: JSON `POST {title, message}` to `NDM_WEBHOOK_URL` / the UI
    setting — pluggable into ntfy, Slack/Discord bridges, Home Assistant, etc.
- Policy: new devices notify by default; *missing* devices are **opt-in** and
  only fire when a device goes missing **since the previous watch run**
  (the historical missing-list would be far too noisy — devices sleep).

## 3. Presence history + uptime

- Two new tables, written during `annotate()`:
  `scans(network, ts)` — every completed scan; `sightings(network, key, ts)` —
  which devices answered in it. Pruned after `NDM_HISTORY_DAYS` (default 30).
  Rough volume: 40 devices × a 5-min watch ≈ 12k rows/day — trivial for SQLite.
- `GET /api/device-history?key&network&hours` returns per-scan presence points
  plus an availability ratio (seen ÷ scans in the window).
- UI: the device modal gains a presence strip (one tick per scan, colored
  seen/missed) and "seen in X of Y scans (Z%)" for the last 7 days.

## Out of scope (Tier 3+)

Port/service fingerprinting, SNMP interface stats, SNMPv3, Windows discovery,
menu-bar mode.
