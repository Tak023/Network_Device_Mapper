# Tier 1 features — design notes

Five quality-of-life features. Shared principles: reuse the existing SQLite DB and
scan pipeline, keep everything best-effort/non-fatal, no new dependencies.

## 1. Custom names & notes

**Problem:** "Samsung Electronics Co.,Ltd device" tells you nothing. Users know
what the device *is* — let them say so once.

- Storage: `device_meta(key, custom_name, notes)` table in the existing history DB
  (`backend/history.py`). Key = MAC when known else IP — same identity rule as
  history, so names follow a device across DHCP renumbering.
- Names are **global, not per-network** (the same laptop on two subnets is one device).
- Label precedence becomes: **custom_name** > unifi_name > hostname > vendor > ip.
  Applied server-side in `history.annotate()` so the table, topology, CSV, and
  missing-device list all pick it up for free.
- API: `POST /api/device-meta` `{key, custom_name, notes}` (token-protected;
  empty strings delete the row). 503 when `NDM_DB=off`.
- UI: ✎ button on each table row opens a modal (name, notes, device info, Wake).

## 2. Latency column

The ping sweep already waits on every reply — we were discarding the timing.

- Parse `time=X ms` from ping output (both macOS and Linux formats) rather than
  wall-clocking the subprocess (process spawn adds 10–30 ms of noise).
- `Device.latency_ms` (null for ARP-only devices that dropped ICMP).
- Sortable "Ping" column; values > 100 ms highlighted.

## 3. Device-type icons

Frontend-only inference — no backend changes, trivially tweakable.

- Priority: role (gateway/switch/AP) → hostname keywords (e.g. `tv`, `printer`,
  `iphone`) → vendor patterns (Espressif → IoT, Sony Interactive → console, …).
- Shown in the table and prefixed to client node labels in the topology
  (infra nodes keep their shapes — that encoding already works).

## 4. Auto-rescan

- Header dropdown: off / 1 / 5 / 15 min, persisted in `localStorage`.
- Re-runs the *last* scan (same target); skips a tick if a scan is in flight.
- Pairs with history diffing: NEW badges and the missing panel update live.

## 5. Wake-on-LAN

- `backend/wol.py`: standard magic packet (6×FF + 16×MAC), sent 3× via UDP
  broadcast to port 9. Pure function for the packet (unit-testable) + a sender.
- API: `POST /api/wol` `{mac}` (token-protected, MAC validated).
- UI: Wake button in the device modal, enabled when a MAC is known.

## Out of scope (Tier 2+)

Scheduled background scans + notifications, timeline/uptime views, port
fingerprinting, SNMP interface stats, Windows discovery support.
