# Network Device Mapper

Scans your local network, discovers reachable devices (name + IP + MAC + vendor),
and presents them as a **sortable table** and a **modern force-directed topology**.

Runs **two ways** (same features, same backend — pick either or both):

|  | How | Best for |
|---|---|---|
| 🖥️ **Desktop app** | `./build_app.sh` → double-click the app | Everyday use — native window, Dock icon, nothing listening beyond loopback |
| 🌐 **Browser / server** | `./run.sh` → `http://127.0.0.1:8000` | Embedding in a website, running on a headless box (NAS/Pi), sharing on the LAN |

<!-- Drop a screenshot at docs/preview.png and uncomment:
![table + topology](docs/preview.png) -->

## What it does

- **Discovers** every reachable device on your primary subnet.
- **Names** them via reverse-DNS, **mDNS/Bonjour** (Apple/IoT gear), and MAC-vendor lookup.
- **Visualizes** them as a hub-and-spoke topology around your gateway/router.
- **Remembers** past scans (SQLite) and flags devices that are **NEW** or have
  **gone missing** since the last scan of that network.
- **Streams progress** live while scanning (ping sweep counts, name resolution, SNMP).
- **Sortable, filterable table** — click any column header; type to filter.
- **Exports** the device list as **CSV** and the topology as a **PNG** (buttons in each
  card header; generated client-side from the current scan).
- **Embeds** anywhere — the widget is a single static page that talks to a small API.

## Quick start

**Desktop app** (native window, no browser):

```bash
pip install -r requirements.txt -r requirements-desktop.txt
./build_app.sh                  # build once -> dist/Network Device Mapper.app
# or run it straight from source:
python3 -m backend.desktop
```

**Browser / server mode** (for embedding, headless boxes, or LAN access):

```bash
./run.sh
# then open http://127.0.0.1:8000  and click “Scan network”
```

`run.sh` creates a virtualenv, installs dependencies, and starts the server.
Both modes are maintained — the desktop app is simply the same server plus the
same UI wrapped in a native window on a private random port.

To run the discovery engine standalone (no UI at all):

```bash
python3 -m backend.discovery
```

## Desktop app details

The backend binds a random `127.0.0.1` port and exits with the window — nothing
is ever reachable from the network.

Configuration: same env vars / `.env` as the server — put a `.env` next to the
app bundle, in the working directory, or in the user data dir
(`~/Library/Application Support/Network Device Mapper/` on macOS). Scan history
is stored there too.

**App icon:** `build_app.sh` generates the `.icns` automatically from
`assets/icon.png` (1024×1024) — replace that file to rebrand. The in-app header
logo (`frontend/logo.png`) is a center-crop of the same image.

Note for distribution: the bundle is ad-hoc signed, so it runs on the build
machine but other Macs will require right-click → Open (or notarization with an
Apple Developer ID) the first time.

## How discovery works

1. Determine this host's IP, subnet mask, and default gateway.
2. Concurrent ICMP **ping-sweep** across the subnet to populate the ARP cache.
3. Read the system **ARP table** (`arp -an`, or `ip neigh` on modern Linux) for IP ↔ MAC.
4. Best-effort name enrichment, never fatal: parallel **reverse-DNS**, then one batched
   **mDNS/Bonjour** query for whatever DNS couldn't name, plus **MAC-vendor** lookup.

This runs **without root** and without raw sockets/scapy. Results are the union of
ping replies and ARP entries, so devices that drop ICMP but answer ARP still appear.
Works with either net-tools (`ifconfig`/`arp`) or iproute2 (`ip`) installed.

## Embedding in a website

The widget (`frontend/index.html`) is plain HTML/JS with no build step.
`vis-network` is vendored locally so everything works on offline/isolated networks.

- **Simplest:** host this server and drop an iframe on your site:
  ```html
  <iframe src="http://YOUR_HOST:8000" width="100%" height="640" style="border:0"></iframe>
  ```
- **Decoupled:** host `frontend/index.html` on your own site, set `API_BASE`
  (top of the `<script>` block) to your scanner's URL, and set
  `NDM_CORS_ORIGINS=https://your-site.example` on the server so the browser may
  call it cross-origin (CORS is closed by default).

## Architecture

```
backend/
  discovery.py   # ping-sweep + ARP + rDNS/mDNS/vendor enrichment  (pure Python, unprivileged)
  mdns.py        # reverse mDNS (Bonjour) lookups, dependency-free
  history.py     # SQLite scan history -> NEW / missing-device diffing
  server.py      # FastAPI: /api/scan (+SSE stream), token/CORS/target guards, widget
frontend/
  index.html     # table + vis-network topology, zero build step
tests/           # parsers, correlation, history, API behavior (pytest)
```

API:

| Method | Path                          | Description                                   |
|--------|-------------------------------|-----------------------------------------------|
| GET    | `/api/scan`                   | Scan the auto-detected local LAN (30s cache)  |
| GET    | `/api/scan?target=<range>`    | Scan a specific range (see formats below)     |
| GET    | `/api/scan?force=1`           | Bypass the cache                              |
| GET    | `/api/scan/stream`            | Same scan as SSE with live progress events    |
| GET    | `/api/health`                 | Liveness probe                               |
| GET    | `/`                           | The embeddable widget                        |

If `NDM_API_TOKEN` is set, `/api/scan*` require it (`X-API-Token` header or
`?token=`; the widget forwards `/?token=...` from its own URL automatically).

### Scanning other networks

Use the **Scan range** box in the widget, or pass `target=` to the API. Accepted formats:

| Format          | Example                       |
|-----------------|-------------------------------|
| CIDR            | `192.168.1.0/24`              |
| Single IP       | `10.0.0.5`                    |
| Explicit range  | `192.168.1.10-192.168.1.50`   |
| Shorthand range | `192.168.1.10-50`             |

Ranges are capped at **4096 hosts** (a `/20`) to prevent accidental massive sweeps;
larger requests return `400` with an explanatory message. CLI equivalent:

```bash
python3 -m backend.discovery 192.168.1.0/24
```

## Real Layer-2 topology

A passive ping/ARP scan **cannot** see switches or which port a device is on — a
switch is transparent at L3, so every device looks one hop from the gateway. To draw
the true **gateway → switch → device** hierarchy you need adjacency data from the
infrastructure itself. Two **pluggable providers** supply it; all credentials are
**user-supplied via `.env`** (nothing is baked in, so the app is safe to share). The
header shows **"physical topology · SNMP/UniFi"** when live, or **"logical view"** on
fallback. Nodes are shaped by role: ◆ gateway · ■ switch · ▲ access point · ● device.

### Provider 1 — SNMP (vendor-neutral, recommended)

Works across **any managed switch** (Cisco, Aruba, Netgear, MikroTik, UniFi, …) using
the standard **LLDP-MIB** (infra links) + **Bridge-MIB** forwarding tables (device →
port), the same approach as LibreNMS/Netdisco/OpenNMS.

Requirements (per user):
- net-snmp CLI tools — `brew install net-snmp` (macOS) / `apt install snmp` (Debian).
- **SNMP enabled** on your switches with a read **community string**. Unmanaged
  switches have no SNMP and remain physically undiscoverable — nothing can map them.

```bash
cp .env.example .env
# set SNMP_COMMUNITY (e.g. "public"); optionally SNMP_TARGETS=10.1.1.1,10.1.1.2
python3 -m backend.snmp 10.1.1.1   # test against one switch — prints the hierarchy
./run.sh                            # auto-loads .env
```

Correlation: a port that faces another managed switch is an *uplink*; end devices are
placed on the switch/port where they're learned on a non-uplink (edge) port. SNMP v3
is not yet supported (v1/v2c only).

### Provider 2 — UniFi controller (optional)

For UniFi networks, read the LLDP topology the controller already computes:

```bash
# set UNIFI_URL + UNIFI_API_KEY in .env
python3 -m backend.unifi        # connectivity test
python3 -m backend.unifi --raw  # dump raw device/client JSON (field debugging)
```

- **API key** *(Network 10.1.84+)* — create at **Settings → Control Plane →
  Integrations** (the **"API Keys"** tab); stateless `X-API-KEY`, no MFA.
- **Local admin** *(older controllers)* — `UNIFI_USERNAME`/`UNIFI_PASSWORD`.

> Providers are tried **SNMP → UniFi → L3 star**. Configure whichever fits; if none is
> set (or the provider is unreachable) the app degrades gracefully — no errors.

## Limitations & honest scope

- Without a topology provider it discovers **layer-3 reachable hosts** only and shows a
  **hub-and-spoke** logical view — accurate for a flat LAN, but not physical wiring.
- **Unmanaged switches are physically undiscoverable** by any method (no SNMP, no IP) —
  devices behind them attach to the nearest *managed* switch the data can see.
- SNMP topology can need per-network tuning (VLANs, LAGs, vendor quirks); use
  `python3 -m backend.snmp <switch-ip>` to validate against your gear.
- Devices with strict firewalls (no ICMP, no ARP response when idle) may be missed.
- The MAC-vendor database is optional; names degrade gracefully without it.

## Security & responsible use

- **Only scan networks you own or are authorized to test.** Active scanning of
  third-party networks may be unlawful.
- **Safe defaults:** the server binds to `127.0.0.1` and CORS is closed, so neither
  the LAN nor a random website your browser visits can reach the API.
- To expose it (`HOST=0.0.0.0 ./run.sh`), set **`NDM_API_TOKEN`** so scans require
  auth, and optionally **`NDM_ALLOWED_TARGETS`** to limit which ranges `?target=`
  may sweep. See `.env.example`.

## Development

```bash
pip install -r requirements.txt -r requirements-dev.txt
ruff check backend tests   # lint
pytest                     # parsers, SNMP correlation, history, API behavior
RELOAD=1 ./run.sh          # auto-restart on code edits
```

CI (GitHub Actions) runs lint + tests on every push/PR.

## Roadmap

- [x] SNMP/LLDP collection for true switch-port topology
- [x] mDNS/Bonjour names for Apple/IoT devices
- [x] Persist scans over time + diff (new/missing device alerts)
- [x] Export to PNG / CSV
- [ ] Open-port / service fingerprinting (opt-in)
- [ ] SNMP v3 support
- [ ] Scheduled background scans + notifications
```
