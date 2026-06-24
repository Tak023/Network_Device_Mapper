# Network Device Mapper

Scans your local network, discovers reachable devices (name + IP + MAC + vendor),
and presents them as a **sortable table** and a **modern force-directed topology**
you can embed in any website.

![table + topology](docs/preview.png) <!-- optional: drop a screenshot here -->

## What it does

- **Discovers** every reachable device on your primary subnet.
- **Names** them via reverse-DNS and MAC-vendor lookup.
- **Visualizes** them as a hub-and-spoke topology around your gateway/router.
- **Exports** the device list as **CSV** and the topology as a **PNG** (buttons in each
  card header; generated client-side from the current scan).
- **Embeds** anywhere — the widget is a single static page that talks to a small API.

## Quick start

```bash
./run.sh
# then open http://127.0.0.1:8000  and click “Scan network”
```

`run.sh` creates a virtualenv, installs dependencies, and starts the server.
To run the discovery engine standalone (no web server):

```bash
python3 -m backend.discovery
```

## How discovery works

1. Determine this host's IP, subnet mask, and default gateway.
2. Concurrent ICMP **ping-sweep** across the subnet to populate the ARP cache.
3. Read the system **ARP table** (`arp -an`) for IP ↔ MAC.
4. Best-effort **reverse-DNS** and **MAC-vendor** enrichment for names.

This runs **without root** and without raw sockets/scapy. Results are the union of
ping replies and ARP entries, so devices that drop ICMP but answer ARP still appear.

## Embedding in a website

The widget (`frontend/index.html`) is plain HTML/JS with no build step.

- **Simplest:** host this server and drop an iframe on your site:
  ```html
  <iframe src="http://YOUR_HOST:8000" width="100%" height="640" style="border:0"></iframe>
  ```
- **Decoupled:** host `frontend/index.html` on your own site and set `API_BASE`
  (top of the `<script>` block) to your scanner's URL. CORS is already open.

## Architecture

```
backend/
  discovery.py   # ping-sweep + ARP + rDNS/vendor enrichment  (pure Python, unprivileged)
  server.py      # FastAPI: /api/scan (cached) + serves the widget, CORS-enabled
frontend/
  index.html     # table + vis-network topology, zero build step
```

API:

| Method | Path                          | Description                                   |
|--------|-------------------------------|-----------------------------------------------|
| GET    | `/api/scan`                   | Scan the auto-detected local LAN (30s cache)  |
| GET    | `/api/scan?target=<range>`    | Scan a specific range (see formats below)     |
| GET    | `/api/scan?force=1`           | Bypass the cache                              |
| GET    | `/api/health`                 | Liveness probe                               |
| GET    | `/`                           | The embeddable widget                        |

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
- The API has **no authentication** and CORS is wide open — intended for trusted
  LAN use. Put it behind auth / a reverse proxy before exposing it publicly.

## Roadmap

- [ ] SNMP/LLDP collection for true switch-port topology
- [ ] mDNS/Bonjour names for Apple/IoT devices
- [ ] Persist scans over time + diff (new/missing device alerts)
- [ ] Open-port / service fingerprinting (opt-in)
- [ ] Export to PNG / CSV
```
