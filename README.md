# Network Device Mapper

Scans your local network, discovers reachable devices (name + IP + MAC + vendor),
and presents them as a **sortable table** and a **modern force-directed topology**
you can embed in any website.

![table + topology](docs/preview.png) <!-- optional: drop a screenshot here -->

## What it does

- **Discovers** every reachable device on your primary subnet.
- **Names** them via reverse-DNS and MAC-vendor lookup.
- **Visualizes** them as a hub-and-spoke topology around your gateway/router.
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

## Limitations & honest scope

- Discovers **layer-3 reachable hosts** on your subnet. It does **not** infer
  physical switch-port wiring — true L2 topology needs **LLDP/CDP/SNMP** against
  managed switches (a sensible future phase).
- Topology is **hub-and-spoke** off the gateway, which is the accurate shape for a
  flat home/SMB LAN.
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
