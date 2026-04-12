# SteelHaze V2

Network security monitor with a web dashboard, persistent storage, passive device detection, traffic monitoring, anomaly detection, and CVE lookups.

---

## Project Structure

```
SteelHazeV2/
├── main.py                  # Entry point
├── steelhaze.db             # SQLite database (auto-created on first run)
├── src/
│   ├── database.py          # DB schema, init, and migrations
│   ├── scanner.py           # nmap ping scan, default interface detection
│   ├── monitor.py           # Main 30s monitoring loop, device/traffic persistence
│   ├── traffic_monitor.py   # Scapy IP sniffer (bytes/packets per IP)
│   ├── passive_scanner.py   # Passive ARP sniffer + ARP cache reader
│   ├── anomaly_detector.py  # Detects HIGH_TRAFFIC, NEW_DEVICE, STEALTH_DEVICE, IP_REASSIGNED
│   ├── nvd_lookup.py        # NVD API CVE lookup by service name
│   ├── nvd_scanner.py       # Deep all-port scan + CVE lookup (runs every 30 min)
│   ├── scan_state.py        # Shared in-memory scan state between monitor and Flask
│   └── app.py               # Flask REST API + page routes
├── templates/
│   ├── base.html            # Shared layout: header, nav, stats bar, JS helpers
│   ├── devices.html         # / — active devices + passive detections per interface
│   ├── traffic.html         # /traffic — bandwidth per device
│   ├── anomalies.html       # /anomalies — alerts
│   ├── cves.html            # /cves — CVE findings per host
│   └── timeline.html        # /timeline — charts (devices/day, CVE severity, traffic, anomalies)
└── static/
    └── style.css            # All CSS
```

---

## Dependencies

### System packages

```bash
sudo apt install nmap python3-netifaces python3-scapy
```

| Package | Used for |
|---|---|
| `nmap` | Network scanning — finds all live hosts |
| `python3-netifaces` | Reads interface info (IP, gateway, subnet) |
| `python3-scapy` | Packet sniffer for traffic monitoring and passive ARP detection |

### Python packages

```bash
pip install flask python-nmap requests
```

---

## How to Run

```bash
sudo python main.py
```

Needs root for packet sniffing (Scapy). Dashboard at **http://localhost:5000**.


---

## What It Does

- **Scans every 30s** using nmap `-sn` via the default route interface — finds all live hosts
- **Passive detection** runs continuously alongside the scan: ARP sniffer + kernel ARP cache reader catch devices that don't respond to nmap (IoT, AP-isolated, stealthy hosts)
- **Traffic monitoring** with Scapy — tracks bytes sent/received per device in real time
- **Deep CVE scan** every 30 min: scans all ports (`-p-`), detects service versions, queries NVD API for CVEs
- **Anomaly detection**: high traffic, new unknown devices, stealth devices (passive-only), IP reassignment
- **Persists everything** to SQLite — history survives restarts

### Dashboard pages

| Page | URL | Shows |
|---|---|---|
| Devices | `/` | Active devices from scan + passive-only section per interface card |
| Traffic | `/traffic` | Bandwidth per device (last 24h) |
| Anomalies | `/anomalies` | All alerts (last 24h) |
| CVE Findings | `/cves` | Open ports + CVEs grouped per host |
| Charts | `/timeline` | Devices/day, CVE severity, top traffic, anomalies/day |

---

## Database Structure

8 tables. All timestamps are UTC.

---

### `networks`
One row per unique network ever seen. Identified by `(gateway_ip, subnet)`.

| Column | Type | Description |
|---|---|---|
| `id` | INTEGER PK | — |
| `ssid` | TEXT | Wi-Fi name, null if wired |
| `gateway_ip` | TEXT | Router IP |
| `subnet` | TEXT | e.g. 192.168.1.0/24 |
| `interface` | TEXT | eth0 / wlan0 |
| `first_seen` | TIMESTAMP | — |
| `last_seen` | TIMESTAMP | — |

Constraint: `UNIQUE(gateway_ip, subnet)`

---

### `devices`
One row per unique physical device. Identity = MAC address. IP is not stored here — it lives in `device_network` because the same device can have different IPs on different networks.

| Column | Type | Description |
|---|---|---|
| `id` | INTEGER PK | — |
| `mac` | TEXT | MAC address, null if nmap couldn't read it |
| `label` | TEXT | User-given nickname |
| `first_seen` | TIMESTAMP | — |
| `last_seen` | TIMESTAMP | — |

---

### `device_network`
Junction table linking a device to a network. Holds the IP (network-specific) and how the device was discovered.

| Column | Type | Description |
|---|---|---|
| `id` | INTEGER PK | — |
| `device_id` | INTEGER FK → devices.id | — |
| `network_id` | INTEGER FK → networks.id | — |
| `ip` | TEXT | Current IP on this network |
| `first_seen` | TIMESTAMP | — |
| `last_seen` | TIMESTAMP | — |
| `is_known` | BOOLEAN | 0 = unknown, 1 = user-approved |
| `source` | TEXT | `nmap` = found by scan, `passive` = found by ARP only |

Constraint: `UNIQUE(device_id, network_id)`

> `source` upgrades from `passive` → `nmap` automatically when nmap finds the device. It never downgrades.

---

### `connection_logs`
One row every scan cycle a device is seen — raw event log.

| Column | Type | Description |
|---|---|---|
| `id` | INTEGER PK | — |
| `device_id` | INTEGER FK → devices.id | — |
| `network_id` | INTEGER FK → networks.id | — |
| `ip` | TEXT | IP at time of log |
| `status` | TEXT | `up` |
| `timestamp` | TIMESTAMP | — |

---

### `traffic_stats`
Bandwidth snapshot every 30s per device, written by the Scapy sniffer.

| Column | Type | Description |
|---|---|---|
| `id` | INTEGER PK | — |
| `device_id` | INTEGER FK → devices.id | — |
| `network_id` | INTEGER FK → networks.id | — |
| `ip` | TEXT | — |
| `bytes_sent` | INTEGER | — |
| `bytes_received` | INTEGER | — |
| `packets` | INTEGER | — |
| `timestamp` | TIMESTAMP | — |

---

### `anomalies`
All alerts from the anomaly detector and CVE scanner.

| Column | Type | Description |
|---|---|---|
| `id` | INTEGER PK | — |
| `type` | TEXT | See types below |
| `ip` | TEXT | — |
| `mac` | TEXT | Plain string — not a FK, survives device deletion |
| `details` | TEXT | Human-readable message |
| `network_id` | INTEGER FK → networks.id | — |
| `timestamp` | TIMESTAMP | — |
| `acknowledged` | BOOLEAN | 0 = unread, 1 = dismissed |

**Anomaly types:**

| Type | Trigger | Dedup |
|---|---|---|
| `NEW_DEVICE` | Unknown device first seen (within 10 min) | Once per MAC per 24h |
| `HIGH_TRAFFIC` | >500 MB in 5 minutes | Once per IP per 1h |
| `STEALTH_DEVICE` | Passive-only device, >5 min old, never seen by nmap | Once per MAC per 24h |
| `IP_REASSIGNED` | IP now seen with a different MAC than before | Once per IP per 24h |
| `CVE_FOUND` | CVE found on a device port | Once per CVE+IP per 24h |

---

### `open_ports`
All open ports found by the deep CVE scan. Cleared and rewritten on each scan (zero-downtime swap).

| Column | Type | Description |
|---|---|---|
| `id` | INTEGER PK | — |
| `device_id` | INTEGER FK → devices.id | — |
| `ip` | TEXT | — |
| `port` | INTEGER | — |
| `service` | TEXT | Service name from nmap |
| `scan_time` | TIMESTAMP | — |

---

### `cve_findings`
CVE hits per port per device. Cleared and rewritten on each scan (zero-downtime swap).

| Column | Type | Description |
|---|---|---|
| `id` | INTEGER PK | — |
| `device_id` | INTEGER FK → devices.id | — |
| `ip` | TEXT | — |
| `port` | INTEGER | — |
| `service` | TEXT | — |
| `cve_id` | TEXT | e.g. CVE-2023-1234 |
| `severity` | TEXT | CRITICAL / HIGH / MEDIUM / LOW |
| `description` | TEXT | — |
| `timestamp` | TIMESTAMP | — |

---

## Table Relationships

```
networks ──< device_network >── devices
                │
                ├──< connection_logs
                ├──< traffic_stats
                └── anomalies (network_id)

devices ──< open_ports
devices ──< cve_findings
devices ──< connection_logs
devices ──< traffic_stats
```

**Key rules:**
- IP is stored in `device_network`, not `devices` — same device, different IPs per network
- `anomalies.mac` is a plain string, not a FK — alerts survive device cleanup
- `source = 'passive'` means the device was never seen by nmap, only by ARP traffic
- `open_ports` and `cve_findings` use a zero-downtime swap: new rows inserted first, old rows deleted at the end by timestamp
