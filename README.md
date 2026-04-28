# SteelHaze

Network security monitor with a web dashboard, persistent storage, passive device detection, traffic monitoring, anomaly detection, CVE lookups, and optional e-paper display support.

---

## Project Structure

```
SteelHazeV2/
├── main.py                  # Entry point
├── steelhaze_<ssid>.db      # Per-network SQLite databases (auto-created, gitignored)
├── src/
│   ├── database.py          # DB schema, connection helper, per-SSID DB switching
│   ├── scanner.py           # nmap ping scan, default interface/gateway detection
│   ├── monitor.py           # Main 30s monitoring loop, device/traffic persistence
│   ├── traffic_monitor.py   # Scapy IP sniffer (bytes/packets per IP)
│   ├── passive_scanner.py   # Passive ARP sniffer + ARP cache reader
│   ├── anomaly_detector.py  # Detects HIGH_TRAFFIC, NEW_DEVICE, STEALTH_DEVICE, CVE_FOUND
│   ├── nvd_lookup.py        # NVD API CVE lookup by service name
│   ├── nvd_scanner.py       # Deep all-port scan + CVE lookup (runs every 30 min)
│   ├── scan_state.py        # Shared in-memory scan state between monitor and Flask
│   ├── telegram_notify.py   # Telegram bot — alerts, scheduled reports, /report command
│   ├── report.py            # PDF report generator (fpdf2 + matplotlib charts)
│   ├── epaper_display.py    # Waveshare 2.13" V4 e-paper display (optional)
│   └── app.py               # Flask REST API + page routes
├── templates/
│   ├── base.html            # Shared layout: header, nav, stats bar, JS helpers
│   ├── devices.html         # / — active devices + passive detections per interface
│   ├── traffic.html         # /traffic — bandwidth per device
│   ├── anomalies.html       # /anomalies — alerts
│   ├── cves.html            # /cves — CVE findings per host
│   └── timeline.html        # /timeline — charts (devices/day, CVE severity, traffic, anomalies)
├── telegram.cfg             # Telegram bot config (gitignored — create manually)
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
pip install flask python-nmap requests fpdf2 matplotlib
```

| Package | Used for |
|---|---|
| `flask` | Web dashboard |
| `python-nmap` | nmap Python bindings |
| `requests` | Telegram API calls |
| `fpdf2` | PDF report generation |
| `matplotlib` | Charts embedded in reports |

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
- **Anomaly detection**: high traffic, new unknown devices, stealth devices (passive-only)
- **Telegram notifications**: optional bot that sends real-time alerts and scheduled PDF reports at 08:00 and 20:00
- **Per-network databases**: each WiFi network (identified by SSID) gets its own SQLite file — data stays separate, history is preserved when reconnecting to a known network

### Dashboard pages

| Page | URL | Shows |
|---|---|---|
| Devices | `/` | nmap-scanned devices + passive-only section per interface card |
| Traffic | `/traffic` | Bandwidth per device (last 24h) |
| Anomalies | `/anomalies` | All alerts (last 24h) |
| CVE Findings | `/cves` | Open ports + CVEs grouped per host |
| Charts | `/timeline` | Devices/day, CVE severity, top traffic, anomalies/day |

---

## Telegram Notifications (optional)

Telegram support is disabled by default. To enable it, create a `telegram.cfg` file in the project root:

```ini
[telegram]
token = your_bot_token_here
chat_id = your_chat_id_here
```

If the file is missing or the fields are empty, the project runs normally with no errors.

### How to get a token and chat ID

1. Open Telegram and message `@BotFather` — send `/newbot` and follow the steps to get a token
2. Message your new bot once, then open `https://api.telegram.org/bot<TOKEN>/getUpdates` in a browser — your `chat_id` is under `message.chat.id`

### What triggers a notification

| Event | When |
|---|---|
| `NEW_DEVICE` | Unknown device joins the network |
| `STEALTH_DEVICE` | Device visible only via ARP — never responds to scan |
| `CVE_FOUND` | A CRITICAL or HIGH severity CVE is found on a device |
| Scheduled report | Every day at 08:00 and 20:00 — text summary + PDF report |
| `/report` command | Send `/report` to the bot at any time to receive a PDF report on demand |

Notifications inherit the existing dedup rules — no extra cooldown needed.

### PDF report contents

The PDF report is generated by `src/report.py` and includes:

- **Stats bar** — total devices, active, unknown, unacknowledged anomalies, CVE count
- **Devices table** — all devices seen in the last 24h (IP, MAC, label, source, last seen)
- **Anomalies table** — deduplicated by type + IP; repeated events collapse to one row with a count prefix (`x4 Device detected passively...`)
- **CVE findings** — all current CVE findings with severity highlighted
- **Charts** — devices seen per day and anomalies per day (last 7 days)

Requires `fpdf2` and `matplotlib`:
```bash
sudo pip3 install fpdf2 matplotlib --break-system-packages
```

---

## E-Paper Display (optional)

Supports a **Waveshare 2.13" V4** e-paper screen connected via SPI. If no display is connected or the library is missing the monitor runs identically — nothing crashes.

### Setup

```bash
# clone the official Waveshare library
git clone https://github.com/waveshare/e-Paper.git

# install it system-wide so sudo python3 can find it
cd e-Paper/RaspberryPi_JetsonNano/python && sudo python3 setup.py install
```

### What it shows

Updates twice per scan cycle — once at the start (scanning state) and once at the end (results):

```
┌──────────────────────────────────────────────┐
│ SteelHaze         (↑)         ◯     14:32  │  ← header: radar + scan dot + time
├──────────────────────────────────────────────┤
│ HomeWiFi                                     │
│ 192.168.1.0/24                               │
├──────────────────────────────────────────────┤
│ Devices: 12              Unknown: 3          │
├──────────────────────────────────────────────┤
│ Anomalies: 2                    CVEs: 5      │
├──────────────────────────────────────────────┤
│ Updated: 28 Apr  14:32        SCANNING...    │
└──────────────────────────────────────────────┘
```

| Element | Behaviour |
|---|---|
| Radar `(↑)` | Rotates 45° each scan cycle — completes 360° every 4 minutes |
| Scan dot `◯` / `●` | Hollow = idle, filled = scan in progress |
| `SCANNING...` | Appears in footer only during active scan |
| Display on shutdown | `Ctrl+C` puts the display to sleep cleanly |

---

## Database

### One file per network

SteelHaze creates a separate SQLite database for each WiFi network it encounters, named after the SSID:

```
steelhaze_HomeWiFi.db
steelhaze_OfficeNetwork.db
steelhaze_wired.db          # used when no SSID is detected (ethernet)
```

At startup, `main.py` reads the current SSID via `iwgetid` and opens the matching file, creating it with the full schema if it does not exist. The monitor loop checks the SSID on every 30s scan cycle — if it changes (e.g. the Pi roamed to a different network), `set_active_ssid()` in `database.py` switches the active file within one interval. All components (`app.py`, `monitor.py`, `passive_scanner.py`, `anomaly_detector.py`, `telegram_notify.py`, `report.py`) connect through the central `db()` helper which always reads the current `DB_PATH`, so the switch is transparent.

Reconnecting to a known SSID reopens the existing file exactly where it left off — full history is preserved.

All database files are gitignored (`*.db`).

---

### Schema — 7 tables, all timestamps UTC

---

### `networks`
One row per unique subnet session within this SSID's database. Identified by `(gateway_ip, subnet)`.

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
One row per unique physical device. Identity = MAC address. IP is not stored here — it lives in `device_network` because the same device can have different IPs across sessions.

| Column | Type | Description |
|---|---|---|
| `id` | INTEGER PK | — |
| `mac` | TEXT | Lowercase MAC address, null if nmap could not read it |
| `label` | TEXT | User-given nickname |
| `first_seen` | TIMESTAMP | — |
| `last_seen` | TIMESTAMP | — |

---

### `device_network`
Junction table linking a device to a network session. Holds the IP and how the device was discovered.

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

> `source` upgrades from `passive` → `nmap` when nmap finds the device. It downgrades `nmap` → `passive` automatically if a device stops responding to scans but is still visible via ARP (missed 5+ consecutive minutes by nmap but present in ARP cache).

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
| `CVE_FOUND` | CVE found on a device port | Once per CVE+IP per 24h |

---

### `open_ports`
All open ports found by the deep CVE scan. Cleared and rewritten on each scan.

| Column | Type | Description |
|---|---|---|
| `id` | INTEGER PK | — |
| `device_id` | INTEGER FK → devices.id | — |
| `ip` | TEXT | — |
| `port` | INTEGER | — |
| `service` | TEXT | Service name + version from nmap |
| `scan_time` | TIMESTAMP | — |

---

### `cve_findings`
CVE hits per port per device. Cleared and rewritten on each scan.

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

### Table relationships

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
- IP is stored in `device_network`, not `devices` — same device can have different IPs across sessions
- All MACs are normalised to lowercase at every write point
- `anomalies.mac` is a plain string, not a FK — alerts survive device cleanup
- `source = 'passive'` means the device was never seen by nmap, only by ARP traffic
- `open_ports` and `cve_findings` are cleared and rewritten each deep scan — old rows deleted by timestamp after new ones are inserted
