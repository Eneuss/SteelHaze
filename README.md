# SteelHaze V2

Network security monitor with a web dashboard, persistent storage, traffic monitoring, anomaly detection, and CVE lookups.

The original version is at `/home/eneus/Desktop/SteelHaze/steelhaze/` and is unchanged.

---

## Project Structure

```
SteelHazeV2/
├── main.py                  # Entry point
├── requirements.txt
├── steelhaze.db             # SQLite database (auto-created on first run)
├── src/
│   ├── database.py          # DB init (devices, traffic, anomalies, CVE findings)
│   ├── scanner.py           # Ping scan (-sn), dynamic network detection
│   ├── monitor.py           # Continuous 30s monitoring loop
│   ├── traffic_monitor.py   # Scapy packet sniffer (bytes/packets per IP)
│   ├── anomaly_detector.py  # Detects HIGH_TRAFFIC, ODD_HOURS, NEW_DEVICE
│   ├── nvd_lookup.py        # NVD API CVE lookup by port
│   ├── nvd_scanner.py       # Deep service version scan + CVE lookup
│   └── app.py               # Flask REST API + dashboard server
└── templates/
    └── dashboard.html       # Web UI (dark theme, auto-refreshes every 30s)
```

---

## How to Run

### First time setup

```bash
cd /home/eneus/Desktop/SteelHazeV2
python3 -m venv venv
venv/bin/pip install -r requirements.txt
```

### Normal mode (recommended — needs root for packet sniffing)

```bash
sudo venv/bin/python main.py
```

Then open **http://localhost:5000** in your browser.

### Without root (no traffic stats, everything else works)

```bash
venv/bin/python main.py --no-traffic
```

### Deep CVE scan (run separately — slow, queries NVD API)

```bash
sudo venv/bin/python main.py --deep-scan
```

Results appear in the **CVE Findings** tab of the dashboard.

### One-shot scan (prints devices to terminal, no web UI)

```bash
venv/bin/python main.py --scan-only
```

---

## What It Does

- **Scans the network** every 30 seconds using nmap ping scan (`-sn`) — finds all live hosts, not just those with open ports
- **Detects the network automatically** from the active interface (no hardcoded IP range)
- **Persists everything** to a SQLite database so history is kept across restarts
- **Monitors traffic** with Scapy — tracks bytes sent/received and packet counts per device
- **Detects anomalies**: high traffic (>100 MB/min), odd-hours activity (02:00–06:00), new unknown devices
- **CVE deep scan**: scans open ports with service version detection and queries the NVD API for known vulnerabilities, saved to the database
- **Web dashboard** at `http://localhost:5000` with five tabs:
  - **Devices** — all devices seen in the last 24h, mark as known
  - **Traffic** — bandwidth usage per device
  - **Anomalies** — alerts from the last 24h
  - **CVE Findings** — results from the deep scanner with links to NVD
  - **Timeline** — bar chart of unique devices per day over 7 days

---

## Database Structure

The database has 7 tables. Each is explained below.

---

### `networks`
Every unique network SteelHaze has ever seen. A network is identified by its gateway IP + subnet combination.

| Column | Description |
|---|---|
| `id` | Unique ID |
| `ssid` | Wi-Fi network name (if available) |
| `gateway_ip` | Router IP address |
| `subnet` | Network range (e.g. 192.168.1.0/24) |
| `interface` | Network interface used (e.g. eth0, wlan0) |
| `first_seen` | When this network was first detected |
| `last_seen` | When it was last detected |

---

### `devices`
The hardware identity of each device. A device is identified by its MAC address. **The IP address is not stored here** because it can change — see `device_network` below.

| Column | Description |
|---|---|
| `id` | Unique ID |
| `mac` | MAC address (hardware identifier) |
| `hostname` | Device hostname (if available) |
| `first_seen` | When this device was first detected |
| `last_seen` | When it was last detected |

---

### `device_network`
Links a device to a network, storing the IP it had on that network. Also tracks whether the device has been marked as known.

| Column | Description |
|---|---|
| `id` | Unique ID |
| `device_id` | Reference to `devices` |
| `network_id` | Reference to `networks` |
| `ip` | IP address of the device on this network |
| `is_known` | Whether the device has been marked as known |
| `first_seen` | First time this device appeared on this network |
| `last_seen` | Last time this device appeared on this network |

> A device can be known on one network and unknown on another — that's why `is_known` lives here and not in `devices`.

---

### `connection_logs`
A timestamped log of every scan event — each time a device was seen on a network.

| Column | Description |
|---|---|
| `id` | Unique ID |
| `device_id` | Reference to `devices` |
| `network_id` | Reference to `networks` |
| `ip` | IP address at the time of the scan |
| `status` | Scan result status |
| `timestamp` | When the event occurred |

---

### `traffic_stats`
Bandwidth snapshots captured by the packet sniffer. One row per device per scan interval.

| Column | Description |
|---|---|
| `id` | Unique ID |
| `device_id` | Reference to `devices` |
| `network_id` | Reference to `networks` |
| `ip` | IP address at the time of capture |
| `bytes_sent` | Bytes sent by the device in this interval |
| `bytes_received` | Bytes received by the device in this interval |
| `packets` | Total packet count in this interval |
| `timestamp` | When the snapshot was taken |

---

### `anomalies`
Alerts generated by the anomaly detector. Types: `HIGH_TRAFFIC`, `ODD_HOURS`, `NEW_DEVICE`.

| Column | Description |
|---|---|
| `id` | Unique ID |
| `type` | Anomaly type (HIGH_TRAFFIC, ODD_HOURS, NEW_DEVICE) |
| `ip` | IP address involved |
| `mac` | MAC address involved |
| `hostname` | Hostname involved |
| `details` | Human-readable description of the anomaly |
| `network_id` | Reference to `networks` |
| `timestamp` | When the anomaly was detected |
| `acknowledged` | Whether the alert has been dismissed |

---

### `cve_findings`
Vulnerabilities found by the deep CVE scanner. Each row is a unique combination of device, port, and CVE ID — so repeated scans never create duplicates.

| Column | Description |
|---|---|
| `id` | Unique ID |
| `device_id` | Reference to `devices` |
| `ip` | IP address at time of scan |
| `port` | Port the vulnerability was found on |
| `service` | Service name running on that port |
| `cve_id` | CVE identifier (e.g. CVE-2021-44228) |
| `severity` | Severity level (e.g. HIGH, CRITICAL) |
| `description` | Summary of the vulnerability |
| `timestamp` | When the finding was recorded |
