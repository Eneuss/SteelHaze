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

## Database Tables

| Table | Contents |
|---|---|
| `devices` | IP, MAC, hostname, first/last seen, known flag |
| `connection_logs` | Every scan event per device |
| `traffic_stats` | Bytes sent/received and packets per device per interval |
| `anomalies` | Detected anomalies with type, details, acknowledged flag |
| `cve_findings` | CVE results linked to device, port, service, severity |
