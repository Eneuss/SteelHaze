# SteelHaze
 
Network security monitor for Linux (built for Raspberry Pi). It scans your network, watches traffic, flags anomalies, looks up CVEs, and shows everything on a web dashboard. Optional Telegram alerts and e-paper display support.
 
One command starts both the monitor loop and the dashboard on port 5000.
 
---
 
## Requirements
 
- Linux with **root** access (needed for packet sniffing and reading MAC addresses)
- Python 3.9+
- The `nmap` binary installed (step 1 below)
- A wired or wireless interface with a default route
---
 
## Quick Start
 
```bash
# 1. Install nmap (required system package)
sudo apt update && sudo apt install -y nmap
 
# 2. Get the code
git clone <your-repo-url> SteelHaze
cd SteelHaze
 
# 3. Install Python dependencies
#    On Raspberry Pi OS / Debian 12+, add --break-system-packages
sudo pip3 install -r requirements.txt --break-system-packages
 
# 4. Run (must be root)
sudo python3 main.py
```
 
Open the dashboard at **http://localhost:5000** (or `http://<pi-ip>:5000` from another machine).
Press **Ctrl+C** to stop.
 
> **Why root?** Scapy needs raw sockets for sniffing and nmap needs elevated privileges to read MAC addresses. Without root the dashboard still loads, but device MACs, passive detection, and traffic stats will be empty.
 
> **Using a virtualenv?** A `venv/` is gitignored, so it's a clean option. Since the program runs as root, start it with `sudo venv/bin/python main.py`, not a bare `sudo python main.py`.
 
---
 
## Dependencies
 
`nmap` is the only required system binary. Everything else is in `requirements.txt`:
 
| Package | Used for |
|---|---|
| `flask` | Web dashboard + REST API |
| `python-nmap` | Bindings for the `nmap` binary |
| `netifaces` | Reads default interface, gateway, subnet |
| `scapy` | Passive ARP sniffer and per-IP traffic sniffer |
| `requests` | NVD CVE API + Telegram |
| `fpdf2` | PDF report generation |
| `matplotlib` | Charts in the PDF report |
 
---
 
## What It Does
 
- **Scans every 30s** with nmap on the default interface's subnet to find all live hosts.
- **Passive detection** runs alongside: an ARP sniffer plus the kernel ARP cache catch devices that don't respond to nmap (IoT, AP-isolated, stealthy hosts).
- **Traffic monitoring** with Scapy: bytes and packets per device.
- **Deep CVE scan** every 30 min: full port scan, detects service versions, queries the NVD API. New devices trigger an immediate scan.
- **Anomaly detection**: high traffic, new unknown devices, stealth (passive-only) devices, and CVE findings.
- **Per-network databases**: each Wi-Fi network (by SSID) gets its own SQLite file, so history stays separate and is preserved across reconnects. The active file switches automatically if you roam to a different network.
### Dashboard pages
 
| Page | URL | Shows |
|---|---|---|
| Devices | `/` | Scanned devices + passive-only detections |
| Traffic | `/traffic` | Bandwidth per device (last 24h) |
| Anomalies | `/anomalies` | All alerts (last 24h) |
| CVE Findings | `/cves` | Open ports + CVEs per host |
| Charts | `/timeline` | Devices/day, CVE severity, top traffic, anomalies/day |
 
---
 
## Telegram Notifications (optional)
 
Disabled by default. To enable, create `telegram.cfg` in the project root:
 
```ini
[telegram]
token = your_bot_token_here
chat_id = your_chat_id_here
```
 
If the file is missing or empty, the project runs normally with no errors.
 
**Getting a token and chat ID:**
1. Message `@BotFather` on Telegram, send `/newbot`, follow the steps to get a token.
2. Message your bot once, then open `https://api.telegram.org/bot<TOKEN>/getUpdates`. Your `chat_id` is under `message.chat.id`.
**You'll get:** real-time alerts for new/stealth devices and CVEs, scheduled PDF reports at 08:00 and 20:00, and an on-demand report by sending `/report` to the bot.
 
---
 
## E-Paper Display (optional)
 
Supports a **Waveshare 2.13" V4** screen over SPI. If no display is connected or the library is missing, the monitor runs identically and nothing crashes.
 
```bash
# Pillow is needed to draw the image
sudo pip3 install Pillow --break-system-packages
 
# Enable SPI (raspi-config > Interface Options > SPI)
 
# Install the Waveshare library system-wide so root can import it
git clone https://github.com/waveshare/e-Paper.git
cd e-Paper/RaspberryPi_JetsonNano/python && sudo python3 setup.py install
```
 
The screen shows SSID, subnet, device/unknown counts, anomalies, and CVEs, refreshing twice per scan cycle.
 
---
 
## Project Structure
 
```
SteelHaze/
├── main.py              # Entry point: starts monitor loop + dashboard
├── requirements.txt
├── src/                 # scanner, monitor, traffic/passive sniffers,
│                        # anomaly detector, NVD lookup, Telegram, report,
│                        # e-paper, database, Flask app
├── templates/           # dashboard pages
└── static/style.css
```
 
Per-network databases (`steelhaze_<ssid>.db`) and `telegram.cfg` are created at runtime and gitignored.
 
