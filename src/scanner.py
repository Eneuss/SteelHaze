#!/usr/bin/env python3
import nmap
import netifaces
import ipaddress
import socket
import subprocess
from datetime import datetime


_mac_vendor_cache = {}

def _load_mac_vendors():
    """Load nmap's MAC prefix database into memory (runs once)."""
    if _mac_vendor_cache:
        return
    try:
        with open("/usr/share/nmap/nmap-mac-prefixes", "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    parts = line.split(None, 1)
                    if len(parts) == 2:
                        _mac_vendor_cache[parts[0].upper()] = parts[1]
    except Exception:
        pass


def lookup_mac_vendor(mac):
    """Return the vendor name for a MAC address, or None if unknown."""
    if not mac or mac == "N/A":
        return None
    _load_mac_vendors()
    prefix = mac.replace(":", "").replace("-", "").upper()[:6]
    return _mac_vendor_cache.get(prefix)


def resolve_hostname(ip, mac="", nmap_hostname=""):
    """Try multiple methods to resolve a hostname for the given IP."""
    # 1. Use nmap's result if it got something useful
    if nmap_hostname and nmap_hostname.lower() not in ("", "unknown"):
        return nmap_hostname

    # 2. Reverse DNS
    try:
        name = socket.gethostbyaddr(ip)[0]
        if name and name != ip:
            return name
    except Exception:
        pass

    # 3. NetBIOS (good for Windows, printers, NAS)
    try:
        result = subprocess.run(
            ["nmblookup", "-A", ip], capture_output=True, text=True, timeout=3
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            if line and not line.startswith("Looking") and "<00>" in line:
                name = line.split()[0].strip()
                if name and name != ip:
                    return name
    except Exception:
        pass

    # 4. mDNS via avahi (good for Apple, IoT, Linux devices)
    try:
        result = subprocess.run(
            ["avahi-resolve", "-a", ip], capture_output=True, text=True, timeout=3
        )
        parts = result.stdout.strip().split()
        if len(parts) >= 2:
            name = parts[1].rstrip(".")
            if name and name != ip:
                return name
    except Exception:
        pass

    # 5. MAC vendor fallback — at least shows the manufacturer
    vendor = lookup_mac_vendor(mac)
    if vendor:
        return vendor

    return "Unknown"


def get_local_network():
    """Detect the local network from the default gateway interface."""
    return get_network_info()["subnet"]


def get_network_info():
    """Return current network metadata: gateway, subnet, interface, ssid."""
    try:
        import subprocess
        gateways = netifaces.gateways()
        default = gateways.get("default", {}).get(netifaces.AF_INET)
        if not default:
            return {"gateway_ip": "unknown", "subnet": "192.168.1.0/24", "interface": "unknown", "ssid": None}
        gateway_ip = default[0]
        iface = default[1]
        addrs = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [{}])[0]
        ip = addrs.get("addr", "")
        netmask = addrs.get("netmask", "255.255.255.0")
        if not ip:
            return {"gateway_ip": gateway_ip, "subnet": "192.168.1.0/24", "interface": iface, "ssid": None}
        network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
        ssid = None
        try:
            result = subprocess.run(["iwgetid", iface, "-r"], capture_output=True, text=True, timeout=2)
            ssid = result.stdout.strip() or None
        except Exception:
            pass
        return {"gateway_ip": gateway_ip, "subnet": str(network), "interface": iface, "ssid": ssid}
    except Exception:
        return {"gateway_ip": "unknown", "subnet": "192.168.1.0/24", "interface": "unknown", "ssid": None}


def scan_network(network_range=None):
    """
    Ping-scan the local network and return a list of discovered devices.
    Uses -sn (no port scan) to find all live hosts quickly.
    Falls back to the detected local network if no range is given.
    """
    if network_range is None:
        network_range = get_local_network()

    print(f"[{datetime.now().strftime('%H:%M:%S')}] Scanning {network_range}...")

    nm = nmap.PortScanner()
    # -sn: ping scan (finds all hosts, not just those with open ports)
    # -T4: faster timing
    # --min-parallelism 10: speed up ARP/ICMP probes
    nm.scan(hosts=network_range, arguments="-sn -T4 --min-parallelism 10")

    devices = []
    for host in nm.all_hosts():
        hostnames = nm[host].get("hostnames", [{}])
        nmap_hostname = hostnames[0].get("name", "") if hostnames else ""
        mac = nm[host]["addresses"].get("mac", "N/A")
        hostname = resolve_hostname(host, mac, nmap_hostname)
        device = {
            "ip": host,
            "mac": mac,
            "hostname": hostname,
            "status": nm[host]["status"]["state"],
            "timestamp": datetime.now().isoformat(),
        }
        devices.append(device)

    print(f"[{datetime.now().strftime('%H:%M:%S')}] Found {len(devices)} device(s).")
    return devices
