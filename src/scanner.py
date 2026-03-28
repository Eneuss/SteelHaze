#!/usr/bin/env python3
import nmap
import netifaces
import ipaddress
import socket
import subprocess
from datetime import datetime


# ── MAC vendor lookup ─────────────────────────────────────────────────────────

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


# ── mDNS cache (built once per scan via avahi-browse) ─────────────────────────

def build_mdns_cache():
    """
    Run avahi-browse once to collect all mDNS device announcements on the network.
    Returns a dict of {ip: hostname}.
    This is far more effective than avahi-resolve per-IP because it collects
    passive announcements from all devices at once.
    """
    cache = {}
    try:
        result = subprocess.run(
            ["avahi-browse", "-a", "-r", "-t", "--parsable"],
            capture_output=True, text=True, timeout=8
        )
        current_name = None
        for line in result.stdout.splitlines():
            parts = line.split(";")
            # Resolved lines start with '=' and have 10 fields:
            # =;iface;proto;name;type;domain;hostname;addr_type;ip;port;txt
            if len(parts) >= 9 and parts[0] == "=":
                name = parts[3].strip()
                ip = parts[8].strip()
                if ip and name and ip != "":
                    # Prefer the most readable name (skip UUIDs/random strings)
                    if ip not in cache or len(name) < len(cache[ip]):
                        cache[ip] = name
    except Exception:
        pass
    return cache


# ── Hostname resolution ───────────────────────────────────────────────────────

def resolve_hostname(ip, mac="", nmap_hostname="", mdns_cache=None):
    """
    Try multiple methods to resolve a human-readable name for the given IP.
    Order: nmap result → mDNS cache → reverse DNS → NetBIOS → MAC vendor.
    """
    # 1. nmap result (from -R flag or script output)
    if nmap_hostname and nmap_hostname.lower() not in ("", "unknown"):
        return nmap_hostname

    # 2. mDNS cache from avahi-browse (most reliable for Apple, Linux, modern IoT)
    if mdns_cache and ip in mdns_cache:
        return mdns_cache[ip]

    # 3. Reverse DNS
    try:
        name = socket.gethostbyaddr(ip)[0]
        if name and name != ip:
            return name
    except Exception:
        pass

    # 4. NetBIOS (Windows PCs, printers, NAS)
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

    # 5. MAC vendor — always works for any device with a registered MAC
    vendor = lookup_mac_vendor(mac)
    if vendor:
        return vendor

    return "Unknown"


# ── Network info ──────────────────────────────────────────────────────────────

def get_local_network():
    """Detect the local network from the default gateway interface."""
    return get_network_info()["subnet"]


def get_network_info():
    """Return current network metadata: gateway, subnet, interface, ssid."""
    try:
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


# ── Scan ──────────────────────────────────────────────────────────────────────

def scan_network(network_range=None):
    """
    Scan the local network and return a list of discovered devices.
    - Builds an mDNS cache first via avahi-browse (catches Apple, Linux, IoT)
    - Uses nmap -sn with -R (DNS) and --script=nbstat (Windows NetBIOS)
    - Falls back to reverse DNS, then NetBIOS, then MAC vendor per device
    """
    if network_range is None:
        network_range = get_local_network()

    print(f"[{datetime.now().strftime('%H:%M:%S')}] Scanning {network_range}...")

    # Build mDNS map once before the scan
    mdns_cache = build_mdns_cache()
    if mdns_cache:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] mDNS: found {len(mdns_cache)} device(s) via avahi-browse")

    nm = nmap.PortScanner()
    # -sn     : ping scan — finds all live hosts without port scanning
    # -R      : force reverse DNS lookup for every host
    # -T4     : faster timing
    # --script=nbstat : query NetBIOS name service (Windows, printers, NAS)
    # --min-parallelism 10 : speed up probes
    nm.scan(hosts=network_range, arguments="-sn -R -T4 --script=nbstat --min-parallelism 10")

    devices = []
    for host in nm.all_hosts():
        hostnames = nm[host].get("hostnames", [{}])
        nmap_hostname = hostnames[0].get("name", "") if hostnames else ""

        # Also check nmap script output for nbstat result
        scripts = nm[host].get("hostscript", [])
        for s in scripts:
            if s.get("id") == "nbstat" and "NetBIOS name:" in s.get("output", ""):
                for part in s["output"].split(","):
                    if "NetBIOS name:" in part:
                        nb_name = part.split("NetBIOS name:")[1].strip().split()[0]
                        if nb_name and nb_name != "<unknown>":
                            nmap_hostname = nmap_hostname or nb_name

        mac = nm[host]["addresses"].get("mac", "N/A")
        hostname = resolve_hostname(host, mac, nmap_hostname, mdns_cache)
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
