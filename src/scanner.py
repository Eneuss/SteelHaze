#!/usr/bin/env python3
import nmap
import netifaces
import ipaddress
from datetime import datetime


def get_local_network():
    """Detect the local network from the default gateway interface."""
    try:
        gateways = netifaces.gateways()
        default = gateways.get("default", {}).get(netifaces.AF_INET)
        if not default:
            return "192.168.1.0/24"
        iface = default[1]
        addrs = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [{}])[0]
        ip = addrs.get("addr", "")
        netmask = addrs.get("netmask", "255.255.255.0")
        if not ip:
            return "192.168.1.0/24"
        network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
        return str(network)
    except Exception:
        return "192.168.1.0/24"


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
        hostname = hostnames[0].get("name", "") if hostnames else ""
        device = {
            "ip": host,
            "mac": nm[host]["addresses"].get("mac", "N/A"),
            "hostname": hostname or "Unknown",
            "status": nm[host]["status"]["state"],
            "timestamp": datetime.now().isoformat(),
        }
        devices.append(device)

    print(f"[{datetime.now().strftime('%H:%M:%S')}] Found {len(devices)} device(s).")
    return devices
