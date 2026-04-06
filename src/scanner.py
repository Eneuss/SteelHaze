#!/usr/bin/env python3
import nmap
import netifaces
import ipaddress
import subprocess
from datetime import datetime


def get_local_network():
    """Return the subnet of the default gateway interface."""
    return get_network_info()["subnet"]


def get_local_ip():
    """Return the local IP of the default gateway interface."""
    try:
        gateways = netifaces.gateways()
        default = gateways.get("default", {}).get(netifaces.AF_INET)
        if not default:
            return None
        iface = default[1]
        addrs = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [{}])[0]
        return addrs.get("addr")
    except Exception:
        return None


def get_network_info():
    """Return metadata for the default gateway interface only (used for DB network records)."""
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


def get_all_interfaces():
    """
    Return a list of all active non-loopback interfaces with their subnet.
    This is what allows scanning both eth0 and wlan0 at the same time.
    """
    interfaces = []
    skip = {"lo"}

    for iface in netifaces.interfaces():
        if iface in skip:
            continue
        addrs = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [])
        for addr in addrs:
            ip = addr.get("addr", "")
            netmask = addr.get("netmask", "")
            if not ip or not netmask:
                continue
            try:
                network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                # skip link-local (169.254.x.x) addresses
                if network.is_link_local:
                    continue
                interfaces.append({"interface": iface, "subnet": str(network), "ip": ip})
            except Exception:
                continue

    return interfaces


def _scan_single(iface, subnet):
    """Run nmap on one interface/subnet and return discovered devices."""
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Scanning {subnet} via {iface}...")
    nm = nmap.PortScanner()
    nm.scan(hosts=subnet, arguments=f"-sn -T4 --min-parallelism 10 -e {iface}")

    devices = []
    for host in nm.all_hosts():
        hostnames = nm[host].get("hostnames", [{}])
        hostname = hostnames[0].get("name", "") if hostnames else ""
        devices.append({
            "ip": host,
            "mac": nm[host]["addresses"].get("mac", "N/A"),
            "hostname": hostname or "Unknown",
            "status": nm[host]["status"]["state"],
            "timestamp": datetime.now().isoformat(),
        })
    return devices


def scan_network(network_range=None):
    """
    Scan all active interfaces (eth0, wlan0, etc.) so no devices are missed
    regardless of how this machine is connected. Results are deduplicated by IP.
    If network_range is given, only that range is scanned (single interface mode).
    """
    if network_range is not None:
        # explicit range requested — fall back to single scan
        info = get_network_info()
        devices = _scan_single(info["interface"], network_range)
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Found {len(devices)} device(s).")
        return devices

    # scan every active interface
    interfaces = get_all_interfaces()
    if not interfaces:
        interfaces = [{"interface": get_network_info()["interface"], "subnet": get_network_info()["subnet"]}]

    seen_ips = set()
    all_devices = []

    for iface_info in interfaces:
        try:
            results = _scan_single(iface_info["interface"], iface_info["subnet"])
            for d in results:
                if d["ip"] not in seen_ips:
                    seen_ips.add(d["ip"])
                    all_devices.append(d)
        except Exception as e:
            print(f"[scanner] Skipping {iface_info['interface']}: {e}")

    print(f"[{datetime.now().strftime('%H:%M:%S')}] Total devices found: {len(all_devices)}.")
    return all_devices
