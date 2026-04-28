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
    """Return metadata for the default gateway interface."""
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


def scan_all_parallel(on_status=None):
    """Scan via default gateway interface. Returns {iface: {...}}. Never raises."""
    net    = get_network_info()
    iface  = net["interface"]
    subnet = net["subnet"]

    if on_status:
        on_status(iface, subnet, "scanning", None, None)
    try:
        devices = _scan_single(subnet)
        status  = "done" if devices else "no_devices"
        if on_status:
            on_status(iface, subnet, status, None, devices)
        return {iface: {"subnet": subnet, "network_info": net, "devices": devices, "error": None}}
    except Exception as e:
        if on_status:
            on_status(iface, subnet, "error", str(e), None)
        return {iface: {"subnet": subnet, "network_info": net, "devices": [], "error": str(e)}}


def get_local_ips():
    """Return all local non-loopback IPv4 addresses (used to exclude self from CVE scans)."""
    ips = []
    for iface in netifaces.interfaces():
        if iface == "lo":
            continue
        for addr in netifaces.ifaddresses(iface).get(netifaces.AF_INET, []):
            ip = addr.get("addr", "")
            if ip:
                ips.append(ip)
    return ips


def _scan_single(subnet):
    """Run nmap on the given subnet, letting the OS pick the best interface."""
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Scanning {subnet}...")
    nm = nmap.PortScanner()
    nm.scan(hosts=subnet, arguments="-sn -T4 --min-parallelism 10")

    local = set(get_local_ips())
    devices = []
    for host in nm.all_hosts():
        if host in local:
            continue
        devices.append({
            "ip":        host,
            "mac":       nm[host]["addresses"].get("mac", "N/A").lower(),
            "status":    nm[host]["status"]["state"],
            "timestamp": datetime.now().isoformat(),
        })
    return devices
