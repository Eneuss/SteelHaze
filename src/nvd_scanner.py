"""
Deep CVE scan: detects open ports + service versions on all hosts,
queries the NVD API, and saves findings to the database.
"""
import nmap
from datetime import datetime
from scanner import get_local_network, get_local_ip, get_local_ips
from nvd_lookup import lookup_cve
from database import db
from anomaly_detector import save_cve_anomaly


def run_nvd_scan(network_range=None):
    if network_range is None:
        network_range = get_local_network()

    #skip our own IPs
    local_ips = get_local_ips()
    fallback = get_local_ip()
    if fallback and fallback not in local_ips:
        local_ips.append(fallback)

    print(f"\n[SteelHaze] Deep CVE scan on: {network_range}")
    if local_ips:
        print(f"[SteelHaze] Excluding local device IPs: {', '.join(local_ips)}")
    print("[SteelHaze] Detecting open ports and service versions (this may take a while)...\n")

    scan_args = "-sV -T4 --open -p- --host-timeout 10m"
    if local_ips:
        scan_args += f" --exclude {','.join(local_ips)}"

    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=network_range, arguments=scan_args)
    except Exception as e:
        print(f"[SteelHaze] CVE scan error: {e}")
        return

    scan_start = datetime.utcnow()
    found = 0

    for host in nm.all_hosts():
        tcp_ports = nm[host].get("tcp", {})
        if not tcp_ports:
            continue
        found += 1

        hostname = nm[host].hostname() or "Unknown"
        mac = nm[host]["addresses"].get("mac", "N/A")

        print(f"{'='*60}")
        print(f"  Host  : {host}  ({hostname})")
        print(f"  MAC   : {mac}")
        print(f"  Ports : {list(tcp_ports.keys())}")
        print(f"{'='*60}")

        #one conn per host so monitor can write in between
        conn = db()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT device_id FROM device_network WHERE ip = ? ORDER BY last_seen DESC LIMIT 1",
            (host,)
        )
        row = cursor.fetchone()
        device_id = row["device_id"] if row else None

        #cache CVE results per port — avoid calling the NVD API twice per port
        port_cves = {}
        for port, data in tcp_ports.items():
            service = data.get("name", "unknown")
            product = data.get("product", "")
            version = data.get("version", "")
            label   = f"{service} {product} {version}".strip()
            print(f"\n  [Port {port}/tcp]  {label}")
            print(f"  --- CVE Lookup (NVD) ---")

            cursor.execute(
                "INSERT INTO open_ports (device_id, ip, port, service) VALUES (?, ?, ?, ?)",
                (device_id, host, port, label)
            )

            cves = lookup_cve(port, service=service, product=product, version=version)
            port_cves[port] = cves
            if not cves:
                print("  No CVE results found for this port.")
            for cve in cves:
                print(f"  {cve['id']} | {cve['severity']}")
                print(f"  {cve['description']}\n")
                cursor.execute(
                    "SELECT 1 FROM cve_findings WHERE ip = ? AND port = ? AND cve_id = ?",
                    (host, port, cve["id"])
                )
                if not cursor.fetchone():
                    cursor.execute('''
                        INSERT INTO cve_findings
                            (device_id, ip, port, service, cve_id, severity, description, timestamp)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (device_id, host, port, label, cve["id"], cve["severity"],
                          cve["description"], datetime.utcnow()))

        conn.commit()
        conn.close()

        #save anomalies using cached CVE results
        for port, cves in port_cves.items():
            for cve in cves:
                if cve['severity'] in ('CRITICAL', 'HIGH'):
                    save_cve_anomaly(host, mac, cve['id'], cve['severity'], cve['description'])

    #clean up old scan rows — only for hosts found in this run so that
    #devices temporarily down during a scan keep their previous CVE history,
    #and targeted single-host scans don't wipe records for other devices
    scanned_hosts = list(nm.all_hosts())
    if scanned_hosts:
        placeholders = ','.join('?' * len(scanned_hosts))
        conn = db()
        cursor = conn.cursor()
        cursor.execute(
            f"DELETE FROM cve_findings WHERE ip IN ({placeholders}) AND timestamp < ?",
            (*scanned_hosts, scan_start)
        )
        cursor.execute(
            f"DELETE FROM open_ports WHERE ip IN ({placeholders}) AND scan_time < ?",
            (*scanned_hosts, scan_start)
        )
        conn.commit()
        conn.close()

    if found == 0:
        print("[SteelHaze] No devices with open ports found on the network.")
    else:
        print(f"\n[SteelHaze] Deep scan complete. {found} host(s) with open ports.")


if __name__ == "__main__":
    run_nvd_scan()
