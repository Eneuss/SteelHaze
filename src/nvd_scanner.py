#!/usr/bin/env python3
"""
Deep CVE scan: detects open ports + service versions on all hosts,
queries the NVD API, and saves findings to the database.
Run this separately from the continuous monitor — it is slow.
"""
import nmap
import sqlite3
from datetime import datetime
from scanner import get_local_network
from nvd_lookup import lookup_cve
from database import DB_PATH


def run_nvd_scan(network_range=None):
    if network_range is None:
        network_range = get_local_network()

    print(f"\n[SteelHaze] Deep CVE scan on: {network_range}")
    print("[SteelHaze] Detecting open ports and service versions (this may take a while)...\n")

    nm = nmap.PortScanner()
    try:
        nm.scan(
            hosts=network_range,
            arguments="-sV -T4 --open -p- --host-timeout 10m",
        )
    except Exception as e:
        print(f"[SteelHaze] CVE scan error: {e}")
        return

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    found = 0

    for host in nm.all_hosts():
        tcp_ports = nm[host].get("tcp", {})
        if not tcp_ports:
            continue
        found += 1

        hostname = nm[host].hostname() or "Unknown"
        mac = nm[host]["addresses"].get("mac", "N/A")

        # Resolve device_id from DB
        cursor.execute("SELECT device_id FROM device_network WHERE ip = ? ORDER BY last_seen DESC LIMIT 1", (host,))
        row = cursor.fetchone()
        device_id = row[0] if row else None

        print(f"{'='*60}")
        print(f"  Host  : {host}  ({hostname})")
        print(f"  MAC   : {mac}")
        print(f"  Ports : {list(tcp_ports.keys())}")
        print(f"{'='*60}")

        for port, data in tcp_ports.items():
            service = data.get("name", "unknown")
            product = data.get("product", "")
            version = data.get("version", "")
            label = f"{service} {product} {version}".strip()
            print(f"\n  [Port {port}/tcp]  {label}")
            print(f"  --- CVE Lookup (NVD) ---")

            cves = lookup_cve(port, service=service, product=product)
            if not cves:
                print("  No CVE results found for this port.")
            for cve in cves:
                print(f"  {cve['id']} | {cve['severity']}")
                print(f"  {cve['description']}\n")

                if device_id:
                    cursor.execute('''
                        INSERT OR IGNORE INTO cve_findings
                            (device_id, ip, port, service, cve_id, severity, description, timestamp)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (device_id, host, port, label, cve["id"], cve["severity"],
                          cve["description"], datetime.now()))

    conn.commit()
    conn.close()

    if found == 0:
        print("[SteelHaze] No devices with open ports found on the network.")
    else:
        print(f"\n[SteelHaze] Deep scan complete. {found} host(s) with open ports.")


if __name__ == "__main__":
    run_nvd_scan()
