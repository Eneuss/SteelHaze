import time
import threading
import sys
import os
from datetime import datetime

sys.path.insert(0, os.path.dirname(__file__))
from scanner import scan_all_parallel
import database as _db_module
from database import db, get_or_create_network
from traffic_monitor import traffic_monitor
from anomaly_detector import detect_anomalies, save_anomaly
from nvd_scanner import run_nvd_scan
from passive_scanner import passive_scanner
from epaper_display import init_display, get_display_stats
import scan_state


def save_devices(devices, network_info):
    conn = db()
    cursor = conn.cursor()
    new_ips = []

    network_id = get_or_create_network(cursor, network_info)

    for device in devices:
        mac = device["mac"].lower() if device.get("mac") else device["mac"]
        ip = device["ip"]

        if mac and mac != "N/A":
            cursor.execute("SELECT id FROM devices WHERE mac = ?", (mac,))
            row = cursor.fetchone()
            if row:
                device_id = row["id"]
                cursor.execute(
                    "UPDATE devices SET last_seen = ? WHERE id = ?",
                    (datetime.now(), device_id)
                )
            else:
                cursor.execute("INSERT INTO devices (mac) VALUES (?)", (mac,))
                device_id = cursor.lastrowid
        else:
            #No MAC — identify by IP within this network
            cursor.execute(
                "SELECT device_id FROM device_network WHERE ip = ? AND network_id = ?",
                (ip, network_id)
            )
            row = cursor.fetchone()
            if row:
                device_id = row["device_id"]
                cursor.execute(
                    "UPDATE devices SET last_seen = ? WHERE id = ?",
                    (datetime.now(), device_id)
                )
            else:
                cursor.execute("INSERT INTO devices (mac) VALUES (?)", (None,))
                device_id = cursor.lastrowid

        cursor.execute(
            "SELECT id FROM device_network WHERE device_id = ? AND network_id = ?",
            (device_id, network_id)
        )
        dn_row = cursor.fetchone()
        if dn_row:
            cursor.execute(
                "UPDATE device_network SET last_seen = ?, ip = ?, source = 'nmap' WHERE id = ?",
                (datetime.now(), ip, dn_row["id"])
            )
        else:
            cursor.execute(
                "INSERT INTO device_network (device_id, network_id, ip, is_known, source) VALUES (?, ?, ?, 0, 'nmap')",
                (device_id, network_id, ip)
            )
            new_ips.append(ip)
            print(f"[{datetime.now().strftime('%H:%M:%S')}] New device: {ip}  {mac}")

        cursor.execute(
            "INSERT INTO connection_logs (device_id, network_id, ip, status) VALUES (?, ?, ?, ?)",
            (device_id, network_id, ip, device.get("status", "up"))
        )

    conn.commit()
    conn.close()
    return new_ips, network_id


def downgrade_to_passive(network_id, active_ips):
    """Downgrade source nmap -> passive for devices missed by nmap but still seen by ARP."""
    passive_ips = passive_scanner.get_recently_seen_ips()
    if not passive_ips:
        return

    conn = db()
    cursor = conn.cursor()

    cursor.execute('''
        SELECT dn.id, dn.ip FROM device_network dn
        WHERE dn.network_id = ?
        AND dn.source = 'nmap'
        AND dn.last_seen < datetime('now', '-5 minutes')
    ''', (network_id,))

    for row in cursor.fetchall():
        if row["ip"] not in active_ips and row["ip"] in passive_ips:
            cursor.execute("UPDATE device_network SET source = 'passive' WHERE id = ?", (row["id"],))
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Downgraded nmap -> passive: {row['ip']}")

    conn.commit()
    conn.close()


def save_traffic_stats():
    stats = traffic_monitor.get_traffic_stats()
    if not stats:
        return

    conn = db()
    cursor = conn.cursor()

    for ip, data in stats.items():
        cursor.execute(
            "SELECT device_id, network_id FROM device_network WHERE ip = ? ORDER BY last_seen DESC LIMIT 1",
            (ip,)
        )
        row = cursor.fetchone()
        if row:
            cursor.execute(
                '''INSERT INTO traffic_stats
                   (device_id, network_id, ip, bytes_sent, bytes_received, packets, timestamp)
                   VALUES (?, ?, ?, ?, ?, ?, ?)''',
                (row["device_id"], row["network_id"], ip, data["bytes_sent"], data["bytes_received"],
                 data["packets"], datetime.now()),
            )

    conn.commit()
    conn.close()


def deep_scan_loop(interval=1800):
    while True:
        try:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Starting scheduled deep CVE scan...")
            run_nvd_scan()
        except Exception as e:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Deep scan error: {e}")
        time.sleep(interval)


_current_ssid = None


def monitor_loop(interval=30):
    global _current_ssid
    print("=== SteelHaze Monitor Started ===")
    print(f"Network scan every {interval}s  |  Deep CVE scan every 30min  |  Dashboard: http://localhost:5000")
    print("Press Ctrl+C to stop\n")

    traffic_monitor.start_monitoring()
    passive_scanner.start()
    threading.Thread(target=deep_scan_loop, daemon=True).start()

    _display = init_display()

    try:
        while True:
            #update display with scanning state before scan starts
            if _display:
                try:
                    total, unknown, anomalies, cves = get_display_stats()
                    subnet = next((s.get('subnet', '') for s in scan_state.get_all().values()), '')
                    _display.update(_current_ssid, subnet, total, unknown, anomalies, cves, scanning=True)
                except Exception as e:
                    print(f'[Epaper] Update failed: {e}')

            results = scan_all_parallel(on_status=scan_state.update)

            #detect SSID change and switch database accordingly
            for result in results.values():
                if result.get('network_info'):
                    ssid = result['network_info'].get('ssid')
                    if ssid != _current_ssid:
                        _current_ssid = ssid
                        _db_module.set_active_ssid(ssid)
                break

            all_new_ips = []
            last_network_info = None
            for iface, result in results.items():
                if result["error"] or not result["devices"]:
                    continue
                new_ips, network_id = save_devices(result["devices"], result["network_info"])
                active_ips = {d['ip'] for d in result['devices']}
                downgrade_to_passive(network_id, active_ips)
                all_new_ips.extend(new_ips)
                last_network_info = result["network_info"]

            if last_network_info:
                passive_new = passive_scanner.save_new_to_db(last_network_info)
                all_new_ips.extend(passive_new)

            save_traffic_stats()

            for ip in all_new_ips:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] Triggering CVE scan for new device: {ip}")
                threading.Thread(target=run_nvd_scan, args=(ip,), daemon=True).start()

            anomalies = detect_anomalies()
            if anomalies:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] {len(anomalies)} anomaly/anomalies detected:")
                for a in anomalies:
                    print(f"  [{a['type']}] {a['ip']}  {a['details']}")
                    save_anomaly(a)

            total = sum(len(r["devices"]) for r in results.values() if not r["error"])
            iface_summary = ", ".join(
                f"{iface}({'ok' if not r['error'] else 'err'})"
                for iface, r in sorted(results.items())
            )
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Scan complete: {total} device(s) [{iface_summary}]. Waiting {interval}s...\n")

            #update display with final results after scan
            if _display:
                try:
                    total_d, unknown_d, anomalies_d, cves_d = get_display_stats()
                    subnet = next((r.get('subnet', '') for r in results.values()), '')
                    _display.update(_current_ssid, subnet, total_d, unknown_d, anomalies_d, cves_d, scanning=False)
                except Exception as e:
                    print(f'[Epaper] Update failed: {e}')

            time.sleep(interval)
    except KeyboardInterrupt:
        if _display:
            _display.sleep()
        print("\nMonitor stopped.")
