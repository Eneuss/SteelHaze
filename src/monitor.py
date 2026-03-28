#!/usr/bin/env python3
import sqlite3
import time
import threading
import sys
import os
from datetime import datetime

sys.path.insert(0, os.path.dirname(__file__))
from scanner import scan_network, get_network_info
from database import DB_PATH
from traffic_monitor import traffic_monitor
from anomaly_detector import detect_anomalies, save_anomaly
from nvd_scanner import run_nvd_scan


def get_or_create_network(cursor, network_info):
    cursor.execute(
        "SELECT id FROM networks WHERE gateway_ip = ? AND subnet = ?",
        (network_info["gateway_ip"], network_info["subnet"])
    )
    row = cursor.fetchone()
    if row:
        cursor.execute(
            "UPDATE networks SET last_seen = ?, ssid = ?, interface = ? WHERE id = ?",
            (datetime.now(), network_info["ssid"], network_info["interface"], row[0])
        )
        return row[0]
    else:
        cursor.execute(
            "INSERT INTO networks (ssid, gateway_ip, subnet, interface) VALUES (?, ?, ?, ?)",
            (network_info["ssid"], network_info["gateway_ip"], network_info["subnet"], network_info["interface"])
        )
        return cursor.lastrowid


def save_devices(devices, network_info):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    new_ips = []

    network_id = get_or_create_network(cursor, network_info)

    for device in devices:
        mac = device["mac"]
        ip = device["ip"]
        hostname = device["hostname"]

        if mac and mac != "N/A":
            cursor.execute("SELECT id FROM devices WHERE mac = ?", (mac,))
            row = cursor.fetchone()
            if row:
                device_id = row[0]
                cursor.execute(
                    "UPDATE devices SET last_seen = ?, hostname = ? WHERE id = ?",
                    (datetime.now(), hostname, device_id)
                )
            else:
                cursor.execute(
                    "INSERT INTO devices (mac, hostname) VALUES (?, ?)",
                    (mac, hostname)
                )
                device_id = cursor.lastrowid
        else:
            # No MAC — identify by IP within this network
            cursor.execute(
                "SELECT device_id FROM device_network WHERE ip = ? AND network_id = ?",
                (ip, network_id)
            )
            row = cursor.fetchone()
            if row:
                device_id = row[0]
                cursor.execute(
                    "UPDATE devices SET last_seen = ?, hostname = ? WHERE id = ?",
                    (datetime.now(), hostname, device_id)
                )
            else:
                cursor.execute(
                    "INSERT INTO devices (mac, hostname) VALUES (?, ?)",
                    (None, hostname)
                )
                device_id = cursor.lastrowid

        # Find or create device_network entry
        cursor.execute(
            "SELECT id FROM device_network WHERE device_id = ? AND network_id = ?",
            (device_id, network_id)
        )
        dn_row = cursor.fetchone()
        if dn_row:
            cursor.execute(
                "UPDATE device_network SET last_seen = ?, ip = ? WHERE id = ?",
                (datetime.now(), ip, dn_row[0])
            )
        else:
            cursor.execute(
                "INSERT INTO device_network (device_id, network_id, ip, is_known) VALUES (?, ?, ?, 0)",
                (device_id, network_id, ip)
            )
            new_ips.append(ip)
            print(f"[{datetime.now().strftime('%H:%M:%S')}] New device: {ip}  {mac}  {hostname}")

        cursor.execute(
            "INSERT INTO connection_logs (device_id, network_id, ip, status) VALUES (?, ?, ?, ?)",
            (device_id, network_id, ip, device.get("status", "up"))
        )

    conn.commit()
    conn.close()
    return new_ips, network_id


def save_traffic_stats(network_id):
    stats = traffic_monitor.get_traffic_stats()
    if not stats:
        return

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    for ip, data in stats.items():
        cursor.execute(
            "SELECT device_id FROM device_network WHERE ip = ? AND network_id = ?",
            (ip, network_id)
        )
        row = cursor.fetchone()
        if row:
            cursor.execute(
                '''INSERT INTO traffic_stats
                   (device_id, network_id, ip, bytes_sent, bytes_received, packets, timestamp)
                   VALUES (?, ?, ?, ?, ?, ?, ?)''',
                (row[0], network_id, ip, data["bytes_sent"], data["bytes_received"],
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


def monitor_loop(interval=30):
    print("=== SteelHaze V2 Monitor Started ===")
    print(f"Network scan every {interval}s  |  Deep CVE scan every 30min  |  Dashboard: http://localhost:5000")
    print("Press Ctrl+C to stop\n")

    traffic_monitor.start_monitoring()
    threading.Thread(target=deep_scan_loop, daemon=True).start()

    try:
        while True:
            network_info = get_network_info()
            devices = scan_network()
            new_ips, network_id = save_devices(devices, network_info)
            save_traffic_stats(network_id)

            for ip in new_ips:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] Triggering CVE scan for new device: {ip}")
                threading.Thread(target=run_nvd_scan, args=(ip,), daemon=True).start()

            anomalies = detect_anomalies()
            if anomalies:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] {len(anomalies)} anomaly/anomalies detected:")
                for a in anomalies:
                    print(f"  [{a['type']}] {a['ip']}  {a['details']}")
                    save_anomaly(a)

            print(f"[{datetime.now().strftime('%H:%M:%S')}] Scan complete. Waiting {interval}s...\n")
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nMonitor stopped.")
