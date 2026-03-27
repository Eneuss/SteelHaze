#!/usr/bin/env python3
import sqlite3
import time
import threading
import sys
import os
from datetime import datetime

sys.path.insert(0, os.path.dirname(__file__))
from scanner import scan_network
from database import DB_PATH
from traffic_monitor import traffic_monitor
from anomaly_detector import detect_anomalies, save_anomaly
from nvd_scanner import run_nvd_scan


def save_devices(devices):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    new_ips = []

    for device in devices:
        mac = device["mac"]
        ip = device["ip"]
        hostname = device["hostname"]

        if mac and mac != "N/A":
            cursor.execute("SELECT id, is_known FROM devices WHERE mac = ?", (mac,))
            row = cursor.fetchone()
            if row:
                device_id = row[0]
                cursor.execute(
                    "UPDATE devices SET last_seen = ?, ip = ?, hostname = ? WHERE id = ?",
                    (datetime.now(), ip, hostname, device_id),
                )
            else:
                cursor.execute(
                    "INSERT INTO devices (ip, mac, hostname, is_known) VALUES (?, ?, ?, 0)",
                    (ip, mac, hostname),
                )
                device_id = cursor.lastrowid
                new_ips.append(ip)
                print(f"[{datetime.now().strftime('%H:%M:%S')}] New device: {ip}  {mac}  {hostname}")
        else:
            cursor.execute("SELECT id FROM devices WHERE ip = ? AND (mac IS NULL OR mac = 'N/A')", (ip,))
            row = cursor.fetchone()
            if row:
                device_id = row[0]
                cursor.execute(
                    "UPDATE devices SET last_seen = ?, hostname = ? WHERE id = ?",
                    (datetime.now(), hostname, device_id),
                )
            else:
                cursor.execute(
                    "INSERT INTO devices (ip, mac, hostname, is_known) VALUES (?, ?, ?, 0)",
                    (ip, mac, hostname),
                )
                device_id = cursor.lastrowid
                new_ips.append(ip)

        cursor.execute(
            "INSERT INTO connection_logs (device_id, ip, status) VALUES (?, ?, ?)",
            (device_id, ip, device.get("status", "up")),
        )

    conn.commit()
    conn.close()
    return new_ips


def save_traffic_stats():
    stats = traffic_monitor.get_traffic_stats()
    if not stats:
        return

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    for ip, data in stats.items():
        cursor.execute("SELECT id FROM devices WHERE ip = ?", (ip,))
        row = cursor.fetchone()
        if row:
            cursor.execute(
                '''INSERT INTO traffic_stats
                   (device_id, ip, bytes_sent, bytes_received, packets, timestamp)
                   VALUES (?, ?, ?, ?, ?, ?)''',
                (row[0], ip, data["bytes_sent"], data["bytes_received"],
                 data["packets"], datetime.now()),
            )

    conn.commit()
    conn.close()


def deep_scan_loop(interval=1800):
    while True:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Starting scheduled deep CVE scan...")
        run_nvd_scan()
        time.sleep(interval)


def monitor_loop(interval=30):
    print("=== SteelHaze V2 Monitor Started ===")
    print(f"Network scan every {interval}s  |  Deep CVE scan every 30min  |  Dashboard: http://localhost:5000")
    print("Press Ctrl+C to stop\n")

    traffic_monitor.start_monitoring()

    threading.Thread(target=deep_scan_loop, daemon=True).start()

    try:
        while True:
            devices = scan_network()
            new_ips = save_devices(devices)
            save_traffic_stats()

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
