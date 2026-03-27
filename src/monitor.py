#!/usr/bin/env python3
import sqlite3
import time
import sys
import os
from datetime import datetime

sys.path.insert(0, os.path.dirname(__file__))
from scanner import scan_network
from database import DB_PATH
from traffic_monitor import traffic_monitor
from anomaly_detector import detect_anomalies, save_anomaly


def save_devices(devices):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

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
                print(f"[{datetime.now().strftime('%H:%M:%S')}] New device: {ip}  {mac}  {hostname}")
        else:
            # Devices without a MAC (e.g. the host itself) — track by IP
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

        cursor.execute(
            "INSERT INTO connection_logs (device_id, ip, status) VALUES (?, ?, ?)",
            (device_id, ip, device.get("status", "up")),
        )

    conn.commit()
    conn.close()


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


def monitor_loop(interval=30):
    print("=== SteelHaze V2 Monitor Started ===")
    print(f"Network scan every {interval}s  |  Dashboard: http://localhost:5000")
    print("Press Ctrl+C to stop\n")

    traffic_monitor.start_monitoring()

    try:
        while True:
            devices = scan_network()
            save_devices(devices)
            save_traffic_stats()

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
