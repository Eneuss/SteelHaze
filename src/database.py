#!/usr/bin/env python3
import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'steelhaze.db')


def init_database():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.execute("PRAGMA journal_mode=WAL")
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS networks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ssid TEXT,
            gateway_ip TEXT NOT NULL,
            subnet TEXT NOT NULL,
            interface TEXT,
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(gateway_ip, subnet)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mac TEXT,
            label TEXT,
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Add label column to existing databases that predate this feature
    cursor.execute("PRAGMA table_info(devices)")
    if 'label' not in [row[1] for row in cursor.fetchall()]:
        cursor.execute("ALTER TABLE devices ADD COLUMN label TEXT")

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS device_network (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER NOT NULL,
            network_id INTEGER NOT NULL,
            ip TEXT NOT NULL,
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_known BOOLEAN DEFAULT 0,
            source TEXT DEFAULT 'nmap',
            FOREIGN KEY (device_id) REFERENCES devices(id),
            FOREIGN KEY (network_id) REFERENCES networks(id),
            UNIQUE(device_id, network_id)
        )
    ''')

    # Migration: add source column to existing databases
    cursor.execute("PRAGMA table_info(device_network)")
    if 'source' not in [row[1] for row in cursor.fetchall()]:
        cursor.execute("ALTER TABLE device_network ADD COLUMN source TEXT DEFAULT 'nmap'")

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS connection_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER,
            network_id INTEGER,
            ip TEXT,
            status TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (device_id) REFERENCES devices(id),
            FOREIGN KEY (network_id) REFERENCES networks(id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS traffic_stats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER,
            network_id INTEGER,
            ip TEXT,
            bytes_sent INTEGER DEFAULT 0,
            bytes_received INTEGER DEFAULT 0,
            packets INTEGER DEFAULT 0,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (device_id) REFERENCES devices(id),
            FOREIGN KEY (network_id) REFERENCES networks(id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS anomalies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT NOT NULL,
            ip TEXT,
            mac TEXT,
            details TEXT,
            network_id INTEGER,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            acknowledged BOOLEAN DEFAULT 0,
            FOREIGN KEY (network_id) REFERENCES networks(id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS open_ports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER,
            ip TEXT,
            port INTEGER,
            service TEXT,
            scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (device_id) REFERENCES devices(id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cve_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER,
            ip TEXT,
            port INTEGER,
            service TEXT,
            cve_id TEXT,
            severity TEXT,
            description TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (device_id) REFERENCES devices(id)
        )
    ''')

    # Migration: merge duplicate MAC entries in devices table
    # (can occur if passive scanner and nmap both inserted the same MAC before one committed)
    cursor.execute('''
        SELECT mac FROM devices
        WHERE mac IS NOT NULL GROUP BY mac HAVING COUNT(*) > 1
    ''')
    for (mac,) in cursor.fetchall():
        cursor.execute('SELECT id, label FROM devices WHERE mac = ? ORDER BY first_seen ASC', (mac,))
        rows = cursor.fetchall()
        keep_id = rows[0][0]
        for rid, label in rows:
            if label:
                keep_id = rid
                break
        dup_ids = [r[0] for r in rows if r[0] != keep_id]
        for dup_id in dup_ids:
            # device_network has UNIQUE(device_id, network_id) - delete conflicting rows first
            cursor.execute('''
                DELETE FROM device_network WHERE device_id = ?
                AND network_id IN (SELECT network_id FROM device_network WHERE device_id = ?)
            ''', (dup_id, keep_id))
            cursor.execute('UPDATE device_network  SET device_id = ? WHERE device_id = ?', (keep_id, dup_id))
            cursor.execute('UPDATE traffic_stats   SET device_id = ? WHERE device_id = ?', (keep_id, dup_id))
            cursor.execute('UPDATE connection_logs SET device_id = ? WHERE device_id = ?', (keep_id, dup_id))
            cursor.execute('UPDATE open_ports      SET device_id = ? WHERE device_id = ?', (keep_id, dup_id))
            cursor.execute('UPDATE cve_findings    SET device_id = ? WHERE device_id = ?', (keep_id, dup_id))
            cursor.execute('DELETE FROM devices WHERE id = ?', (dup_id,))

    conn.commit()
    conn.close()
