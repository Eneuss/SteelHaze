#!/usr/bin/env python3
import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'steelhaze.db')


def init_database():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # WAL mode: readers and writers don't block each other
    cursor.execute("PRAGMA journal_mode=WAL")

    # If old schema (no networks table), wipe and recreate
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='networks'")
    if not cursor.fetchone():
        conn.close()
        if os.path.exists(DB_PATH):
            os.remove(DB_PATH)
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")

    # Migrate: drop cve_findings if it has the old UNIQUE constraint
    cursor.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='cve_findings'")
    row = cursor.fetchone()
    if row and 'UNIQUE' in row[0]:
        cursor.execute("DROP TABLE cve_findings")

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
            hostname TEXT,
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS device_network (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER NOT NULL,
            network_id INTEGER NOT NULL,
            ip TEXT NOT NULL,
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_known BOOLEAN DEFAULT 0,
            FOREIGN KEY (device_id) REFERENCES devices(id),
            FOREIGN KEY (network_id) REFERENCES networks(id),
            UNIQUE(device_id, network_id)
        )
    ''')

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
            hostname TEXT,
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

    conn.commit()
    conn.close()
