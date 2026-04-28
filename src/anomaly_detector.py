from datetime import datetime
from database import db
import telegram_notify


def detect_anomalies():
    conn = db()
    cursor = conn.cursor()
    anomalies = []

    #1. High traffic: more than 500 MB in the last 5 minutes
    cursor.execute('''
        SELECT dn.ip, d.mac,
               SUM(t.bytes_sent + t.bytes_received) AS total_bytes,
               MAX(t.timestamp) AS last_seen
        FROM devices d
        JOIN traffic_stats t ON d.id = t.device_id
        JOIN device_network dn ON d.id = dn.device_id AND t.network_id = dn.network_id
        WHERE t.timestamp > datetime('now', '-5 minutes')
        GROUP BY d.id
        HAVING total_bytes > 524288000
    ''')
    for row in cursor.fetchall():
        cursor.execute('''
            SELECT COUNT(*) FROM anomalies
            WHERE type = 'HIGH_TRAFFIC' AND ip = ?
            AND timestamp > datetime('now', '-1 hours')
        ''', (row["ip"],))
        if cursor.fetchone()[0] == 0:
            anomalies.append({
                "type": "HIGH_TRAFFIC",
                "ip": row["ip"],
                "mac": row["mac"],
                "details": f"High traffic: {row['total_bytes'] / 1024 / 1024:.2f} MB in 5 minutes",
                "timestamp": row["last_seen"],
            })

    #2. new unknown devices (first seen <10 min ago)
    cursor.execute('''
        SELECT dn.ip, d.mac, dn.first_seen
        FROM devices d
        JOIN device_network dn ON d.id = dn.device_id
        WHERE dn.is_known = 0 AND dn.first_seen > datetime('now', '-10 minutes')
    ''')
    for row in cursor.fetchall():
        cursor.execute('''
            SELECT COUNT(*) FROM anomalies
            WHERE type = 'NEW_DEVICE' AND mac = ?
            AND timestamp > datetime('now', '-24 hours')
        ''', (row["mac"],))
        if cursor.fetchone()[0] == 0:
            anomalies.append({
                "type": "NEW_DEVICE",
                "ip": row["ip"],
                "mac": row["mac"],
                "details": "New unrecognised device detected",
                "timestamp": row["first_seen"],
            })

    #3. Stealth devices: passive-only, >5 min old, not already alerted in 24h
    cursor.execute('''
        SELECT dn.ip, d.mac, dn.first_seen
        FROM devices d
        JOIN device_network dn ON d.id = dn.device_id
        WHERE dn.source = 'passive'
        AND dn.first_seen < datetime('now', '-5 minutes')
    ''')
    for row in cursor.fetchall():
        cursor.execute('''
            SELECT COUNT(*) FROM anomalies
            WHERE type = 'STEALTH_DEVICE' AND mac = ?
            AND timestamp > datetime('now', '-24 hours')
        ''', (row["mac"],))
        if cursor.fetchone()[0] == 0:
            anomalies.append({
                "type": "STEALTH_DEVICE",
                "ip": row["ip"],
                "mac": row["mac"],
                "details": "Device detected passively - does not respond to network scan",
                "timestamp": row["first_seen"],
            })

    conn.close()
    return anomalies


def save_anomaly(anomaly):
    conn = db()
    conn.execute('''
        INSERT INTO anomalies (type, ip, mac, details, timestamp)
        VALUES (?, ?, ?, ?, ?)
    ''', (
        anomaly["type"],
        anomaly["ip"],
        anomaly.get("mac", ""),
        anomaly["details"],
        datetime.now(),
    ))
    conn.commit()
    conn.close()
    if anomaly["type"] in ('NEW_DEVICE', 'STEALTH_DEVICE'):
        telegram_notify.notify(anomaly["type"], anomaly["ip"], anomaly.get("mac", ""), anomaly["details"])


def save_cve_anomaly(ip, mac, cve_id, severity, description):
    conn = db()
    #skip if same CVE already logged for this IP in the last 24h
    row = conn.execute('''
        SELECT COUNT(*) FROM anomalies
        WHERE type = 'CVE_FOUND' AND ip = ?
        AND details LIKE ?
        AND timestamp > datetime('now', '-24 hours')
    ''', (ip, f"{cve_id}%")).fetchone()
    if row[0] == 0:
        details = f"{cve_id} ({severity}): {description[:120]}"
        conn.execute('''
            INSERT INTO anomalies (type, ip, mac, details, timestamp)
            VALUES (?, ?, ?, ?, ?)
        ''', ('CVE_FOUND', ip, mac or '', details, datetime.now()))
        conn.commit()
        conn.close()
        telegram_notify.notify('CVE_FOUND', ip, mac or '', details)
    else:
        conn.close()
