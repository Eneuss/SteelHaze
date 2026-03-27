#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from flask import Flask, render_template, jsonify
import sqlite3
from datetime import datetime, timedelta
from database import DB_PATH

app = Flask(
    __name__,
    template_folder=os.path.join(os.path.dirname(__file__), '..', 'templates'),
    static_folder=os.path.join(os.path.dirname(__file__), '..', 'static'),
)


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@app.route('/')
def index():
    return render_template('dashboard.html')


@app.route('/api/devices')
def get_devices():
    conn = db()
    rows = conn.execute('''
        SELECT ip, mac, hostname, first_seen, last_seen, is_known
        FROM devices
        WHERE last_seen > ?
        ORDER BY last_seen DESC
    ''', (datetime.now() - timedelta(hours=24),)).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route('/api/stats')
def get_stats():
    conn = db()
    total   = conn.execute('SELECT COUNT(*) FROM devices').fetchone()[0]
    active  = conn.execute(
        'SELECT COUNT(*) FROM devices WHERE last_seen > ?',
        (datetime.now() - timedelta(minutes=5),)
    ).fetchone()[0]
    unknown = conn.execute('SELECT COUNT(*) FROM devices WHERE is_known = 0').fetchone()[0]
    anomaly_count = conn.execute(
        "SELECT COUNT(*) FROM anomalies WHERE timestamp > datetime('now', '-24 hours')"
    ).fetchone()[0]
    cve_count = conn.execute(
        "SELECT COUNT(*) FROM cve_findings WHERE timestamp > datetime('now', '-7 days')"
    ).fetchone()[0]
    conn.close()
    return jsonify({
        'total': total,
        'active': active,
        'unknown': unknown,
        'anomalies': anomaly_count,
        'cves': cve_count,
    })


@app.route('/api/mark_known/<mac>', methods=['POST'])
def mark_known(mac):
    conn = db()
    conn.execute('UPDATE devices SET is_known = 1 WHERE mac = ?', (mac,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})


@app.route('/api/traffic')
def get_traffic():
    conn = db()
    rows = conn.execute('''
        SELECT d.ip, d.mac, d.hostname,
               SUM(t.bytes_sent)     AS total_sent,
               SUM(t.bytes_received) AS total_received,
               SUM(t.packets)        AS total_packets,
               MAX(t.timestamp)      AS last_update
        FROM devices d
        LEFT JOIN traffic_stats t ON d.id = t.device_id
        WHERE t.timestamp > datetime('now', '-24 hours')
        GROUP BY d.ip
        ORDER BY (total_sent + total_received) DESC
    ''').fetchall()
    conn.close()
    result = []
    for r in rows:
        if r['total_sent'] is not None:
            result.append({
                'ip': r['ip'],
                'mac': r['mac'],
                'hostname': r['hostname'],
                'bytes_sent': r['total_sent'],
                'bytes_received': r['total_received'],
                'total_bytes': r['total_sent'] + r['total_received'],
                'packets': r['total_packets'],
                'last_update': r['last_update'],
            })
    return jsonify(result)


@app.route('/api/timeline')
def get_timeline():
    conn = db()
    rows = conn.execute('''
        SELECT DATE(timestamp) AS date, COUNT(DISTINCT device_id) AS device_count
        FROM connection_logs
        WHERE timestamp > datetime('now', '-7 days')
        GROUP BY DATE(timestamp)
        ORDER BY date ASC
    ''').fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route('/api/anomalies')
def get_anomalies():
    conn = db()
    rows = conn.execute('''
        SELECT type, ip, mac, hostname, details, timestamp, acknowledged
        FROM anomalies
        WHERE timestamp > datetime('now', '-24 hours')
        ORDER BY timestamp DESC
        LIMIT 50
    ''').fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route('/api/cves')
def get_cves():
    conn = db()
    rows = conn.execute('''
        SELECT f.ip, d.hostname, f.port, f.service, f.cve_id, f.severity, f.description, f.timestamp
        FROM cve_findings f
        LEFT JOIN devices d ON f.device_id = d.id
        ORDER BY f.timestamp DESC
        LIMIT 100
    ''').fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route('/api/acknowledge_anomaly/<int:anomaly_id>', methods=['POST'])
def acknowledge_anomaly(anomaly_id):
    conn = db()
    conn.execute('UPDATE anomalies SET acknowledged = 1 WHERE id = ?', (anomaly_id,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})
