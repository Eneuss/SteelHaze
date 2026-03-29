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
        SELECT d.mac, d.hostname, d.first_seen,
               dn.ip, dn.last_seen, dn.is_known
        FROM devices d
        JOIN device_network dn ON d.id = dn.device_id
        WHERE dn.last_seen > ?
        AND dn.id = (SELECT id FROM device_network WHERE device_id = d.id ORDER BY last_seen DESC LIMIT 1)
        ORDER BY dn.last_seen DESC
    ''', (datetime.now() - timedelta(hours=24),)).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route('/api/stats')
def get_stats():
    conn = db()
    total = conn.execute('SELECT COUNT(*) FROM devices').fetchone()[0]
    active = conn.execute('''
        SELECT COUNT(DISTINCT d.id) FROM devices d
        JOIN device_network dn ON d.id = dn.device_id
        WHERE d.last_seen > ?
    ''', (datetime.now() - timedelta(minutes=5),)).fetchone()[0]
    unknown = conn.execute('''
        SELECT COUNT(DISTINCT d.id) FROM devices d
        JOIN device_network dn ON d.id = dn.device_id
        WHERE dn.is_known = 0
        AND dn.id = (SELECT id FROM device_network WHERE device_id = d.id ORDER BY last_seen DESC LIMIT 1)
    ''').fetchone()[0]
    anomaly_count = conn.execute(
        "SELECT COUNT(*) FROM anomalies WHERE timestamp > datetime('now', '-24 hours')"
    ).fetchone()[0]
    cve_count = conn.execute(
        "SELECT COUNT(*) FROM cve_findings"
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
    row = conn.execute('SELECT id FROM devices WHERE mac = ?', (mac,)).fetchone()
    if row:
        conn.execute('UPDATE device_network SET is_known = 1 WHERE device_id = ?', (row[0],))
        conn.commit()
    conn.close()
    return jsonify({'success': True})


@app.route('/api/traffic')
def get_traffic():
    conn = db()
    rows = conn.execute('''
        SELECT dn.ip, d.mac, d.hostname,
               SUM(t.bytes_sent)     AS total_sent,
               SUM(t.bytes_received) AS total_received,
               SUM(t.packets)        AS total_packets,
               MAX(t.timestamp)      AS last_update
        FROM devices d
        JOIN traffic_stats t ON d.id = t.device_id
        JOIN device_network dn ON d.id = dn.device_id AND t.network_id = dn.network_id
        WHERE t.timestamp > datetime('now', '-24 hours')
        GROUP BY d.id
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


@app.route('/api/ports_and_cves')
def get_ports_and_cves():
    conn = db()

    ports = conn.execute('''
        SELECT p.ip, d.hostname, p.port, p.service
        FROM open_ports p
        LEFT JOIN devices d ON p.device_id = d.id
        ORDER BY p.ip, p.port
    ''').fetchall()

    cves = conn.execute('''
        SELECT ip, port, cve_id, severity, description
        FROM cve_findings
        ORDER BY ip, port
    ''').fetchall()

    conn.close()

    # Index CVEs by (ip, port)
    cve_map = {}
    for c in cves:
        key = (c['ip'], c['port'])
        cve_map.setdefault(key, []).append({
            'cve_id': c['cve_id'],
            'severity': c['severity'],
            'description': c['description'],
        })

    # Build per-IP structure
    hosts = {}
    for p in ports:
        ip = p['ip']
        if ip not in hosts:
            hosts[ip] = {'ip': ip, 'hostname': p['hostname'] or '—', 'vulnerable_ports': [], 'clean_ports': []}
        port_cves = cve_map.get((ip, p['port']), [])
        entry = {'port': p['port'], 'service': p['service']}
        if port_cves:
            entry['cves'] = port_cves
            hosts[ip]['vulnerable_ports'].append(entry)
        else:
            hosts[ip]['clean_ports'].append(entry)

    # Sort hosts by IP
    import socket
    def ip_sort(h):
        try: return socket.inet_aton(h['ip'])
        except: return b''
    result = sorted(hosts.values(), key=ip_sort)
    return jsonify(result)


@app.route('/api/acknowledge_anomaly/<int:anomaly_id>', methods=['POST'])
def acknowledge_anomaly(anomaly_id):
    conn = db()
    conn.execute('UPDATE anomalies SET acknowledged = 1 WHERE id = ?', (anomaly_id,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})
