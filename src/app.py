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
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


@app.route('/')
def devices():
    return render_template('devices.html', active='devices')

@app.route('/traffic')
def traffic():
    return render_template('traffic.html', active='traffic')

@app.route('/anomalies')
def anomalies():
    return render_template('anomalies.html', active='anomalies')

@app.route('/cves')
def cves():
    return render_template('cves.html', active='cves')

@app.route('/timeline')
def timeline():
    return render_template('timeline.html', active='timeline')


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
    import socket
    conn = db()

    # CVE findings are always available — use as primary source
    cves = conn.execute('''
        SELECT f.ip, d.hostname, f.port, f.service, f.cve_id, f.severity, f.description
        FROM cve_findings f
        LEFT JOIN devices d ON f.device_id = d.id
        ORDER BY f.ip, f.port
    ''').fetchall()

    # Open ports (populated after first scan with new code — may be empty)
    ports = conn.execute('''
        SELECT p.ip, d.hostname, p.port, p.service
        FROM open_ports p
        LEFT JOIN devices d ON p.device_id = d.id
        ORDER BY p.ip, p.port
    ''').fetchall()

    conn.close()

    SEV_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
    hosts = {}

    # Build from CVE findings first — always works even on first run
    for c in cves:
        ip = c['ip']
        if ip not in hosts:
            hosts[ip] = {'ip': ip, 'hostname': c['hostname'] or '—', 'ports': {}}
        if ip not in hosts or c['port'] not in hosts[ip]['ports']:
            hosts[ip]['ports'][c['port']] = {'service': c['service'], 'cves': []}
        hosts[ip]['ports'][c['port']]['cves'].append({
            'cve_id': c['cve_id'],
            'severity': c['severity'],
            'description': c['description'],
        })

    # Merge open_ports — adds clean ports and fills in any missing hosts
    for p in ports:
        ip = p['ip']
        if ip not in hosts:
            hosts[ip] = {'ip': ip, 'hostname': p['hostname'] or '—', 'ports': {}}
        if p['port'] not in hosts[ip]['ports']:
            hosts[ip]['ports'][p['port']] = {'service': p['service'], 'cves': []}

    # Build final sorted structure
    result = []
    for host in hosts.values():
        vulnerable, clean = [], []
        for port, data in sorted(host['ports'].items()):
            entry = {'port': port, 'service': data['service']}
            if data['cves']:
                entry['cves'] = sorted(data['cves'], key=lambda c: SEV_ORDER.get(c['severity'], 4))
                vulnerable.append(entry)
            else:
                clean.append(entry)
        result.append({
            'ip': host['ip'],
            'hostname': host['hostname'],
            'vulnerable_ports': vulnerable,
            'clean_ports': clean,
        })

    def ip_sort(h):
        try: return socket.inet_aton(h['ip'])
        except: return b''

    return jsonify(sorted(result, key=ip_sort))


@app.route('/api/acknowledge_anomaly/<int:anomaly_id>', methods=['POST'])
def acknowledge_anomaly(anomaly_id):
    conn = db()
    conn.execute('UPDATE anomalies SET acknowledged = 1 WHERE id = ?', (anomaly_id,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})
