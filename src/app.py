#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from flask import Flask, render_template, jsonify, request
import sqlite3
from datetime import datetime, timedelta
from database import DB_PATH
import scan_state

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
        SELECT d.mac, d.label, d.first_seen,
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


@app.route('/api/interfaces')
def get_interfaces():
    state = scan_state.get_all()
    conn  = db()

    # Pull all devices seen in the last 24h with their most recent interface
    rows = conn.execute('''
        SELECT d.mac, d.label, d.first_seen,
               dn.ip, dn.last_seen, dn.is_known, n.interface, dn.source
        FROM devices d
        JOIN device_network dn ON d.id = dn.device_id
        JOIN networks n ON dn.network_id = n.id
        WHERE dn.last_seen > datetime('now', '-24 hours')
        AND dn.id = (
            SELECT id FROM device_network
            WHERE device_id = d.id
            ORDER BY last_seen DESC LIMIT 1
        )
        ORDER BY dn.last_seen DESC
    ''').fetchall()
    conn.close()

    # Index for enriching active scan_state devices (nmap only)
    db_by_mac  = {}
    db_by_ip   = {}
    db_nmap_by_iface    = {}
    db_passive_by_iface = {}
    for r in rows:
        row = dict(r)
        src = row.get('source') or 'nmap'
        if src == 'passive':
            db_passive_by_iface.setdefault(r['interface'], []).append(row)
        else:
            if r['mac']:
                db_by_mac[r['mac']] = row
            db_by_ip[r['ip']] = row
            db_nmap_by_iface.setdefault(r['interface'], []).append(row)

    if not state:
        return jsonify({})

    result = {}
    for iface, s in sorted(state.items()):
        raw_devices = s.get('devices', [])

        active_ips  = {d.get('ip')  for d in raw_devices}
        active_macs = {d.get('mac') for d in raw_devices if d.get('mac')}

        def enrich(d):
            meta = db_by_mac.get(d.get('mac')) or db_by_ip.get(d.get('ip')) or {}
            return {
                'ip':         d.get('ip'),
                'mac':        d.get('mac') or meta.get('mac') or '—',
                'label':      meta.get('label'),
                'is_known':   meta.get('is_known', 0),
                'first_seen': meta.get('first_seen'),
                'last_seen':  meta.get('last_seen'),
            }

        active = [enrich(d) for d in raw_devices]

        # Offline: nmap-source devices seen in last 24h, not in current scan
        offline = [
            {
                'ip':         r['ip'],
                'mac':        r['mac'] or '—',
                'label':      r['label'],
                'is_known':   r['is_known'],
                'first_seen': r['first_seen'],
                'last_seen':  r['last_seen'],
            }
            for r in db_nmap_by_iface.get(iface, [])
            if r['ip'] not in active_ips
            and (not r['mac'] or r['mac'] not in active_macs)
        ]

        # Passive: passively-seen devices not found by nmap
        passive = [
            {
                'ip':         r['ip'],
                'mac':        r['mac'] or '—',
                'label':      r['label'],
                'is_known':   r['is_known'],
                'first_seen': r['first_seen'],
                'last_seen':  r['last_seen'],
            }
            for r in db_passive_by_iface.get(iface, [])
            if r['ip'] not in active_ips
            and (not r['mac'] or r['mac'] not in active_macs)
        ]

        result[iface] = {
            'subnet':  s.get('subnet', ''),
            'status':  s.get('status', 'idle'),
            'error':   s.get('error'),
            'devices': active + offline,
            'passive': passive,
        }
    return jsonify(result)


@app.route('/api/mark_known/<mac>', methods=['POST'])
def mark_known(mac):
    body = request.get_json(silent=True) or {}
    label = (body.get('label') or '').strip() or None
    conn = db()
    row = conn.execute('SELECT id FROM devices WHERE mac = ?', (mac,)).fetchone()
    if row:
        conn.execute('UPDATE device_network SET is_known = 1 WHERE device_id = ?', (row[0],))
        conn.execute('UPDATE devices SET label = ? WHERE id = ?', (label, row[0]))
        conn.commit()
    conn.close()
    return jsonify({'success': True})


@app.route('/api/set_label/<mac>', methods=['POST'])
def set_label(mac):
    body = request.get_json(silent=True) or {}
    label = (body.get('label') or '').strip() or None
    conn = db()
    conn.execute('UPDATE devices SET label = ? WHERE mac = ?', (label, mac))
    conn.commit()
    conn.close()
    return jsonify({'success': True})


@app.route('/api/traffic')
def get_traffic():
    conn = db()
    rows = conn.execute('''
        SELECT dn.ip, d.mac, d.label,
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
                'label': r['label'],
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
        SELECT a.type, a.ip, a.mac, d.label, a.details, a.timestamp, a.acknowledged
        FROM anomalies a
        LEFT JOIN devices d ON a.mac = d.mac AND a.mac != ''
        WHERE a.timestamp > datetime('now', '-24 hours')
        ORDER BY a.timestamp DESC
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
        SELECT f.ip, f.port, f.service, f.cve_id, f.severity, f.description
        FROM cve_findings f
        ORDER BY f.ip, f.port
    ''').fetchall()

    # Open ports (populated after first scan with new code — may be empty)
    ports = conn.execute('''
        SELECT p.ip, p.port, p.service
        FROM open_ports p
        ORDER BY p.ip, p.port
    ''').fetchall()

    # mac + label lookup by IP
    device_info = {}
    for r in conn.execute('''
        SELECT dn.ip, d.mac, d.label
        FROM device_network dn JOIN devices d ON dn.device_id = d.id
    ''').fetchall():
        if r['ip'] not in device_info:
            device_info[r['ip']] = {'mac': r['mac'], 'label': r['label']}

    conn.close()

    SEV_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
    hosts = {}

    # Build from CVE findings first — always works even on first run
    for c in cves:
        ip = c['ip']
        if ip not in hosts:
            info = device_info.get(ip, {})
            hosts[ip] = {'ip': ip, 'mac': info.get('mac'), 'label': info.get('label'), 'ports': {}}
        if c['port'] not in hosts[ip]['ports']:
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
            info = device_info.get(ip, {})
            hosts[ip] = {'ip': ip, 'mac': info.get('mac'), 'label': info.get('label'), 'ports': {}}
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
            'mac': host['mac'],
            'label': host['label'],
            'vulnerable_ports': vulnerable,
            'clean_ports': clean,
        })

    def ip_sort(h):
        try: return socket.inet_aton(h['ip'])
        except: return b''

    return jsonify(sorted(result, key=ip_sort))


@app.route('/api/chart/cve_severity')
def chart_cve_severity():
    conn = db()
    rows = conn.execute('''
        SELECT severity, COUNT(*) AS count
        FROM cve_findings
        GROUP BY severity
    ''').fetchall()
    conn.close()
    result = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'UNKNOWN': 0}
    for r in rows:
        sev = (r['severity'] or 'UNKNOWN').upper()
        result[sev] = result.get(sev, 0) + r['count']
    return jsonify(result)


@app.route('/api/chart/anomalies_per_day')
def chart_anomalies_per_day():
    conn = db()
    rows = conn.execute('''
        SELECT DATE(timestamp) AS date, COUNT(*) AS count
        FROM anomalies
        WHERE timestamp > datetime('now', '-7 days')
        GROUP BY DATE(timestamp)
        ORDER BY date ASC
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
