import configparser
import logging
import os
import sqlite3
import threading
import time
import urllib.parse
import urllib.request
from datetime import datetime, timedelta

from database import DB_PATH

log = logging.getLogger('telegram')

_CFG_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'telegram.cfg')
_token = None
_chat_id = None


def _load():
    global _token, _chat_id
    cfg = configparser.ConfigParser()
    cfg.read(_CFG_PATH)
    _token = cfg.get('telegram', 'token', fallback='').strip()
    _chat_id = cfg.get('telegram', 'chat_id', fallback='').strip()


_load()


def send(text):
    if not _token or not _chat_id:
        return
    url = f'https://api.telegram.org/bot{_token}/sendMessage'
    data = urllib.parse.urlencode({'chat_id': _chat_id, 'text': text}).encode()
    try:
        urllib.request.urlopen(url, data, timeout=10)
    except Exception as e:
        log.warning(f'telegram send failed: {e}')


def send_document(pdf_bytes, filename='steelhaze_report.pdf', caption=''):
    if not _token or not _chat_id:
        return
    try:
        import requests
        requests.post(
            f'https://api.telegram.org/bot{_token}/sendDocument',
            data={'chat_id': _chat_id, 'caption': caption},
            files={'document': (filename, pdf_bytes, 'application/pdf')},
            timeout=30,
        )
    except Exception as e:
        log.warning(f'telegram send_document failed: {e}')


def notify(anomaly_type, ip, mac, details):
    lines = [f'{anomaly_type} -- {ip}']
    if mac:
        lines[0] += f' ({mac})'
    lines.append(details)
    send('\n'.join(lines))


def _summary_text():
    try:
        conn = sqlite3.connect(DB_PATH, timeout=10)
        total = conn.execute('SELECT COUNT(*) FROM devices').fetchone()[0]
        unknown = conn.execute('''
            SELECT COUNT(DISTINCT d.id) FROM devices d
            JOIN device_network dn ON d.id = dn.device_id
            WHERE dn.is_known = 0
            AND dn.id = (
                SELECT id FROM device_network
                WHERE device_id = d.id ORDER BY last_seen DESC LIMIT 1
            )
        ''').fetchone()[0]
        anomalies = conn.execute('''
            SELECT COUNT(*) FROM anomalies
            WHERE timestamp > datetime('now', '-24 hours') AND acknowledged = 0
        ''').fetchone()[0]
        cves = conn.execute('SELECT COUNT(*) FROM cve_findings').fetchone()[0]
        cve_hosts = conn.execute('SELECT COUNT(DISTINCT ip) FROM cve_findings').fetchone()[0]
        conn.close()
        now = datetime.now().strftime('%H:%M')
        return (
            f'SteelHaze report -- {now}\n'
            f'Devices: {total} total, {unknown} unknown\n'
            f'Anomalies (24h): {anomalies} unacknowledged\n'
            f'CVEs: {cves} found across {cve_hosts} device(s)'
        )
    except Exception as e:
        log.warning(f'summary query failed: {e}')
        return None


def _send_report():
    msg = _summary_text()
    if msg:
        send(msg)
    try:
        from report import generate
        pdf = generate()
        now = datetime.now().strftime('%Y-%m-%d_%H-%M')
        send_document(pdf, filename=f'steelhaze_{now}.pdf')
    except Exception as e:
        log.warning(f'report generation failed: {e}')


def _seconds_until_next_report():
    now = datetime.now()
    candidates = []
    for hour in (8, 20):
        t = now.replace(hour=hour, minute=0, second=0, microsecond=0)
        if t > now:
            candidates.append(t)
    if not candidates:
        candidates.append(now.replace(hour=8, minute=0, second=0, microsecond=0) + timedelta(days=1))
    return (min(candidates) - now).total_seconds()


def _summary_loop():
    while True:
        threading.Event().wait(_seconds_until_next_report())
        _send_report()


def _poll_loop():
    offset = 0
    while True:
        try:
            import requests
            resp = requests.get(
                f'https://api.telegram.org/bot{_token}/getUpdates',
                params={'offset': offset, 'timeout': 25},
                timeout=30,
            )
            data = resp.json()
            if data.get('ok'):
                for update in data.get('result', []):
                    offset = update['update_id'] + 1
                    text = update.get('message', {}).get('text', '').strip()
                    if text == '/report':
                        _send_report()
        except Exception as e:
            log.warning(f'telegram poll error: {e}')
            time.sleep(5)


def start_summary_thread():
    if not _token or not _chat_id:
        return
    threading.Thread(target=_summary_loop, daemon=True, name='telegram-summary').start()
    threading.Thread(target=_poll_loop,    daemon=True, name='telegram-poll').start()
