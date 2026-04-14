#!/usr/bin/env python3
import io
import logging
import sqlite3
from datetime import datetime, timedelta

from database import DB_PATH

log = logging.getLogger('report')


def _safe(text):
    return str(text or '-').replace('—', '-').replace('–', '-')


def _db():
    return sqlite3.connect(DB_PATH, timeout=10)


def _stats(conn):
    now = datetime.utcnow()
    total = conn.execute('SELECT COUNT(*) FROM devices').fetchone()[0]
    active = conn.execute('''
        SELECT COUNT(DISTINCT d.id) FROM devices d
        JOIN device_network dn ON d.id = dn.device_id
        WHERE d.last_seen > ?
    ''', (now - timedelta(minutes=5),)).fetchone()[0]
    unknown = conn.execute('''
        SELECT COUNT(DISTINCT d.id) FROM devices d
        JOIN device_network dn ON d.id = dn.device_id
        WHERE dn.is_known = 0
        AND dn.id = (
            SELECT id FROM device_network
            WHERE device_id = d.id ORDER BY last_seen DESC LIMIT 1
        )
    ''').fetchone()[0]
    anomalies_24h = conn.execute('''
        SELECT COUNT(*) FROM anomalies
        WHERE timestamp > datetime('now', '-24 hours') AND acknowledged = 0
    ''').fetchone()[0]
    cves = conn.execute('SELECT COUNT(*) FROM cve_findings').fetchone()[0]
    return {
        'total': total, 'active': active, 'unknown': unknown,
        'anomalies_24h': anomalies_24h, 'cves': cves,
    }


def _devices(conn):
    return conn.execute('''
        SELECT dn.ip, d.mac, d.label, dn.source, d.last_seen
        FROM devices d
        JOIN device_network dn ON d.id = dn.device_id
        WHERE d.last_seen > datetime('now', '-24 hours')
        ORDER BY d.last_seen DESC
    ''').fetchall()


def _anomalies(conn):
    return conn.execute('''
        SELECT timestamp, type, ip, mac, details
        FROM anomalies
        WHERE timestamp > datetime('now', '-24 hours')
        ORDER BY timestamp DESC
    ''').fetchall()


def _cves(conn):
    return conn.execute('''
        SELECT ip, port, service, cve_id, severity, description
        FROM cve_findings
        ORDER BY ip, severity DESC, port
    ''').fetchall()


def _chart_data(conn):
    dev_rows = conn.execute('''
        SELECT date(last_seen), COUNT(DISTINCT id)
        FROM devices
        WHERE last_seen > datetime('now', '-7 days')
        GROUP BY date(last_seen) ORDER BY date(last_seen)
    ''').fetchall()
    anm_rows = conn.execute('''
        SELECT date(timestamp), COUNT(*)
        FROM anomalies
        WHERE timestamp > datetime('now', '-7 days')
        GROUP BY date(timestamp) ORDER BY date(timestamp)
    ''').fetchall()
    return dev_rows, anm_rows


def _generate_chart(dev_rows, anm_rows):
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
    except ImportError:
        return None

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 3), dpi=100)
    fig.patch.set_facecolor('#f5f7fa')

    for ax, rows, color, title in [
        (ax1, dev_rows, '#2d5986', 'Devices seen per day (7d)'),
        (ax2, anm_rows, '#c0392b', 'Anomalies per day (7d)'),
    ]:
        ax.set_facecolor('#f5f7fa')
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        ax.set_title(title, fontsize=10, pad=8)
        ax.tick_params(labelsize=8)
        if rows:
            labels = [r[0][5:] for r in rows]  # MM-DD
            values = [r[1] for r in rows]
            ax.bar(labels, values, color=color, width=0.6)
            ax.tick_params(axis='x', rotation=30)
        else:
            ax.text(0.5, 0.5, 'No data', ha='center', va='center',
                    transform=ax.transAxes, color='#999999', fontsize=9)

    plt.tight_layout(pad=1.5)
    buf = io.BytesIO()
    plt.savefig(buf, format='png', bbox_inches='tight', facecolor=fig.get_facecolor())
    plt.close(fig)
    buf.seek(0)
    return buf.read()


# PDF helpers

def _section_title(pdf, title):
    pdf.ln(3)
    pdf.set_font('Helvetica', 'B', 10)
    pdf.set_fill_color(220, 230, 245)
    pdf.set_text_color(26, 43, 74)
    pdf.cell(0, 6, f'  {title}', fill=True, new_x='LMARGIN', new_y='NEXT')
    pdf.ln(1)
    pdf.set_text_color(33, 33, 33)


def _draw_table(pdf, headers, widths, rows):
    pdf.set_font('Helvetica', 'B', 8)
    pdf.set_fill_color(45, 89, 134)
    pdf.set_text_color(255, 255, 255)
    for h, w in zip(headers, widths):
        pdf.cell(w, 6, h, fill=True)
    pdf.ln()

    if not rows:
        pdf.set_font('Helvetica', 'I', 8)
        pdf.set_text_color(160, 160, 160)
        pdf.set_fill_color(255, 255, 255)
        pdf.cell(sum(widths), 5, '  No records found', new_x='LMARGIN', new_y='NEXT')
        pdf.ln(1)
        return

    pdf.set_font('Helvetica', '', 7)
    for i, row in enumerate(rows):
        pdf.set_fill_color(240, 245, 255) if i % 2 == 0 else pdf.set_fill_color(255, 255, 255)
        pdf.set_text_color(33, 33, 33)
        for val, w in zip(row, widths):
            pdf.cell(w, 5, _safe(val)[:60], fill=True)
        pdf.ln()
    pdf.ln(1)


_SEV_COLORS = {
    'CRITICAL': (200, 40, 40),
    'HIGH':     (210, 105, 10),
    'MEDIUM':   (170, 140, 0),
    'LOW':      (40, 140, 40),
}


def _draw_cve_table(pdf, rows):
    headers = ['IP', 'Port', 'Service', 'CVE ID', 'Severity']
    widths  = [35,   15,     35,         55,        40]

    pdf.set_font('Helvetica', 'B', 8)
    pdf.set_fill_color(45, 89, 134)
    pdf.set_text_color(255, 255, 255)
    for h, w in zip(headers, widths):
        pdf.cell(w, 6, h, fill=True)
    pdf.ln()

    if not rows:
        pdf.set_font('Helvetica', 'I', 8)
        pdf.set_text_color(160, 160, 160)
        pdf.cell(sum(widths), 5, '  No CVE findings', new_x='LMARGIN', new_y='NEXT')
        pdf.ln(1)
        return

    for i, (ip, port, service, cve_id, severity, desc) in enumerate(rows):
        bg = (240, 245, 255) if i % 2 == 0 else (255, 255, 255)
        pdf.set_fill_color(*bg)
        pdf.set_font('Helvetica', '', 7)
        pdf.set_text_color(33, 33, 33)
        for val, w in zip([ip, str(port), service, cve_id], widths[:4]):
            pdf.cell(w, 5, _safe(val), fill=True)
        r, g, b = _SEV_COLORS.get(severity, (100, 100, 100))
        pdf.set_text_color(r, g, b)
        pdf.cell(widths[4], 5, _safe(severity), fill=True)
        pdf.ln()
        pdf.set_fill_color(*bg)
        pdf.set_font('Helvetica', 'I', 6)
        pdf.set_text_color(110, 110, 110)
        pdf.cell(sum(widths), 4, '  ' + _safe(desc)[:120], fill=True)
        pdf.ln()

    pdf.ln(1)


# Main entry point

def generate():
    try:
        from fpdf import FPDF
    except ImportError:
        raise RuntimeError('fpdf2 is not installed — run: pip install fpdf2')

    conn = _db()
    stats    = _stats(conn)
    devices  = _devices(conn)
    anomalies = _anomalies(conn)
    cves     = _cves(conn)
    dev_rows, anm_rows = _chart_data(conn)
    conn.close()

    chart_png = _generate_chart(dev_rows, anm_rows)

    pdf = FPDF()
    pdf.set_margins(15, 15, 15)
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    pdf.set_fill_color(26, 43, 74)
    pdf.rect(0, 0, 210, 22, 'F')
    pdf.set_font('Helvetica', 'B', 15)
    pdf.set_text_color(255, 255, 255)
    pdf.set_y(5)
    pdf.cell(0, 8, 'SteelHaze Security Report', align='C', new_x='LMARGIN', new_y='NEXT')
    pdf.set_font('Helvetica', '', 9)
    pdf.cell(0, 5, datetime.now().strftime('%Y-%m-%d  %H:%M'), align='C', new_x='LMARGIN', new_y='NEXT')
    pdf.set_text_color(33, 33, 33)
    pdf.set_y(28)

    box_w = 180 / 5
    labels = ['Total Devices', 'Active (5 min)', 'Unknown', 'Anomalies (24h)', 'CVEs']
    values = [stats['total'], stats['active'], stats['unknown'], stats['anomalies_24h'], stats['cves']]
    for i, (lbl, val) in enumerate(zip(labels, values)):
        x = 15 + i * box_w
        pdf.set_fill_color(240, 245, 255)
        pdf.rect(x, 28, box_w - 1, 16, 'F')
        pdf.set_font('Helvetica', 'B', 15)
        pdf.set_text_color(26, 43, 74)
        pdf.set_xy(x, 29)
        pdf.cell(box_w - 1, 8, str(val), align='C')
        pdf.set_font('Helvetica', '', 7)
        pdf.set_text_color(100, 100, 100)
        pdf.set_xy(x, 37)
        pdf.cell(box_w - 1, 5, lbl, align='C')

    pdf.set_y(50)
    pdf.set_text_color(33, 33, 33)


    _section_title(pdf, 'Devices (last 24h)')
    _draw_table(pdf,
        headers=['IP', 'MAC', 'Label', 'Source', 'Last Seen'],
        widths  =[35,   42,    33,       22,        48],
        rows=[(r[0], r[1], r[2], r[3], r[4][:16] if r[4] else '') for r in devices],
    )


    _section_title(pdf, 'Anomalies (last 24h)')
    _draw_table(pdf,
        headers=['Time', 'Type', 'IP', 'Details'],
        widths  =[32,     30,    32,    86],
        rows=[(r[0][:16] if r[0] else '', r[1], r[2], r[4]) for r in anomalies],
    )


    _section_title(pdf, 'CVE Findings')
    _draw_cve_table(pdf, cves)


    if chart_png:
        _section_title(pdf, 'Activity (last 7 days)')
        pdf.image(io.BytesIO(chart_png), x=15, w=180)

    return bytes(pdf.output())
