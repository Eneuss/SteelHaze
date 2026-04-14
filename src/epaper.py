#!/usr/bin/env python3
"""
E-paper display thread for SteelHaze.
Shows a glanceable status summary on a Waveshare 2.13inch e-Paper HAT (250x122).
Silently disabled if the waveshare_epd library is not installed.

Install on Pi Zero 2W:
    pip3 install waveshare-epaper pillow
or:
    git clone https://github.com/waveshare/e-Paper
    cd e-Paper/RaspberryPi_JetsonNano/python && pip3 install .
"""
import logging
import os
import socket
import sqlite3
import threading
from datetime import datetime, timedelta

log = logging.getLogger('epaper')

try:
    from waveshare_epd import epd2in13_V4
    from PIL import Image, ImageDraw, ImageFont
    _AVAILABLE = True
except ImportError:
    _AVAILABLE = False

from database import DB_PATH

REFRESH_INTERVAL = 60  # seconds between display updates

# Truetype font paths to try (Pi OS Lite includes DejaVu via fonts-dejavu-core)
_BOLD_FONTS = [
    '/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf',
    '/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf',
    '/usr/share/fonts/truetype/freefont/FreeSansBold.ttf',
]
_REGULAR_FONTS = [
    '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf',
    '/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf',
    '/usr/share/fonts/truetype/freefont/FreeSans.ttf',
]


def _font(paths, size):
    for p in paths:
        if os.path.exists(p):
            try:
                return ImageFont.truetype(p, size)
            except Exception:
                continue
    return ImageFont.load_default()


def _local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return '?.?.?.?'


def _stats():
    try:
        conn = sqlite3.connect(DB_PATH, timeout=10)
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

        anomalies = conn.execute('''
            SELECT COUNT(*) FROM anomalies
            WHERE timestamp > datetime('now', '-24 hours')
            AND acknowledged = 0
        ''').fetchone()[0]

        cves = conn.execute('SELECT COUNT(*) FROM cve_findings').fetchone()[0]

        last_scan = conn.execute(
            'SELECT MAX(last_seen) FROM device_network'
        ).fetchone()[0]

        conn.close()
        return {
            'total': total, 'active': active, 'unknown': unknown,
            'anomalies': anomalies, 'cves': cves, 'last_scan': last_scan,
        }
    except Exception as e:
        log.warning(f'stats query failed: {e}')
        return None


def _time_ago(ts_str):
    if not ts_str:
        return 'never'
    try:
        dt = datetime.strptime(ts_str[:19], '%Y-%m-%d %H:%M:%S')
        secs = int((datetime.utcnow() - dt).total_seconds())
        if secs < 60:
            return f'{secs}s ago'
        if secs < 3600:
            return f'{secs // 60}m ago'
        return f'{secs // 3600}h ago'
    except Exception:
        return '?'


def _draw(stats, ip):
    """
    Build the 250x122 monochrome PIL image to send to the display.

    Layout:
      0- 18  header bar (inverted): "SteelHaze"  +  local IP
     18- 72  top row: Active (left) | Unknown (right, inverted if > 0)
     72-110  bottom row: Anomalies (left, inverted if > 0) | CVEs (right)
    110-122  footer: "scan Xm ago"  +  current time HH:MM
    """
    W, H = 250, 122
    MID_X = 125    # vertical divider x
    ROW1_Y = 18    # top of first data row
    ROW2_Y = 72    # top of second data row
    FOOT_Y = 110   # top of footer

    img = Image.new('1', (W, H), 255)  # 255 = white
    d = ImageDraw.Draw(img)

    f_title  = _font(_BOLD_FONTS,    13)
    f_ip     = _font(_REGULAR_FONTS, 11)
    f_label  = _font(_REGULAR_FONTS,  9)
    f_big    = _font(_BOLD_FONTS,    24)  # top row numbers
    f_mid    = _font(_BOLD_FONTS,    20)  # bottom row numbers
    f_footer = _font(_REGULAR_FONTS, 10)

    # Header (inverted)
    d.rectangle((0, 0, W - 1, ROW1_Y - 1), fill=0)
    d.text((4, 3),       'SteelHaze', font=f_title, fill=255)
    d.text((W - 88, 4),  ip,          font=f_ip,    fill=255)

    # Grid lines
    d.line((0,     ROW1_Y, W,     ROW1_Y), fill=0, width=1)
    d.line((MID_X, ROW1_Y, MID_X, FOOT_Y), fill=0, width=1)
    d.line((0,     ROW2_Y, W,     ROW2_Y), fill=0, width=1)
    d.line((0,     FOOT_Y, W,     FOOT_Y), fill=0, width=1)

    if stats is None:
        d.text((8, 50), 'DB unavailable', font=f_label, fill=0)
    else:
        # -- Top-left: Active / Total --
        d.text((6, ROW1_Y + 2), 'ACTIVE', font=f_label, fill=0)
        active_str = f"{stats['active']}/{stats['total']}"
        d.text((6, ROW1_Y + 14), active_str, font=f_big, fill=0)

        # -- Top-right: Unknown (inverted when > 0) --
        unk = stats['unknown']
        d.text((MID_X + 5, ROW1_Y + 2), 'UNKNOWN', font=f_label, fill=0)
        if unk > 0:
            d.rectangle((MID_X + 1, ROW1_Y + 12, W - 2, ROW2_Y - 2), fill=0)
            d.text((MID_X + 6, ROW1_Y + 14), str(unk), font=f_big, fill=255)
        else:
            d.text((MID_X + 6, ROW1_Y + 14), '0', font=f_big, fill=0)

        # -- Bottom-left: Anomalies 24h unacknowledged (inverted when > 0) --
        anm = stats['anomalies']
        d.text((6, ROW2_Y + 2), 'ANOMALIES 24H', font=f_label, fill=0)
        if anm > 0:
            d.rectangle((2, ROW2_Y + 13, MID_X - 2, FOOT_Y - 2), fill=0)
            d.text((7, ROW2_Y + 14), str(anm), font=f_mid, fill=255)
        else:
            d.text((6, ROW2_Y + 14), '0', font=f_mid, fill=0)

        # -- Bottom-right: CVEs --
        d.text((MID_X + 5, ROW2_Y + 2), 'CVEs', font=f_label, fill=0)
        d.text((MID_X + 6, ROW2_Y + 14), str(stats['cves']), font=f_mid, fill=0)

    # Footer
    scan_str = _time_ago(stats['last_scan']) if stats else '?'
    now_str  = datetime.now().strftime('%H:%M')
    d.text((4,      FOOT_Y + 1), f'scan {scan_str}', font=f_footer, fill=0)
    d.text((W - 32, FOOT_Y + 1), now_str,            font=f_footer, fill=0)

    return img


class _EpaperThread(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True, name='epaper')
        self._stop = threading.Event()

    def stop(self):
        self._stop.set()

    def run(self):
        try:
            epd = epd2in13_V4.EPD()
            epd.init()
            epd.Clear(0xFF)
            log.info('e-paper display ready')
        except Exception as e:
            log.error(f'e-paper init failed: {e}')
            return

        while not self._stop.is_set():
            try:
                img = _draw(_stats(), _local_ip())
                epd.display(epd.getbuffer(img))
            except Exception as e:
                log.warning(f'e-paper update error: {e}')

            self._stop.wait(REFRESH_INTERVAL)

        # Shutdown: clear and sleep
        try:
            epd.init()
            epd.Clear(0xFF)
            epd.sleep()
            log.info('e-paper display off')
        except Exception:
            pass


def start():
    """Start the e-paper display thread. No-op if waveshare_epd is not installed."""
    if not _AVAILABLE:
        log.info('waveshare_epd not found — display disabled')
        return None
    t = _EpaperThread()
    t.start()
    return t
