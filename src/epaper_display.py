"""
Waveshare 2.13" V4 e-paper display for SteelHaze.
If the display is not connected or the library is unavailable
every call is silently skipped — the monitor continues normally.
"""
import math
import time
import urllib.request
from datetime import datetime

try:
    from PIL import Image, ImageDraw, ImageFont
    _PIL_OK = True
except ImportError:
    _PIL_OK = False

_FONT_BOLD = '/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf'
_FONT_REG  = '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf'

W, H = 250, 122   # landscape: width x height


class EpaperDisplay:
    def __init__(self):
        if not _PIL_OK:
            raise RuntimeError('Pillow not installed')
        from waveshare_epd import epd2in13_V4
        self._epd = epd2in13_V4.EPD()
        self._epd.init()
        self._epd.Clear(0xFF)
        self._step          = 0     # radar rotation state (0-7)
        self._ext_ip        = None
        self._ext_ip_ts     = 0     # last fetch timestamp
        self._load_fonts()
        print('[Epaper] Display initialised (2.13" V4)')

    def _load_fonts(self):
        try:
            self._lg = ImageFont.truetype(_FONT_BOLD, 13)
            self._md = ImageFont.truetype(_FONT_REG, 11)
            self._sm = ImageFont.truetype(_FONT_REG, 9)
        except Exception:
            f = ImageFont.load_default()
            self._lg = self._md = self._sm = f

    def _refresh_ext_ip(self):
        if time.time() - self._ext_ip_ts < 300:
            return
        try:
            with urllib.request.urlopen('https://api.ipify.org', timeout=5) as r:
                self._ext_ip = r.read().decode().strip()
        except Exception:
            self._ext_ip = None
        self._ext_ip_ts = time.time()

    def _draw_radar(self, draw, cx, cy, r):
        """Draw a radar circle with a rotating sweep line."""
        draw.ellipse([(cx - r, cy - r), (cx + r, cy + r)], outline=255, width=1)
        angle = math.radians(self._step * 45)
        x2 = cx + int((r - 1) * math.sin(angle))
        y2 = cy - int((r - 1) * math.cos(angle))
        draw.line([(cx, cy), (x2, y2)], fill=255, width=1)
        self._step = (self._step + 1) % 8

    def update(self, ssid, subnet, total, unknown, anomalies, cves, scanning):
        self._refresh_ext_ip()

        img  = Image.new('1', (W, H), 255)
        draw = ImageDraw.Draw(img)
        now  = datetime.now().strftime('%H:%M')

        # ── header bar (black bg, white content) ──────────────────
        draw.rectangle([(0, 0), (W, 21)], fill=0)
        draw.text((6, 4), 'SteelHaze', font=self._lg, fill=255)
        draw.text((W - 37, 6), now, font=self._sm, fill=255)

        # scan dot — filled = scanning, outline = idle
        dot_cx, dot_cy, dot_r = W - 52, 11, 8
        if scanning:
            draw.ellipse([(dot_cx - dot_r, dot_cy - dot_r),
                          (dot_cx + dot_r, dot_cy + dot_r)], fill=255)
        else:
            draw.ellipse([(dot_cx - dot_r, dot_cy - dot_r),
                          (dot_cx + dot_r, dot_cy + dot_r)], outline=255, width=1)

        # radar sweep
        self._draw_radar(draw, cx=W - 90, cy=11, r=8)

        # ── separator ─────────────────────────────────────────────
        draw.line([(0, 22), (W, 22)], fill=0)

        # ── network ───────────────────────────────────────────────
        draw.text((6, 26), ssid or 'No SSID', font=self._md, fill=0)
        draw.text((6, 40), subnet or '', font=self._sm, fill=0)
        if self._ext_ip:
            ext_text = f'ext: {self._ext_ip}'
            bbox = draw.textbbox((0, 0), ext_text, font=self._sm)
            draw.text((W - (bbox[2] - bbox[0]) - 6, 40), ext_text, font=self._sm, fill=0)

        # ── separator ─────────────────────────────────────────────
        draw.line([(0, 53), (W, 53)], fill=0)

        # ── devices ───────────────────────────────────────────────
        draw.text((6,   57), f'Devices: {total}',   font=self._md, fill=0)
        draw.text((140, 57), f'Unknown: {unknown}', font=self._md, fill=0)

        # ── separator ─────────────────────────────────────────────
        draw.line([(0, 73), (W, 73)], fill=0)

        # ── anomalies ─────────────────────────────────────────────
        draw.text((6,   77), f'Anomalies: {anomalies}', font=self._md, fill=0)
        draw.text((160, 77), f'CVEs: {cves}',           font=self._md, fill=0)

        # ── separator ─────────────────────────────────────────────
        draw.line([(0, 93), (W, 93)], fill=0)

        # ── footer ────────────────────────────────────────────────
        ts = datetime.now().strftime('%d %b  %H:%M')
        draw.text((6, 97), f'Updated: {ts}', font=self._sm, fill=0)
        if scanning:
            draw.text((170, 97), 'SCANNING...', font=self._sm, fill=0)

        self._epd.display(self._epd.getbuffer(img))

    def clear_and_sleep(self):
        try:
            self._epd.Clear(0xFF)
            self._epd.sleep()
        except Exception:
            pass


def get_display_stats():
    """Query live stats from the active DB."""
    try:
        from database import db
        conn     = db()
        cur_nets = '''SELECT id FROM networks
                      WHERE last_seen IN (
                          SELECT MAX(last_seen) FROM networks GROUP BY interface
                      )'''
        total = conn.execute(f'''
            SELECT COUNT(DISTINCT d.id) FROM devices d
            JOIN device_network dn ON d.id = dn.device_id
            WHERE dn.network_id IN ({cur_nets})
            AND dn.last_seen > datetime('now', '-24 hours')
        ''').fetchone()[0]
        unknown = conn.execute(f'''
            SELECT COUNT(DISTINCT d.id) FROM devices d
            JOIN device_network dn ON d.id = dn.device_id
            WHERE dn.is_known = 0
            AND dn.network_id IN ({cur_nets})
            AND dn.last_seen > datetime('now', '-24 hours')
        ''').fetchone()[0]
        anomalies = conn.execute('''
            SELECT COUNT(*) FROM anomalies
            WHERE timestamp > datetime('now', '-24 hours') AND acknowledged = 0
        ''').fetchone()[0]
        cves = conn.execute('SELECT COUNT(*) FROM cve_findings').fetchone()[0]
        conn.close()
        return total, unknown, anomalies, cves
    except Exception as e:
        print(f'[Epaper] Stats query failed: {e}')
        return 0, 0, 0, 0


def init_display():
    """Try to initialise the display. Returns EpaperDisplay or None if unavailable."""
    try:
        return EpaperDisplay()
    except Exception as e:
        print(f'[Epaper] Not available — running without display: {e}')
        return None
