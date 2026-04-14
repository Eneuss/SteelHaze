#!/usr/bin/env python3
import threading
import subprocess
import sqlite3
import time
from datetime import datetime

try:
    from scapy.all import sniff, ARP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from scanner import get_network_info, get_local_ips
from database import DB_PATH


class PassiveScanner:
    def __init__(self):
        self._seen = {}   # mac -> {ip, first_seen, last_seen}
        self._lock = threading.Lock()

    def _arp_handler(self, pkt):
        if ARP not in pkt:
            return
        if pkt[ARP].op not in (1, 2):
            return
        ip  = pkt[ARP].psrc
        mac = pkt[ARP].hwsrc
        if ip == "0.0.0.0" or not mac or mac == "ff:ff:ff:ff:ff:ff":
            return
        now = datetime.now()
        with self._lock:
            if mac in self._seen:
                self._seen[mac]['ip']        = ip
                self._seen[mac]['last_seen'] = now
            else:
                self._seen[mac] = {'ip': ip, 'first_seen': now, 'last_seen': now}

    def _arp_sniffer(self, iface):
        try:
            sniff(prn=self._arp_handler, filter="arp", store=False, iface=iface)
        except Exception as e:
            print(f"[PassiveScanner] ARP sniffer error: {e}")

    def _cache_reader(self):
        while True:
            try:
                local = set(get_local_ips())
                result = subprocess.run(
                    ["ip", "neigh", "show"],
                    capture_output=True, text=True, timeout=5
                )
                now = datetime.now()
                for line in result.stdout.splitlines():
                    parts = line.split()
                    # format: <ip> dev <iface> lladdr <mac> <state>
                    if len(parts) < 5 or ":" not in parts[4]:
                        continue
                    ip    = parts[0]
                    mac   = parts[4]
                    state = parts[-1]
                    if ip in local or state in ("FAILED", "INCOMPLETE"):
                        continue
                    with self._lock:
                        if mac in self._seen:
                            self._seen[mac]['ip']        = ip
                            self._seen[mac]['last_seen'] = now
                        else:
                            self._seen[mac] = {'ip': ip, 'first_seen': now, 'last_seen': now}
            except Exception as e:
                print(f"[PassiveScanner] Cache reader error: {e}")
            time.sleep(30)

    def start(self):
        if not SCAPY_AVAILABLE:
            print("[PassiveScanner] scapy not available — passive detection disabled.")
            return
        net   = get_network_info()
        iface = net.get("interface") or None
        threading.Thread(target=self._arp_sniffer, args=(iface,), daemon=True).start()
        threading.Thread(target=self._cache_reader, daemon=True).start()
        print(f"[PassiveScanner] Started on interface: {iface or 'default'}")

    def get_seen(self):
        with self._lock:
            return {mac: dict(v) for mac, v in self._seen.items()}

    def get_recently_seen_ips(self, seconds=300):
        """Return set of IPs seen by ARP within the last `seconds` seconds."""
        cutoff = datetime.now().timestamp() - seconds
        with self._lock:
            return {
                data['ip']
                for data in self._seen.values()
                if data['last_seen'].timestamp() >= cutoff
            }

    def save_new_to_db(self, network_info):
        """Save passively-seen devices to DB with source='passive'. Returns list of new IPs added."""
        seen  = self.get_seen()
        local = set(get_local_ips())
        if not seen:
            return []

        conn   = sqlite3.connect(DB_PATH, timeout=30)
        cursor = conn.cursor()

        cursor.execute(
            "SELECT id FROM networks WHERE gateway_ip = ? AND subnet = ?",
            (network_info["gateway_ip"], network_info["subnet"])
        )
        row = cursor.fetchone()
        if not row:
            conn.close()
            return []
        network_id = row[0]

        new_ips = []
        for mac, data in seen.items():
            ip = data['ip']
            if ip in local:
                continue

            now = datetime.now()

            cursor.execute("SELECT id FROM devices WHERE mac = ?", (mac,))
            row = cursor.fetchone()
            if row:
                device_id = row[0]
                cursor.execute("UPDATE devices SET last_seen = ? WHERE id = ?", (now, device_id))
            else:
                cursor.execute("INSERT INTO devices (mac) VALUES (?)", (mac,))
                device_id = cursor.lastrowid

            cursor.execute(
                "SELECT id, source FROM device_network WHERE device_id = ? AND network_id = ?",
                (device_id, network_id)
            )
            dn = cursor.fetchone()
            if dn:
                # Only update timestamp/ip; don't downgrade nmap -> passive
                cursor.execute(
                    "UPDATE device_network SET last_seen = ?, ip = ? WHERE id = ?",
                    (now, ip, dn[0])
                )
            else:
                cursor.execute(
                    "INSERT INTO device_network (device_id, network_id, ip, is_known, source) "
                    "VALUES (?, ?, ?, 0, 'passive')",
                    (device_id, network_id, ip)
                )
                new_ips.append(ip)
                print(f"[PassiveScanner] New passive device: {ip}  {mac}")

        conn.commit()
        conn.close()
        return new_ips


passive_scanner = PassiveScanner()
