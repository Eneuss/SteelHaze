#!/usr/bin/env python3
from collections import defaultdict
from datetime import datetime
import threading

try:
    from scapy.all import sniff, IP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class TrafficMonitor:
    def __init__(self):
        self.traffic_data = defaultdict(
            lambda: {"bytes_sent": 0, "bytes_received": 0, "packets": 0, "last_updated": datetime.now()}
        )
        self._lock = threading.Lock()
        self.monitoring = False
        self._thread = None

    def _packet_handler(self, packet):
        if IP not in packet:
            return
        src = packet[IP].src
        dst = packet[IP].dst
        size = len(packet)
        with self._lock:
            if src.startswith("192.168.") or src.startswith("10.") or src.startswith("172."):
                d = self.traffic_data[src]
                d["bytes_sent"] += size
                d["packets"] += 1
                d["last_updated"] = datetime.now()
            if dst.startswith("192.168.") or dst.startswith("10.") or dst.startswith("172."):
                d = self.traffic_data[dst]
                d["bytes_received"] += size
                d["packets"] += 1
                d["last_updated"] = datetime.now()

    def start_monitoring(self, interface=None):
        if not SCAPY_AVAILABLE:
            print("[TrafficMonitor] scapy not installed — traffic monitoring disabled.")
            return
        if self.monitoring:
            return

        def _run():
            print(f"[TrafficMonitor] Listening on interface: {interface or 'default'}")
            try:
                sniff(prn=self._packet_handler, store=False, iface=interface)
            except Exception as e:
                print(f"[TrafficMonitor] Error: {e}")

        self.monitoring = True
        self._thread = threading.Thread(target=_run, daemon=True)
        self._thread.start()

    def get_traffic_stats(self):
        with self._lock:
            stats = {}
            for ip, data in self.traffic_data.items():
                stats[ip] = {
                    "bytes_sent": data["bytes_sent"],
                    "bytes_received": data["bytes_received"],
                    "total_bytes": data["bytes_sent"] + data["bytes_received"],
                    "packets": data["packets"],
                    "last_updated": data["last_updated"].isoformat(),
                }
        return stats

    def reset_stats(self):
        with self._lock:
            self.traffic_data.clear()


traffic_monitor = TrafficMonitor()
