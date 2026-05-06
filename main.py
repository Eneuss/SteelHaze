"""
SteelHaze starting point.
Starts both the network monitor loop and the Flask web dashboard in parallel.
"""
import os
import socket
import time
import threading

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from database import set_active_ssid
from scanner import get_network_info


def wait_for_network(timeout=60):
    print("[SteelHaze] Waiting for network...")
    start = time.time()
    while time.time() - start < timeout:
        try:
            socket.setdefaulttimeout(3)
            socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect(("8.8.8.8", 53))
            print("[SteelHaze] Network is up!")
            return True
        except OSError:
            time.sleep(5)
    print("[SteelHaze] Network timeout, continuing anyway...")
    return False


def run_web():
    from app import app
    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)


def run_monitor(interval=30):
    from monitor import monitor_loop
    monitor_loop(interval=interval)


def main():
    wait_for_network()
    net = get_network_info()
    set_active_ssid(net.get('ssid'))

    print("=== SteelHaze ===")
    print("Dashboard: http://localhost:5000\n")

    web_thread = threading.Thread(target=run_web, daemon=True)
    web_thread.start()

    from telegram_notify import start_summary_thread
    start_summary_thread()

    run_monitor(interval=30)


if __name__ == '__main__':
    main()
