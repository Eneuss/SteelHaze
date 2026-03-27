#!/usr/bin/env python3
"""
SteelHaze V2 — main entry point.
Starts both the network monitor loop and the Flask web dashboard in parallel.

Usage:
    sudo python main.py            # full mode (traffic monitoring needs root)
    python main.py --no-traffic    # skip packet sniffing (no root needed)
    python main.py --scan-only     # one-shot scan, no web UI
    python main.py --deep-scan     # CVE scan against NVD (slow)
"""
import sys
import os
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from database import init_database


def run_web():
    from app import app
    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)


def run_monitor(interval=30):
    from monitor import monitor_loop
    monitor_loop(interval=interval)


def main():
    args = sys.argv[1:]

    init_database()

    if '--deep-scan' in args:
        from nvd_scanner import run_nvd_scan
        run_nvd_scan()
        return

    if '--scan-only' in args:
        from scanner import scan_network
        devices = scan_network()
        for d in devices:
            print(f"  {d['ip']:<16}  {d['mac']:<20}  {d['hostname']}")
        return

    if '--no-traffic' in args:
        from traffic_monitor import traffic_monitor
        traffic_monitor.monitoring = False  # prevent start
        # Monkey-patch so monitor doesn't start it
        import traffic_monitor as tm
        tm.traffic_monitor.start_monitoring = lambda **kw: None

    print("=== SteelHaze V2 ===")
    print("Dashboard: http://localhost:5000")
    print("Deep CVE scan: python main.py --deep-scan\n")

    # Run web server in background thread, monitor loop in foreground
    web_thread = threading.Thread(target=run_web, daemon=True)
    web_thread.start()

    run_monitor(interval=30)


if __name__ == '__main__':
    main()
