#!/usr/bin/env python3
"""
SteelHaze V2 — main entry point.
Starts both the network monitor loop and the Flask web dashboard in parallel.

Usage:
    sudo python main.py            # full mode
    python main.py --scan-only     # one-shot scan, no web UI
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

    if '--scan-only' in args:
        from scanner import scan_all_parallel
        results = scan_all_parallel()
        for iface, r in sorted(results.items()):
            print(f"\n[{iface}] {r['subnet']}")
            if r['error']:
                print(f"  Error: {r['error']}")
            elif not r['devices']:
                print("  No devices found.")
            else:
                for d in r['devices']:
                    print(f"  {d['ip']:<16}  {d['mac']:<20}")
        return

    print("=== SteelHaze V2 ===")
    print("Dashboard: http://localhost:5000\n")

    # Run web server in background thread, monitor loop in foreground
    web_thread = threading.Thread(target=run_web, daemon=True)
    web_thread.start()

    run_monitor(interval=30)


if __name__ == '__main__':
    main()
