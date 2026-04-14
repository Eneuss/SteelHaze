#!/usr/bin/env python3
"""
SteelHaze V2 — main entry point.
Starts both the network monitor loop and the Flask web dashboard in parallel.

Usage:
    sudo python main.py
"""
import os
import threading

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from database import init_database


def run_web():
    from app import app
    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)


def run_monitor(interval=30):
    from monitor import monitor_loop
    monitor_loop(interval=interval)


def main():
    init_database()

    print("=== SteelHaze V2 ===")
    print("Dashboard: http://localhost:5000\n")

    web_thread = threading.Thread(target=run_web, daemon=True)
    web_thread.start()

    from telegram_notify import start_summary_thread
    start_summary_thread()

    run_monitor(interval=30)


if __name__ == '__main__':
    main()
