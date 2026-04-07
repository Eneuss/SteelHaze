#!/usr/bin/env python3
"""
Shared in-memory scan state. Both monitor.py and app.py import this module.
Because Flask and the monitor run in the same process (Flask in a daemon thread),
the module-level dict is truly shared — no IPC needed.
"""
import threading
import copy

_lock = threading.Lock()
_interfaces = {}
# {
#   'eth0': {
#     'subnet':  '192.168.1.0/24',
#     'status':  'idle' | 'scanning' | 'done' | 'no_devices' | 'error',
#     'error':   None | 'error message string',
#     'devices': [{ip, mac, status}, ...]   # raw nmap results for this interface
#   }
# }


def update(iface, subnet, status, error=None, devices=None):
    with _lock:
        prev = _interfaces.get(iface, {})
        _interfaces[iface] = {
            'subnet':  subnet,
            'status':  status,
            'error':   error,
            # keep previous device list while scanning so page doesn't go blank
            'devices': devices if devices is not None else prev.get('devices', []),
        }


def get_all():
    with _lock:
        return copy.deepcopy(_interfaces)
