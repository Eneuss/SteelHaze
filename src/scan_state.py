#shared scan state between monitor and Flask (same process, no IPC needed)
import threading
import copy

_lock = threading.Lock()
_interfaces = {}


def update(iface, subnet, status, error=None, devices=None):
    with _lock:
        prev = _interfaces.get(iface, {})
        _interfaces[iface] = {
            'subnet':  subnet,
            'status':  status,
            'error':   error,
            #keep previous device list while scanning so page doesn't go blank
            'devices': devices if devices is not None else prev.get('devices', []),
        }


def get_all():
    with _lock:
        return copy.deepcopy(_interfaces)
