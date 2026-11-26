"""What a Proxmox VE node offers a new guest: its storages, ISO images and container templates. The infra reading holds them, and the
Workloads page and the plan steps read them from there."""
from __future__ import annotations


def is_proxmox(reading: dict | None) -> bool:
    r = reading or {}
    tools = set(r.get('tools') or [])
    return 'pve' in ((r.get('wl_units') or {}).get('markers') or []) or 'qm' in tools or 'pct' in tools


def is_proxmox_host(conn, host: str, reading: dict | None = None) -> bool:
    """The scan's platform line (from pveversion) or the infra reading, so a node that was scanned but not yet measured is still seen.
    A caller that already holds the host's reading passes it."""
    from . import inframeasure, preflight
    if (preflight.facts_from_scan(conn, host).get('platform') or '').startswith('proxmox'):
        return True
    return is_proxmox(reading if reading is not None else inframeasure.reading(conn, host))


def refuse_on_node(conn, h: dict, say) -> bool:
    """The generic VM and LXC steps would make things Proxmox VE does not know of: on a node they say so and the check stops."""
    if not is_proxmox_host(conn, h['name']):
        return False
    say('crit', 'this is a Proxmox VE node: use Create a Proxmox VM or Create a Proxmox container (or the Proxmox action and remove steps), '
                'so Proxmox knows about it')
    return True


def _int(v: str) -> int | None:
    return int(v) if v.strip().isdigit() else None


def parse_node(lines: list[str]) -> dict:
    """The proxmox_node section: s NAME TYPE STATUS TOTAL USED (KiB), t NAME CONTENT, i VOLID SIZE (an ISO), v VOLID SIZE (a template)."""
    storages: dict[str, dict] = {}
    isos: list[dict] = []
    templates: list[dict] = []
    content: dict[str, list[str]] = {}
    for line in lines:
        f = line.split('\t')
        kind = f[0] if f else ''
        try:
            if kind == 's' and len(f) >= 6 and f[1]:
                storages[f[1]] = {'name': f[1], 'type': f[2], 'active': f[3] == 'active', 'content': [],
                                  'total_kib': _int(f[4]), 'used_kib': _int(f[5])}
            elif kind == 't' and len(f) >= 3 and f[1]:
                content[f[1]] = [c for c in f[2].strip().split(',') if c]
            elif kind in ('i', 'v') and len(f) >= 3 and ':' in f[1]:
                item = {'storage': f[1].split(':', 1)[0], 'volid': f[1], 'size': _int(f[2])}
                (isos if kind == 'i' else templates).append(item)
        except (IndexError, ValueError):
            continue
    for name, c in content.items():
        if name in storages:
            storages[name]['content'] = c
    return {'storages': list(storages.values()), 'isos': isos, 'templates': templates}
