"""What the web app makes of the agent's scan plugin (roadmap section 11.4; the plugin is agent/src/bin/plugin-scan.rs and the script
it carries is agent/scan/inventory.scan). Scans on an agent host are scripts carried in the plugin (decision of 2026-11-16): the
controller sends no script and names none, it only takes what the plugin's own script wrote.

The plugin writes the sections of the SSH scan's inventory that can be read from files, in the same form, and they are read here with
the same parser (remote.inventory_of). Everything is the agent's claim, under the host its key belongs to.

    take_inventory(conn, host, body, at)  an `inventory` reading, one part of a run; when a run's parts are all in:
        on a monitoring-only host       the host's inventory and its mounts, labelled as reported by agent (there is no SSH scan)
        on a host with SSH as well      compared with what the last SSH scan read: the hostname, the OS and the filesystems mounted
    problems(conn, now)
        agent-scan-disagree:HOST        the scan plugin and the SSH scan say different things of the same host
        agent-scan-old:HOST             a monitoring-only host whose agent has not sent its inventory for STALE_SECS
"""
from __future__ import annotations

import json
import time

from .agentwatch import plugins_by_host
from .db import Conn, loads

MOST_PARTS = 64
MOST_PART = 48 << 10
STALE_SECS = 3 * 3600
LABEL = 'reported by agent'
PSEUDO = ('proc', 'sysfs', 'tmpfs', 'devtmpfs', 'devpts', 'cgroup', 'cgroup2', 'securityfs', 'debugfs', 'tracefs', 'mqueue', 'hugetlbfs',
          'pstore', 'bpf', 'configfs', 'fusectl', 'autofs', 'overlay', 'nsfs', 'ramfs', 'squashfs', 'efivarfs', 'binfmt_misc', 'rpc_pipefs')


def _row(conn: Conn, host: str) -> dict | None:
    rows = conn.all('SELECT at, received_at, script, sections_json, compared_json FROM agent_inventory WHERE host = :h', {'h': host})
    if not rows:
        return None
    at, received, script, sections, compared = rows[0]
    return {'at': at, 'received_at': received, 'script': script, 'data': loads(sections) or {}, 'compared': loads(compared)}


def _save(conn: Conn, host: str, **f):
    if _row(conn, host) is None:
        conn.execute("INSERT INTO agent_inventory (host, at, received_at, script, sections_json) VALUES (:h, 0, 0, '', '{}')", {'h': host})
    conn.execute(f'UPDATE agent_inventory SET {", ".join(f"{k} = :{k}" for k in f)} WHERE host = :host_', f | {'host_': host})


def take_inventory(conn: Conn, host: str, body: dict, at: int) -> int:
    run, part, of, text = body.get('run'), body.get('part'), body.get('of'), body.get('text')
    ok = all(isinstance(x, int) and not isinstance(x, bool) for x in (run, part, of)) and isinstance(text, str)
    if not ok or not (0 <= part < of <= MOST_PARTS) or len(text) > MOST_PART or body.get('script') != 'inventory':
        return 0
    row = _row(conn, host) or {'data': {}}
    parts = row['data'].get('parts') if row['data'].get('run') == run else None
    parts = dict(parts or {})
    parts[str(part)] = text
    if len(parts) < of:
        _save(conn, host, sections_json=json.dumps({'run': run, 'of': of, 'parts': parts, 'sections': row['data'].get('sections')}), received_at=at)
        return 1
    from .remote import parse_sections
    whole = ''.join(parts.get(str(i), '') for i in range(of))
    sections = parse_sections(whole)
    when = min(run, at)
    _save(conn, host, at=when, received_at=at, script='inventory', sections_json=json.dumps({'run': run, 'sections': sections}))
    mode = conn.scalar('SELECT mode FROM agents WHERE host = :h', {'h': host})
    if mode == 'monitoring':
        apply_monitoring(conn, host, sections, when)
    else:
        _save(conn, host, compared_json=json.dumps(compare(conn, host, sections) | {'at': at}))
    return 1


class _Dialect:
    def __init__(self, dialect):
        self.dialect = dialect

    def ts(self, expr: str) -> str:
        return expr if self.dialect == 'sqlite' else f'to_timestamp({expr})'


def apply_monitoring(conn: Conn, host: str, sections: dict, at: int):
    """A monitoring-only host's inventory and mounts, from its agent: there is no SSH scan to take them from. Its machine id is not
    taken from here; it was pinned when an admin adopted the host, and what the agent claims is compared with it (agentwatch)."""
    from .db import Database
    from .remote import inventory_of
    from .scanner import ScanOptions, plan_mounts
    rows = conn.all('SELECT host_id, ssh_host FROM hosts WHERE hostname = :h', {'h': host})
    if not rows:
        return
    host_id, address = rows[0]
    inv = inventory_of(sections, address or host)
    data = json.loads(inv.to_json()) | {'source': 'agent', 'label': LABEL, 'agent_at': at}
    dialect = _Dialect(conn.dialect)
    cast = ':inv' if conn.dialect == 'sqlite' else 'CAST(:inv AS jsonb)'
    conn.execute(f'UPDATE hosts SET inventory_json = {cast}, os_info = :os, last_scanned_at = {dialect.ts(":at")} WHERE host_id = :h',
                 {'inv': json.dumps(data), 'os': inv.os_info, 'at': at, 'h': host_id})
    planned = plan_mounts(inv.mounts, ScanOptions())
    Database.sync_mounts(dialect, conn, host_id, planned)
    conn.execute("""INSERT INTO mount_usage (host_id, mount_point, at, used_bytes, total_bytes)
                    SELECT host_id, mount_point, :now, used_bytes, total_bytes FROM mounts
                    WHERE host_id = :h AND total_bytes > 0 AND used_bytes IS NOT NULL
                    AND scan_state NOT IN ('gone', 'bind-alias')""", {'now': at, 'h': host_id})
    try:
        from .graph import rebuild_host
        rebuild_host(None, conn, host)
    except Exception:
        from . import errlog
        errlog.trace()


def _mounted(mounts) -> set:
    out = set()
    for m in mounts or []:
        target = m.get('target') if isinstance(m, dict) else getattr(m, 'target', None)
        fstype = m.get('fstype') if isinstance(m, dict) else getattr(m, 'fstype', None)
        if target and fstype and fstype not in PSEUDO and not str(target).startswith(('/proc', '/sys', '/dev', '/run')):
            out.add(target)
    return out


def compare(conn: Conn, host: str, sections: dict) -> dict:
    """The scan plugin's inventory beside the last SSH scan's: what differs. Where there was no SSH scan there is nothing to compare."""
    from .remote import RemoteError, inventory_of
    row = conn.all('SELECT inventory_json, os_info, ssh_host FROM hosts WHERE hostname = :h', {'h': host})
    ssh = loads(row[0][0] or '{}') if row else {}
    if not ssh or ssh.get('source') == 'agent':
        return {'differs': [], 'compared': False}
    try:
        inv = inventory_of(sections, row[0][2] or host)
    except RemoteError:
        return {'differs': ['the agent sent no mount table'], 'compared': True}
    differs = []
    if (row[0][1] or '').split(' · ')[0] != (inv.os_info or '').split(' · ')[0]:
        differs.append(f'the OS: the agent says {(inv.os_info or "nothing")[:80]}, the scan {(row[0][1] or "nothing")[:80]}')
    theirs, mine = _mounted(ssh.get('mounts')), _mounted(inv.mounts)
    if theirs and mine != theirs:
        only_scan, only_agent = sorted(theirs - mine)[:5], sorted(mine - theirs)[:5]
        differs.append('the filesystems mounted: ' + '; '.join(x for x in (f'only the scan saw {", ".join(only_scan)}' if only_scan else '',
                                                                        f'only the agent saw {", ".join(only_agent)}' if only_agent else '') if x))
    ssh_pools = {p.get('name') for p in (ssh.get('zfs_pools') or []) if isinstance(p, dict) and p.get('name')}
    agent_pools = {p.get('name') if isinstance(p, dict) else getattr(p, 'name', None) for p in (getattr(inv, 'zfs_pools', None) or [])} - {None}
    if ssh_pools and agent_pools and ssh_pools != agent_pools:
        differs.append(f'the ZFS pools: scan saw {", ".join(sorted(ssh_pools))}, agent saw {", ".join(sorted(agent_pools))}')
    return {'differs': differs, 'compared': True}


def view(conn: Conn, host: str) -> dict | None:
    r = _row(conn, host)
    if not r:
        return None
    return {'at': r['at'], 'received_at': r['received_at'], 'sections': sorted((r['data'].get('sections') or {}).keys()), 'compared': r['compared'], 'label': LABEL}


def problems(conn: Conn, now: float | None = None) -> dict:
    now = int(now or time.time())
    out = {}
    plugins = plugins_by_host(conn)
    for host, mode in conn.all("SELECT host, mode FROM agents WHERE enabled = 1 AND state = 'running'"):
        r = _row(conn, host)
        if r and (r['compared'] or {}).get('differs'):
            out[f'agent-scan-disagree:{host}'] = ('agent-scan-disagree', host, f'The agent\'s scan and the SSH scan disagree about {host}',
                                                  f'{LABEL}, against what the SSH scan measured: ' + '; '.join(r['compared']['differs'])[:500], 'warn')
        if mode == 'monitoring':
            if 'scan' in plugins.get(host, ()) and (not r or now - (r['received_at'] or 0) > STALE_SECS):
                out[f'agent-scan-old:{host}'] = ('agent-scan-old', host, f'{host} has not sent its inventory',
                                                 f'a monitoring-only host is read through its agent alone, and its scan plugin has sent nothing for {STALE_SECS // 3600} hours', 'warn')
    return out
