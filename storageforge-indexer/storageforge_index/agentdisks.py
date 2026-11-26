"""What the web app makes of the agent's disks plugin (roadmap section 11.4 and PF-04; the plugin is agent/src/bin/plugin-disks.rs).

The plugin sends each disk's health in the shape `smartctl -j -a` prints, so it is read here with the same function the SSH collector's
report is read with (health._smart): the two say the same of the same disk, and can be compared. Everything here is the agent's claim,
under the host its key belongs to.

    take_smart(conn, host, body, at)    a `smart` reading: one row of agent_disks per disk
    take_errors(conn, host, body, at)   an `errors` reading: the kernel's count of a disk's failed commands, md's per member, and the
                                        kernel's lines that say a disk failed, kept per disk (the last LINES_KEPT)
    disks(conn, host)                   what the agent last said of each disk, labelled as its claim, beside what the SSH collector said
    problems(conn, now)                 for the notification center:
        agent-smart:HOST:DEV            a disk the agent says fails or has bad sectors, where no scan over SSH says anything of it (a
                                        monitoring-only host, or a host without the collector)
        agent-disk-disagree:HOST:DEV    the agent and the SSH collector say different things of the same disk
        agent-disk-errors:HOST:DEV      the kernel counted failed commands on a disk, or wrote that it failed, in the last day
"""
from __future__ import annotations

import json
import re
import time

from .agentwatch import LABEL
from .db import Conn, loads

LINES_KEPT = 20
ERRORS_RECENT_SECS = 86400
MOST_DISKS = 64
DEV_RE = re.compile(r'[A-Za-z0-9]{1,32}|md:[A-Za-z0-9]{1,16}/[A-Za-z0-9]{1,32}')


def _text(value, most: int) -> str:
    return value[:most] if isinstance(value, str) else ''


def _row(conn: Conn, host: str, dev: str) -> dict | None:
    rows = conn.all('SELECT at, health_json, raw_json, lines_json, ioerr, ioerr_at, error FROM agent_disks WHERE host = :h AND dev = :d', {'h': host, 'd': dev})
    if not rows:
        return None
    at, health, raw, lines, ioerr, ioerr_at, error = rows[0]
    return {'at': at, 'health': loads(health), 'raw': loads(raw), 'lines': loads(lines) or [], 'ioerr': ioerr, 'ioerr_at': ioerr_at, 'error': error}


def _save(conn: Conn, host: str, dev: str, at: int, **fields):
    if _row(conn, host, dev) is None:
        conn.execute('INSERT INTO agent_disks (host, dev, at) VALUES (:h, :d, :t)', {'h': host, 'd': dev, 't': at})
    fields['at'] = at
    conn.execute(f'UPDATE agent_disks SET {", ".join(f"{k} = :{k}" for k in fields)} WHERE host = :host_ AND dev = :dev_', fields | {'host_': host, 'dev_': dev})


def take_smart(conn: Conn, host: str, body: dict, at: int) -> int:
    from .health import _smart
    n = 0
    for d in (body.get('disks') if isinstance(body.get('disks'), list) else [])[:MOST_DISKS]:
        dev = d.get('dev') if isinstance(d, dict) else None
        if not isinstance(dev, str) or not DEV_RE.fullmatch(dev) or dev.startswith('md:'):
            continue
        raw = d.get('smartctl') if isinstance(d.get('smartctl'), dict) else None
        text = json.dumps(raw) if raw else ''
        health = _smart(text) if raw and len(text) < 64 << 10 else None
        about = {k: _text(d.get(k), 100) for k in ('model', 'serial', 'firmware', 'kind')}
        _save(conn, host, dev, at, health_json=json.dumps(health | about) if health else json.dumps(about),
              raw_json=text if health else None, error=_text(d.get('error'), 300) or (None if health else 'the disk answered nothing to read'))
        n += 1
    return n


def take_errors(conn: Conn, host: str, body: dict, at: int) -> int:
    n = 0
    counts = body.get('ioerr') if isinstance(body.get('ioerr'), dict) else {}
    md = body.get('md') if isinstance(body.get('md'), dict) else {}
    for dev, count in list(counts.items())[:MOST_DISKS] + [(f'md:{k}', v) for k, v in list(md.items())[:MOST_DISKS]]:
        if not isinstance(dev, str) or not DEV_RE.fullmatch(dev) or not isinstance(count, int) or count < 0:
            continue
        before = _row(conn, host, dev)
        grew = before is not None and before['ioerr'] is not None and count > before['ioerr']
        # the first reading after the agent starts is where counting begins: what the kernel counted before is not news
        _save(conn, host, dev, at, ioerr=count, **({'ioerr_at': at} if grew else {}))
        n += 1
    for line in (body.get('lines') if isinstance(body.get('lines'), list) else [])[:50]:
        if not isinstance(line, dict):
            continue
        dev = line.get('dev') if isinstance(line.get('dev'), str) and DEV_RE.fullmatch(line.get('dev') or '') else ''
        # a partition's line is its disk's: sda1 is sda, nvme0n1p2 is nvme0n1
        dev = re.sub(r'(nvme\d+n\d+)p\d+$', r'\1', dev) if dev.startswith('nvme') else re.sub(r'^(sd[a-z]+|vd[a-z]+)\d+$', r'\1', dev)
        row = _row(conn, host, dev) or {'lines': []}
        lines = (row['lines'] + [{'at': int(line['at']) // 1_000_000 if isinstance(line.get('at'), int) else at, 'message': _text(line.get('message'), 500)}])[-LINES_KEPT:]
        _save(conn, host, dev, at, lines_json=json.dumps(lines), ioerr_at=at)
        n += 1
    return n


def _ssh_health(conn: Conn, host: str) -> dict:
    """What the SSH collector's last report said of each disk, by name."""
    inv = loads(conn.scalar('SELECT inventory_json FROM hosts WHERE hostname = :h', {'h': host}) or '{}') or {}
    report = inv.get('health') if isinstance(inv, dict) else None
    return (report or {}).get('disks') or {} if isinstance(report, dict) else {}


def disks(conn: Conn, host: str) -> list[dict]:
    ssh = _ssh_health(conn, host)
    out = []
    for (dev,) in conn.all('SELECT dev FROM agent_disks WHERE host = :h ORDER BY dev', {'h': host}):
        r = _row(conn, host, dev)
        out.append(r | {'dev': dev, 'raw': None, 'source': 'agent', 'label': LABEL, 'scan': ssh.get(dev)})
    return out


def problems(conn: Conn, now: float | None = None) -> dict:
    now = int(now or time.time())
    out = {}
    hosts = [h for (h,) in conn.all("SELECT host FROM agents WHERE enabled = 1 AND state = 'running'")]
    for host in hosts:
        ssh = _ssh_health(conn, host)
        for (dev,) in conn.all('SELECT dev FROM agent_disks WHERE host = :h', {'h': host}):
            r = _row(conn, host, dev)
            h = r['health'] or {}
            state = h.get('smart')
            theirs = (ssh.get(dev) or {}).get('smart')
            bad = ', '.join(f'{h[k]} {k}' for k in ('reallocated', 'pending', 'uncorrectable') if h.get(k))
            if state in ('fail', 'warn') and theirs is None:
                out[f'agent-smart:{host}:{dev}'] = ('agent-smart', host, f'/dev/{dev} on {host} ' + ('fails its SMART check' if state == 'fail' else 'reports bad sectors'),
                                                    f'{LABEL}: {bad or "replace it"}. No scan over SSH reads this disk to confirm it', 'crit' if state == 'fail' else 'warn')
            if state and theirs and state != theirs:
                out[f'agent-disk-disagree:{host}:{dev}'] = ('agent-disk-disagree', host, f'The agent and the scan disagree about /dev/{dev} on {host}',
                                                            f'{LABEL}: {state}; measured by the SSH collector: {theirs}. One of them is stale, or one is lying', 'warn')
            if r['ioerr_at'] and now - r['ioerr_at'] < ERRORS_RECENT_SECS:
                last = r['lines'][-1]['message'] if r['lines'] else ''
                what = f'the kernel counts {r["ioerr"]} failed commands' if r['ioerr'] else 'the kernel wrote that it failed'
                name = dev[3:] if dev.startswith('md:') else (dev or 'a disk')
                out[f'agent-disk-errors:{host}:{dev}'] = ('agent-disk-errors', host, f'{name} on {host} has errors',
                                                          f'{LABEL}: {what}' + (f'; last: {last[:200]}' if last else ''), 'warn')
    return out
