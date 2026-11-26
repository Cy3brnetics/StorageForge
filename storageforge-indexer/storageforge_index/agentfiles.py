"""What the web app makes of the agent's files plugin (roadmap sections 11.4 and 9, "Watchers"; the plugin is
agent/src/bin/plugin-files.rs). The plugin is root on its host in effect, and only an admin switches it on (routes_agent.py).

Everything here is the agent's claim, stored under the host its key belongs to, never one a reading names.

    take_changes(conn, host, body, at)   a `changes` reading: each change kept in agent_file_events with the process and account
                                         behind it, applied to the host's file index where the host has an indexed mount for it
                                         (an index that updates itself), and a change to a file StorageForge manages, made while no
                                         deploy of the host ran, kept as a hand edit
    take_reads(conn, host, body, at)     a `reads` reading: files read per account and minute, for reads out of hours
    take_watching(conn, host, body, at)  which filesystems the plugin watches, and which it could not
    after_scan(conn, host, scan_id)      the file index from both (decision of 2026-11-16): a change the scan found that the agent never
                                         reported, and one the agent reported that the scan contradicts, are disagreements
    problems(conn, now)                  for the notification center:
        agent-hand-edit:HOST:PATH        a managed file edited by hand: configuration drift, which cannot be ignored. It leaves when a
                                         scan or a deploy of the host finished after the edit (the scan keeps the edited file in the
                                         host's configuration history)
        agent-offhours:HOST:USER         an account read more than the limit in an hour out of working hours
        agent-files-disagree:HOST        the agent and the scan disagree about the host's files
        agent-files-blind:HOST           the plugin could not watch a filesystem, or the kernel dropped events
"""
from __future__ import annotations

import datetime as dt
import json
import posixpath
import re
import time

from .db import Conn, loads
from .paths import deepest

MOST_EVENTS_PER_HOST = 50_000
KEEP_READS_SECS = 8 * 86400
RECENT_SECS = 86400
ACTIONS = ('write', 'create', 'delete', 'moved_from', 'moved_to')
SETTINGS_KEY = 'agent.files'
DEFAULTS = {'work_start': 7, 'work_end': 19, 'work_days': [0, 1, 2, 3, 4], 'offhours_reads_per_hour': 500, 'ransomware_burst_per_minute': 40}
LABEL = 'reported by agent'
_PATH_BAD = re.compile(r'[\x00-\x1f\x7f]')


def settings(conn: Conn) -> dict:
    from .alerts import get_setting
    got = get_setting(conn, SETTINGS_KEY) or {}
    return {**DEFAULTS, **{k: got[k] for k in DEFAULTS if k in got}}


def _path(value) -> str | None:
    if not isinstance(value, str) or not value.startswith('/') or len(value) > 4096 or _PATH_BAD.search(value):
        return None
    return posixpath.normpath(value)


def _int(value, most: int = 2**63 - 1):
    return value if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= most else None


def users(conn: Conn, host: str) -> dict:
    """uid to account name, from the host's last inventory (a scan's, or the scan plugin's)."""
    inv = loads(conn.scalar('SELECT inventory_json FROM hosts WHERE hostname = :h', {'h': host}) or '{}') or {}
    out = {0: 'root'}
    for line in str(inv.get('accounts') or '').splitlines():
        f = line.split('\t')
        if len(f) >= 3 and f[0] == 'u' and f[2].isdigit():
            out[int(f[2])] = f[1][:64]
    return out


def managed_paths(conn: Conn, host: str) -> set:
    """The files StorageForge wrote on the host and checks, as the last scan's drift check listed them."""
    inv = loads(conn.scalar('SELECT inventory_json FROM hosts WHERE hostname = :h', {'h': host}) or '{}') or {}
    out = set()
    for line in str(inv.get('managed') or '').splitlines():
        m = re.match(r'^(/\S+): (OK|FAILED)', line)
        if m:
            out.add(m.group(1))
    return out


def is_managed(path: str, managed: set) -> bool:
    from .hostconfig import CONFIG_PATH
    return path in managed or bool(CONFIG_PATH.fullmatch(path))


def _deploying(conn: Conn, host: str, at: int) -> bool:
    """Whether a deploy run of the host ran at that time (a change it made is no hand edit)."""
    return bool(conn.scalar("""SELECT count(*) FROM deploy_runs WHERE host = :h AND started_at <= :t
                               AND (finished_at IS NULL OR finished_at >= :t0)""", {'h': host, 't': at + 5, 't0': at - 30}))


def _mount_for(conn: Conn, host: str, path: str):
    rows = conn.all("""SELECT m.mount_id, m.mount_point FROM mounts m JOIN hosts h ON h.host_id = m.host_id
                       WHERE h.hostname = :h AND m.scan_state = 'indexed'""", {'h': host})
    return deepest(rows, path, key=lambda r: r[1])


def _apply_index(conn: Conn, host: str, path: str, act: str, st: dict | None) -> str:
    """The change made in the host's file index. Returns what was done, for the event's row."""
    from .db import dir_id
    found = _mount_for(conn, host, path)
    if not found or path == found[1]:
        return 'no indexed mount'
    mount_id = found[0]
    parent, name = posixpath.split(path)
    sqlite = conn.dialect == 'sqlite'
    rows = conn.all("""SELECT r.file_id FROM file_records r JOIN directories d ON d.dir_id = r.dir_id
                       WHERE d.mount_id = :m AND d.path = :p AND r.filename = :n""", {'m': mount_id, 'p': parent, 'n': name})
    if act in ('delete', 'moved_from'):
        if not rows:
            return 'not in the index'
        if sqlite:
            conn.execute("INSERT INTO file_fts (file_fts, rowid, filename) VALUES ('delete', :i, :n)", {'i': rows[0][0], 'n': name})
        conn.execute('DELETE FROM file_records WHERE file_id = :i', {'i': rows[0][0]})
        return 'removed'
    if not isinstance(st, dict) or _int(st.get('size')) is None or _int(st.get('mtime')) is None:
        return 'gone before it could be read'
    is_dir = st.get('kind') == 'dir'
    p = {'size': 0 if is_dir else st['size'], 'mtime': st['mtime'], 'uid': _int(st.get('uid'), 2**32), 'gid': _int(st.get('gid'), 2**32),
         'dir': is_dir if not sqlite else int(is_dir), 'link': (st.get('kind') == 'link') if not sqlite else int(st.get('kind') == 'link')}
    if rows:
        conn.execute(f"""UPDATE file_records SET file_size_bytes = :size, modified_at = {conn.ts(':mtime')}, owner_uid = :uid, group_gid = :gid,
                             checksum_hash = CASE WHEN file_size_bytes <> :size THEN NULL ELSE checksum_hash END WHERE file_id = :i""", p | {'i': rows[0][0]})
        return 'updated'
    ext = '' if is_dir or '.' not in name.lstrip('.') else name.rsplit('.', 1)[1].lower()[:32]
    did = dir_id(conn, mount_id, parent)
    fid = conn.scalar(f"""INSERT INTO file_records (mount_id, dir_id, filename, extension, file_size_bytes, is_directory, is_symlink, owner_uid, group_gid, modified_at)
                          VALUES (:m, :d, :n, :e, :size, :dir, :link, :uid, :gid, {conn.ts(':mtime')})
                          ON CONFLICT (dir_id, filename) DO NOTHING RETURNING file_id""", p | {'m': mount_id, 'd': did, 'n': name, 'e': ext})
    if fid and sqlite:
        conn.execute('INSERT INTO file_fts (rowid, filename) VALUES (:i, :n)', {'i': fid, 'n': name})
    return 'added'


def take_changes(conn: Conn, host: str, body: dict, at: int) -> int:
    changes = body.get('changes') if isinstance(body.get('changes'), list) else []
    who, managed, n = users(conn, host), managed_paths(conn, host), 0
    for c in changes[:1000]:
        if not isinstance(c, dict):
            continue
        path, act = _path(c.get('path')), c.get('action')
        if not path or act not in ACTIONS:
            continue
        when = min(_int(c.get('at')) or at, at)          # nothing is dated ahead of when it came
        uid = _int(c.get('uid'), 2**32)
        is_hand = act in ('write', 'create', 'moved_to') and is_managed(path, managed) and not _deploying(conn, host, when)
        indexed = _apply_index(conn, host, path, act, c.get('stat'))
        conn.execute("""INSERT INTO agent_file_events (host, at, received_at, path, action, pid, process, uid, user_name, managed, indexed)
                        VALUES (:h, :t, :r, :p, :a, :pid, :proc, :uid, :user, :m, :i)""",
                     {'h': host, 't': when, 'r': at, 'p': path, 'a': act, 'pid': _int(c.get('pid'), 2**32), 'proc': (c.get('process') or '')[:64] if isinstance(c.get('process'), str) else None,
                      'uid': uid, 'user': who.get(uid) if uid is not None else None, 'm': 1 if is_hand else 0, 'i': indexed})
        n += 1
    blind = {k: _int(body.get(k)) or 0 for k in ('left_out', 'overflow')}
    if blind['left_out'] or blind['overflow']:
        _note(conn, host, 'dropped', blind | {'at': at})
    over = conn.scalar('SELECT count(*) FROM agent_file_events WHERE host = :h', {'h': host}) or 0
    if over > MOST_EVENTS_PER_HOST:
        cut = conn.scalar('SELECT event_id FROM agent_file_events WHERE host = :h ORDER BY event_id DESC LIMIT 1 OFFSET :n', {'h': host, 'n': MOST_EVENTS_PER_HOST})
        conn.execute('DELETE FROM agent_file_events WHERE host = :h AND event_id <= :c AND managed = 0', {'h': host, 'c': cut})
    return n


def take_reads(conn: Conn, host: str, body: dict, at: int) -> int:
    minute = _int(body.get('minute'))
    if minute is None or minute * 60 > at + 120:
        return 0
    who, n = users(conn, host), 0
    for a in (body.get('accounts') if isinstance(body.get('accounts'), list) else [])[:500]:
        if not isinstance(a, dict) or _int(a.get('reads')) is None:
            continue
        uid = _int(a.get('uid'), 2**32)
        uid = -1 if uid is None else uid
        folders = {k[:300]: v for k, v in list((a.get('folders') or {}).items())[:10] if isinstance(k, str) and _int(v) is not None} if isinstance(a.get('folders'), dict) else {}
        conn.execute('DELETE FROM agent_file_reads WHERE host = :h AND minute = :m AND uid = :u', {'h': host, 'm': minute, 'u': uid})
        conn.execute("""INSERT INTO agent_file_reads (host, minute, uid, user_name, reads, folders_json) VALUES (:h, :m, :u, :n, :r, :f)""",
                     {'h': host, 'm': minute, 'u': uid, 'n': who.get(uid), 'r': a['reads'], 'f': json.dumps(folders)})
        n += 1
    conn.execute('DELETE FROM agent_file_reads WHERE host = :h AND minute < :m', {'h': host, 'm': (at - KEEP_READS_SECS) // 60})
    return n


def _note(conn: Conn, host: str, what: str, value):
    from .alerts import get_setting, set_setting
    key = f'{SETTINGS_KEY}.state:{host}'
    state = get_setting(conn, key) or {}
    state[what] = value
    set_setting(conn, key, state, 'agent')


def state(conn: Conn, host: str) -> dict:
    from .alerts import get_setting
    return get_setting(conn, f'{SETTINGS_KEY}.state:{host}') or {}


def take_watching(conn: Conn, host: str, body: dict, at: int) -> int:
    def listed(key):
        return [{k: str(x.get(k) or '')[:300] for k in ('target', 'fstype', 'how', 'why')} for x in (body.get(key) or [])[:256] if isinstance(x, dict)] if isinstance(body.get(key), list) else []
    _note(conn, host, 'watching', {'at': at, 'filesystems': listed('filesystems'), 'refused': listed('refused'), 'error': str(body.get('error') or '')[:300] or None})
    return 1


def after_scan(conn: Conn, host: str, scan_id: int) -> dict:
    """The file index from both. Called when a scan of a host whose agent runs the files plugin has finished: the changes that scan
    found are set against what the agent reported since the scan before it began."""
    rows = conn.all('SELECT started_at FROM scans WHERE scan_id = :s', {'s': scan_id})
    if not rows or not state(conn, host).get('watching'):
        return {'unreported': 0, 'contradicted': 0}
    started = _epoch(rows[0][0])
    prev = conn.all("""SELECT s.started_at FROM scans s JOIN hosts h ON h.host_id = s.host_id WHERE h.hostname = :h AND s.scan_id < :s
                       ORDER BY s.scan_id DESC LIMIT 1""", {'h': host, 's': scan_id})
    since = _epoch(prev[0][0]) if prev else started - 86400
    watched_since = state(conn, host)['watching'].get('at') or started
    since = max(since, watched_since)
    reported = {p for (p,) in conn.all('SELECT DISTINCT path FROM agent_file_events WHERE host = :h AND at >= :a AND at < :b AND action IN (' + ', '.join(f"'{a}'" for a in ACTIONS) + ')',
                                       {'h': host, 'a': since, 'b': started})}
    changed = conn.all("""SELECT c.change_type, c.parent_path, c.filename, m.mount_point FROM file_changes c JOIN mounts m ON m.mount_id = c.mount_id
                          WHERE c.scan_id = :s AND c.is_directory = :f LIMIT 5000""", {'s': scan_id, 'f': False if conn.dialect != 'sqlite' else 0})
    unreported, contradicted = [], []
    for kind, parent, name, _mp in changed:
        path = posixpath.join(parent, name)
        if path in reported:
            # the agent said this changed and put what it read in the index; the scan found it otherwise
            contradicted.append(path)
        else:
            unreported.append(path)
    for path in contradicted[:200]:
        conn.execute("UPDATE agent_file_events SET checked = 'contradicted by a scan' WHERE host = :h AND path = :p AND at >= :a AND at < :b",
                     {'h': host, 'p': path, 'a': since, 'b': started})
    for path in unreported[:200]:
        conn.execute("""INSERT INTO agent_file_events (host, at, received_at, path, action, managed, indexed, checked)
                        VALUES (:h, :t, :t, :p, 'unreported', 0, 'from a scan', 'found by a scan, never reported by the agent')""",
                     {'h': host, 't': started, 'p': path})
    result = {'unreported': len(unreported), 'contradicted': len(contradicted), 'scan_id': scan_id, 'at': started,
              'examples': (unreported[:3] + contradicted[:3])}
    _note(conn, host, 'compared', result)
    return result


def _epoch(value) -> int:
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, dt.datetime):
        return int(value.timestamp())
    try:
        return int(dt.datetime.fromisoformat(str(value)).timestamp())
    except ValueError:
        return int(time.time())


def recent(conn: Conn, host: str, limit: int = 100) -> list[dict]:
    keys = ('id', 'at', 'path', 'action', 'pid', 'process', 'uid', 'user', 'hand_edit', 'indexed', 'checked')
    rows = conn.all("""SELECT event_id, at, path, action, pid, process, uid, user_name, managed, indexed, checked FROM agent_file_events
                       WHERE host = :h ORDER BY event_id DESC LIMIT :n""", {'h': host, 'n': max(1, min(int(limit), 1000))})
    return [dict(zip(keys, r)) | {'hand_edit': bool(r[8]), 'label': LABEL if r[3] != 'unreported' else 'measured by scan'} for r in rows]


def offhours(when: int, cfg: dict) -> bool:
    t = time.localtime(when)
    return t.tm_wday not in cfg['work_days'] or not (cfg['work_start'] <= t.tm_hour < cfg['work_end'])


def ransomware_signs(conn: Conn, host: str, now: float | None = None) -> list[dict]:
    """Detect high-rate file write/rename/delete bursts in agent_file_events over the last hour."""
    now = int(now or time.time())
    cfg = settings(conn)
    limit = int(cfg.get('ransomware_burst_per_minute') or 40)
    rows = conn.all("""SELECT (at / 60) AS bucket, max(process), max(user_name), count(*), max(at)
                       FROM agent_file_events
                       WHERE host = :h AND at >= :s AND action IN ('write', 'delete', 'moved_from', 'moved_to')
                       GROUP BY (at / 60), COALESCE(process, '')
                       HAVING count(*) >= :lim
                       ORDER BY count(*) DESC LIMIT 5""",
                    {'h': host, 's': now - 3600, 'lim': limit})
    return [{'host': host, 'minute': int(b), 'process': proc or 'unknown', 'user': user or 'unknown', 'count': int(cnt), 'at': int(at)}
            for b, proc, user, cnt, at in rows]


def problems(conn: Conn, now: float | None = None) -> dict:
    now = int(now or time.time())
    out = {}
    running = [h for (h,) in conn.all("SELECT host FROM agents WHERE enabled = 1 AND state = 'running'")]
    cfg = settings(conn)
    for host in running:
        bursts = ransomware_signs(conn, host, now)
        if bursts:
            top = bursts[0]
            out[f'agent-files-ransomware:{host}'] = (
                'security-ransomware', host, f'High-rate file modification burst on {host}',
                f'{LABEL}: {top["process"]} ({top["user"]}) modified or renamed {top["count"]} files in one minute', 'crit'
            )
        last_seen = _last_settled(conn, host)
        for path, at, process, user, uid in conn.all("""SELECT path, max(at), max(process), max(user_name), max(uid) FROM agent_file_events
                                                        WHERE host = :h AND managed = 1 AND at > :s GROUP BY path""", {'h': host, 's': last_seen}):
            who = f'{process or "a process"} as {user or (f"uid {uid}" if uid is not None else "an account it could not tell")}'
            out[f'agent-hand-edit:{host}:{path}'] = ('drift', host, f'{path} on {host} was edited by hand',
                                                     f'{LABEL}: changed by {who} at {time.strftime("%Y-%m-%d %H:%M", time.localtime(at))}, while no deploy of the host ran. '
                                                     'Scan the host to keep this version in its configuration history, or deploy again to put the managed one back', 'warn')
        hour = (now // 3600) * 3600
        for uid, user, reads in conn.all("""SELECT uid, max(user_name), sum(reads) FROM agent_file_reads WHERE host = :h AND minute >= :m GROUP BY uid""",
                                         {'h': host, 'm': (now - 3600) // 60}):
            if reads and int(reads) > cfg['offhours_reads_per_hour'] and offhours(hour, cfg):
                name = user or (f'uid {uid}' if uid is not None and uid >= 0 else 'an account it could not tell')
                out[f'agent-offhours:{host}:{name}'] = ('agent-offhours', host, f'{name} read {int(reads)} files on {host} out of working hours',
                                                        f'{LABEL}: in the last hour, more than {cfg["offhours_reads_per_hour"]}. Working hours are {cfg["work_start"]}:00 to {cfg["work_end"]}:00', 'warn')
        s = state(conn, host)
        cmp_ = s.get('compared') or {}
        if (cmp_.get('unreported') or cmp_.get('contradicted')) and now - (cmp_.get('at') or 0) < RECENT_SECS * 7:
            out[f'agent-files-disagree:{host}'] = ('agent-files-disagree', host, f'The agent and the scan disagree about the files on {host}',
                                                   f'the scan found {cmp_.get("unreported", 0)} change(s) the agent never reported, and contradicted {cmp_.get("contradicted", 0)} it did'
                                                   + (f'; for example {", ".join(cmp_.get("examples") or [])[:300]}' if cmp_.get('examples') else ''), 'warn')
        w, d = s.get('watching') or {}, s.get('dropped') or {}
        if w.get('refused') or w.get('error') or (d and now - (d.get('at') or 0) < RECENT_SECS):
            why = w.get('error') or '; '.join(f'{r["target"]}: {r["why"]}' for r in (w.get('refused') or [])[:3])
            if d and now - (d.get('at') or 0) < RECENT_SECS:
                why = (why + '; ' if why else '') + f'{d.get("overflow", 0)} queue overflow(s) and {d.get("left_out", 0)} change(s) left out in the last day'
            out[f'agent-files-blind:{host}'] = ('agent-files-blind', host, f'The files plugin on {host} does not see everything', f'{LABEL}: {why[:500]}', 'info')
    return out


def _last_settled(conn: Conn, host: str) -> int:
    """When the host's files were last taken in by a person's own tool: the last scan finished, or the last deploy run finished."""
    scan = conn.scalar("""SELECT max(s.finished_at) FROM scans s JOIN hosts h ON h.host_id = s.host_id WHERE h.hostname = :h AND s.status <> 'failed'""", {'h': host})
    deploy = conn.scalar("SELECT max(finished_at) FROM deploy_runs WHERE host = :h AND status = 'ok'", {'h': host})
    return max(_epoch(scan) if scan else 0, int(deploy or 0))
