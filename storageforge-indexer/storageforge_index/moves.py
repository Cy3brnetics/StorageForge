"""Data move plans: rsync steps between folders on scanned hosts, checked against the index, run by a generated script.

A plan is a list of steps. Each step takes one folder (src host + path) to another (dst host + path) with a method:

  copy       rsync the folder across; the source is left alone
  move       copy, then --verify, then --cutover renames the source to <name>.migrated-<date> (never deletes) and,
             on the same host, leaves a symlink at the old path so nothing that used it breaks
  mirror     a copy that keeps running: --install writes a systemd timer (optionally with --delete-after)
  rsnapshot  rotating hard-linked snapshots of the source under dst: --install writes an rsnapshot config and timers
  git        a bare archive copy of a repository (git clone --mirror), refreshed by --run and, after --install,
             on a timer; every branch and tag, nothing deleted from the archive unless the source deleted it

StorageForge never moves data itself. check() answers what it can from the index without touching any host (sizes,
free space on the destination mount, unmounted planned mounts, unreadable folders, files already there, loops) and
script() writes a Bash script in the style of storage-setup.sh: read-only report by default, explicit modes for
everything that changes a disk, only-adds, resumable, runnable here or on another machine with --host.
"""
from __future__ import annotations

import datetime as dt
import json
import ipaddress
import posixpath
import re
import shlex
import time

from .db import Conn
from .scriptkit import HELPERS, REMOTE, comments, host_name, one_line, package_check

METHODS = ('copy', 'move', 'mirror', 'rsnapshot', 'git')
SCHEDULES = ('hourly', 'daily', 'weekly', 'monthly')
LOCAL_MBPS, NET_MBPS = 400, 110            # rough MB/s for the time estimate: disk to disk, and gigabit
PATH_RE = re.compile(r'/[^\0\n]*')
LOGIN_RE = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}@[A-Za-z0-9_.:\[\]%-]{1,253}')
EXCLUDE_RE = re.compile(r'[^\0\n]{1,400}')
CALENDAR_RE = re.compile(r'[A-Za-z0-9*][A-Za-z0-9*,./:~ -]{0,79}')      # systemd OnCalendar; checked again on the host
WINDOW_RE = re.compile(r'([01]\d|2[0-3]):[0-5]\d-([01]\d|2[0-3]):[0-5]\d')
ROUTE_VIAS = ('lan', 'mesh')
ADDRESS_RE = re.compile(r'[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?')
IFACE_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,14}')     # what the kernel allows: tailscale0, ztabcdef12, wt0
TRANSPORTS = ('rsync', 'btrfs', 'zfs')
HASHES = ('sha256', 'blake3')


def slug(text: str) -> str:
    return re.sub(r'[^a-z0-9_-]+', '-', text.lower()).strip('-') or 'plan'


def host_slug(name: str) -> str:            # same rule as storage-setup.sh: short hostname, lowercase
    s = re.sub(r'[^a-z0-9_-]', '', (name or '').split('.')[0].lower())
    return s or 'unknown'


def _path(p, what) -> str:
    p = str(p or '').strip()
    if not PATH_RE.fullmatch(p) or '/../' in p + '/' or '/./' in p + '/':
        raise ValueError(f'{what} must be an absolute path without .. or line breaks')
    return posixpath.normpath(p)


# The Moves form writes these to stop containers around a copy: a fixed verb and a checked name, so they are not raw commands
PLAIN_HOOK = re.compile(r'docker compose -p [A-Za-z0-9][A-Za-z0-9_.-]* (stop|start)')


def has_raw_hooks(plan: dict) -> bool:
    """Pre or post commands other than those: they run as root on a host, so they take hosts.command."""
    return any(not PLAIN_HOOK.fullmatch(c) for s in plan.get('steps') or [] for o in (s.get('options') or {}, s)
               for k in ('pre', 'post') for c in o.get(k) or [])


def _only(names, i: int, method: str) -> list[str]:
    """A copy step can take chosen files from directly in its source folder instead of all of it."""
    names = [str(n) for n in names or []]
    if not names:
        return []
    if method != 'copy':
        raise ValueError(f'step {i}: only a copy can take chosen files')
    if len(names) > 1000 or any(not n or n in ('.', '..') or len(n) > 255 or '/' in n or '\n' in n or '\0' in n for n in names):
        raise ValueError(f'step {i}: chosen files must be up to 1000 plain file names')
    return sorted(set(names))


def only_filters(names: list[str]) -> list[str]:
    """rsync arguments that send just these names. rsync reads a backslash as an escape only in a pattern that has
    wildcards, so a name is escaped only if it has some: they must match themselves."""
    if not names:
        return []
    literal = (re.sub(r'([*?[\\])', r'\\\1', n) if re.search(r'[*?[]', n) else n for n in names)
    return [*(f'--include=/{n}' for n in literal), '--exclude=*']


def _route(r, i: int) -> dict:
    via, addr, iface = str(r.get('via') or ''), str(r.get('address') or '').strip(), str(r.get('iface') or '').strip()
    if via not in ROUTE_VIAS:
        raise ValueError(f'step {i}: a route is {" or ".join(ROUTE_VIAS)}')
    try:
        ipaddress.ip_address(addr)
    except ValueError:
        if not ADDRESS_RE.fullmatch(addr):
            raise ValueError(f'step {i}: route address must be a hostname or IP address') from None
    if iface and not IFACE_RE.fullmatch(iface):
        raise ValueError(f'step {i}: route interface must be an interface name such as tailscale0')
    return {'via': via, 'address': addr, 'iface': iface or None}


def _whole(value, what: str, i: int, low: int, high: int) -> int:
    try:
        return max(low, min(int(value), high))
    except (TypeError, ValueError):
        raise ValueError(f'step {i}: {what} must be a whole number') from None


def _engine(o: dict, i: int, method: str, excludes: list, snapshot: bool) -> dict:
    """The sync engine's options, for deployed jobs. Only what is switched on is kept: a plan that uses none of them
    fingerprints as it did before they existed, so deployed plans do not all turn up as changed."""
    out = {}
    routes = [_route(r, i) for r in o.get('routes') or []]
    if len(routes) > 4:
        raise ValueError(f'step {i}: up to 4 routes')
    if routes:
        out['routes'] = routes
    transport = o.get('transport') or 'rsync'
    if transport not in TRANSPORTS:
        raise ValueError(f'step {i}: transport must be one of {", ".join(TRANSPORTS)}')
    if transport != 'rsync':
        if method != 'mirror':
            raise ValueError(f'step {i}: only mirror steps can use {transport} snapshot streams')
        if excludes or snapshot or o.get('dedup'):
            raise ValueError(f'step {i}: a snapshot stream sends the whole subvolume or dataset: it takes no excludes, '
                             'snapshot-first or file dedup')
        out['transport'] = transport
    if o.get('dedup'):
        if method not in ('copy', 'move', 'mirror'):
            raise ValueError(f'step {i}: file dedup is for copy, move and mirror (rsnapshot already links, git packs)')
        algo = o.get('hash') or 'sha256'
        if algo not in HASHES:
            raise ValueError(f'step {i}: hash must be one of {", ".join(HASHES)}')
        out.update(dedup=True, hash=algo, dedup_hardlink=bool(o.get('dedup_hardlink')),
                   dedup_min_kb=_whole(o.get('dedup_min_kb') or 1024, 'the smallest file to dedup', i, 1, 1 << 30))
    if o.get('preflight'):
        out.update(preflight=True, reserve_gb=_whole(o.get('reserve_gb') if o.get('reserve_gb') not in (None, '') else 1, 'the space to keep free', i, 0, 100_000))
    if o.get('extent_dedup'):
        if o['extent_dedup'] not in ('weekly', 'monthly'):
            raise ValueError(f'step {i}: extent dedup runs weekly or monthly')
        if method == 'git' or transport != 'rsync':
            raise ValueError(f'step {i}: extent dedup needs writable files: not git archives or snapshot streams')
        out['extent_dedup'] = o['extent_dedup']
    return out


def normalize(body: dict) -> dict:
    """Validate a plan from the UI or CLI and fill defaults. Raises ValueError with a readable reason."""
    name = str(body.get('name') or '').strip()
    if not name or len(name) > 80 or '\n' in name:
        raise ValueError('give the plan a name (up to 80 characters)')
    steps = []
    for i, s in enumerate(body.get('steps') or [], 1):
        method = s.get('method') or 'copy'
        if method not in METHODS:
            raise ValueError(f'step {i}: method must be one of {", ".join(METHODS)}')
        src, dst = s.get('src') or {}, s.get('dst') or {}
        if not src.get('host') or not dst.get('host'):
            raise ValueError(f'step {i}: pick a source and a destination host')
        src_host, dst_host = host_name(src['host'], f'step {i}: the source host'), host_name(dst['host'], f'step {i}: the destination host')
        o = s.get('options') or {}
        login = str(o.get('src_login') or '').strip()
        if login and not LOGIN_RE.fullmatch(login):
            raise ValueError(f'step {i}: source login must look like user@host')
        excludes = [str(x).strip() for x in s.get('excludes') or [] if str(x).strip()]
        if any(not EXCLUDE_RE.fullmatch(x) for x in excludes):
            raise ValueError(f'step {i}: exclude patterns cannot contain line breaks')
        keep = {k: max(0, min(int((o.get('keep') or {}).get(k, d)), 999))
                for k, d in (('hourly', 0), ('daily', 7), ('weekly', 4), ('monthly', 6))}
        bw, bwn = o.get('bwlimit'), o.get('bwlimit_night')
        schedule = str(o.get('schedule') or 'daily').strip()
        if schedule not in SCHEDULES and not CALENDAR_RE.fullmatch(schedule):
            raise ValueError(f'step {i}: schedule must be hourly, daily, weekly, monthly or a systemd calendar time '
                             f'such as "*-*-* 02:30" or "Sun 03:00"')
        windows = {}
        for k in ('window', 'night'):
            w = str(o.get(k) or '').replace(' ', '')
            if w and not WINDOW_RE.fullmatch(w):
                raise ValueError(f'step {i}: {k} must look like 01:00-06:00')
            windows[k] = w or None
        hooks = {}
        for k in ('pre', 'post'):
            cmds = [str(c).strip() for c in o.get(k) or [] if str(c).strip()]
            if len(cmds) > 10 or any(len(c) > 500 or '\n' in c or '\0' in c for c in cmds):
                raise ValueError(f'step {i}: up to 10 {k} commands, one line each')
            hooks[k] = cmds
        only = _only(s.get('only'), i, method)
        steps.append({
            'id': str(s.get('id') or f's{i}'), 'method': method, 'note': one_line(s.get('note') or '')[:300],
            'src': {'host': src_host, 'path': _path(src.get('path'), f'step {i} source')},
            'dst': {'host': dst_host, 'path': _path(dst.get('path'), f'step {i} destination')},
            'excludes': excludes,
            **({'only': only} if only else {}),
            'options': {'checksum': bool(o.get('checksum')), 'delete': bool(o.get('delete')) and method == 'mirror',
                        'remote_sudo': o.get('remote_sudo', True) is not False, 'one_fs': o.get('one_fs', True) is not False,
                        'link_back': o.get('link_back', True) is not False and method == 'move',
                        'bwlimit': int(bw) if bw not in (None, '', 0, '0') else None, 'src_login': login or None,
                        'schedule': schedule, 'keep': keep,
                        # deployed jobs only (the downloadable script ignores these)
                        'bwlimit_night': int(bwn) if bwn not in (None, '', 0, '0') else None,
                        'window': windows['window'], 'night': windows['night'] or ('22:00-07:00' if bwn else None),
                        'pre': hooks['pre'], 'post': hooks['post'], 'snapshot': bool(o.get('snapshot')),
                        'verify': o.get('verify') if o.get('verify') in ('weekly', 'monthly') else None,
                        **_engine(o, i, method, excludes, bool(o.get('snapshot')))},
        })
    return {'name': name, 'notes': str(body.get('notes') or '')[:2000], 'steps': steps,
            'net_mbps': max(1, min(int(body.get('net_mbps') or NET_MBPS), 100_000))}


# ── what the index knows ───────────────────────────────────────────────
def hosts(conn: Conn) -> dict:
    out = {}
    for hid, name, ssh_host, ssh_user, ssh_port, ip in conn.all(
            'SELECT host_id, hostname, ssh_host, ssh_user, ssh_port, ip_address FROM hosts'):
        mounts = [dict(zip(('id', 'target', 'source', 'fstype', 'total', 'used', 'state', 'options'), r)) for r in conn.all(
            """SELECT mount_id, mount_point, source, filesystem_type, total_bytes, used_bytes, scan_state, mount_options FROM mounts
               WHERE host_id = :h AND scan_state <> 'gone'""", {'h': hid})]
        out[name] = {'id': hid, 'name': name, 'ssh_host': ssh_host or ip or name, 'ssh_user': ssh_user,
                     'ssh_port': ssh_port or 22, 'mounts': mounts}
    return out


def find_host(hs: dict, name: str):
    n = (name or '').lower()
    return next((h for k, h in hs.items() if k.lower() == n or host_slug(k) == host_slug(n)
                 or (h['ssh_host'] or '').lower() == n), None)


def _under(path: str, root: str) -> bool:
    return root == '/' or path == root or path.startswith(root.rstrip('/') + '/')


def mount_of(host: dict, path: str):
    ms = [m for m in host['mounts'] if m['state'] in ('indexed', 'skipped') and _under(path, m['target'])]
    return max(ms, key=lambda m: len(m['target']), default=None)


def _subtree_sql(path: str, mount_target: str) -> tuple[str, dict]:
    if path == mount_target:
        return 'f.mount_id = :m', {}
    return ('f.dir_id IN (SELECT dir_id FROM directories WHERE mount_id = :m AND (path = :p OR (path >= :lo AND path < :hi)))',
            {'p': path, 'lo': path + '/', 'hi': path + '0'})          # '0' sorts right after '/'


def subtree(conn: Conn, mount: dict, path: str) -> dict:
    where, p = _subtree_sql(path, mount['target'])
    n, size, files = conn.all(f"""SELECT count(*), coalesce(sum(f.file_size_bytes), 0), coalesce(sum(CASE WHEN f.is_directory THEN 0 ELSE 1 END), 0)
                                  FROM file_records f WHERE {where}""", {'m': mount['id'], **p})[0]
    return {'entries': n, 'bytes': size, 'files': files}


def browse(conn: Conn, host_name: str, path: str = '/') -> dict:
    """Subfolders of path on a host, with indexed sizes: one pass over the subtree, rolled up to the first level."""
    hs = hosts(conn)
    h = find_host(hs, host_name)
    if not h:
        raise ValueError(f'{host_name} has not been scanned')
    path = _path(path or '/', 'path')
    m = mount_of(h, path)
    children: dict[str, dict] = {}
    if m and m['state'] == 'indexed':
        where, p = _subtree_sql(path, m['target'])
        base = path.rstrip('/') + '/'
        for parent, size, n in conn.all(f"""SELECT d.path, coalesce(sum(f.file_size_bytes), 0), count(*)
                                            FROM file_records f JOIN directories d ON d.dir_id = f.dir_id WHERE {where} GROUP BY d.path""", {'m': m['id'], **p}):
            if parent == path or not parent.startswith(base):
                continue
            first = parent[len(base):].split('/', 1)[0]
            c = children.setdefault(first, {'name': first, 'bytes': 0, 'entries': 0})
            c['bytes'] += size
            c['entries'] += n
        for (name,) in conn.all("""SELECT f.filename FROM file_records f JOIN directories d ON d.dir_id = f.dir_id
                                   WHERE d.mount_id = :m AND d.path = :p AND f.is_directory""", {'m': m['id'], 'p': path}):
            children.setdefault(name, {'name': name, 'bytes': 0, 'entries': 0})
    for mm in h['mounts']:                                  # mounts directly below: their own filesystems
        rel = mm['target'][len(path.rstrip('/')) + 1:] if _under(mm['target'], path) and mm['target'] != path else ''
        if rel and '/' not in rel and mm['state'] != 'gone':
            children[rel] = {'name': rel, 'bytes': mm['used'] or 0, 'entries': None, 'mount': mm['fstype']}
    here = subtree(conn, m, path) if m and m['state'] == 'indexed' else None
    return {'host': h['name'], 'path': path, 'mount': m and m['target'], 'indexed': bool(m and m['state'] == 'indexed'),
            'size': here, 'dirs': sorted(children.values(), key=lambda c: c['name'].lower())}


def _planned_mounts(conn: Conn, host: str) -> list[str]:
    from .graph import stored_blueprint
    from .payloads import node_from_blueprint
    bp = stored_blueprint(conn, host)
    return [m['target'] for m in node_from_blueprint(bp)['mounts'] if str(m.get('target', '')).startswith('/')] if bp else []


def _relset(conn: Conn, mount: dict, path: str, limit: int):
    where, p = _subtree_sql(path, mount['target'])
    rows = conn.execute(f"""SELECT d.path, f.filename, f.file_size_bytes FROM file_records f JOIN directories d ON d.dir_id = f.dir_id
                            WHERE {where} AND NOT f.is_directory LIMIT :lim""", {'m': mount['id'], **p, 'lim': limit + 1}).fetchall()
    if len(rows) > limit:
        return None
    cut = len(path.rstrip('/'))
    return {(posixpath.join(par, fn)[cut:], size) for par, fn, size in rows}


def check(conn: Conn, plan: dict, compare_limit: int = 300_000) -> dict:
    """Everything the index can say about a plan before anything runs. Levels: ok, note, warn, crit."""
    hs = hosts(conn)
    out, space = [], {}
    moved_away: list[tuple[str, str]] = []
    for i, s in enumerate(plan['steps'], 1):
        items, info = [], {'step': i, 'id': s['id']}
        say = lambda level, text: items.append({'level': level, 'text': text})   # noqa: E731
        sh, dh = find_host(hs, s['src']['host']), find_host(hs, s['dst']['host'])
        src, dst = s['src']['path'], s['dst']['path']
        if not sh:
            say('crit', f'source host {s["src"]["host"]} has not been scanned')
        if not dh:
            say('crit', f'destination host {s["dst"]["host"]} has not been scanned')
        if not (sh and dh):
            out.append({**info, 'items': items})
            continue
        same_host = sh['id'] == dh['id']
        info.update(runner=dh['name'], same_host=same_host)
        if s['method'] != 'git':
            say(*package_check(conn, dh, 'rsync'))
            if not same_host:
                say(*package_check(conn, sh, 'rsync'))
            if s['method'] == 'rsnapshot':
                say(*package_check(conn, dh, 'rsnapshot'))
        else:
            say(*package_check(conn, dh, 'git'))
            if not same_host:
                say(*package_check(conn, sh, 'git'))
        o = s['options']
        if o.get('dedup'):
            say(*package_check(conn, dh, 'python3'))
            if not same_host:
                say(*package_check(conn, sh, 'python3'))
        if o.get('extent_dedup'):
            say(*package_check(conn, dh, 'duperemove'))
        if not same_host and not o.get('routes') and (sh['ssh_host'] or '').startswith('127.77.'):
            say('crit', f'{sh["name"]} is a remote node, reachable only from StorageForge through its tunnel, so {dh["name"]} '
                        'cannot pull from it: add a route, such as a mesh address')
        if o.get('routes') and same_host:
            say('note', 'source and destination are the same host: the routes are not used')
        if o.get('transport') == 'btrfs':
            say(*package_check(conn, dh, 'btrfs-progs'))
        if o.get('transport'):
            for side, h0, p0 in (('source', sh, src), ('destination', dh, dst)):
                fs = (mount_of(h0, p0) or {}).get('fstype')
                if fs and fs != o['transport']:
                    say('crit', f'the {side} {p0} is on {fs}: a {o["transport"]} stream needs {o["transport"]} on both sides')
            say('note', f'{src} must be the root of its own {"subvolume" if o["transport"] == "btrfs" else "dataset"}: '
                        'only a whole one can be sent, and the run refuses anything else')
        if same_host and (_under(dst, src) or _under(src, dst)):
            say('crit', 'source and destination overlap: one is inside the other, so rsync would copy into itself')
        for h0, p0 in moved_away:
            if h0 == sh['name'] and _under(src, p0):
                say('warn', f'an earlier move step renames {p0} at cutover; run this step before that cutover')
        sm = mount_of(sh, src)
        size = None
        if s['method'] == 'git':
            repo = conn.all('SELECT bare, branch, head_subject, refs, size_kb FROM git_repos WHERE host_id = :h AND path = :p',
                            {'h': sh['id'], 'p': src})
            if not repo:
                say('warn', f'{src} is not a git repository the last scan of {sh["name"]} found')
            else:
                bare, branch, subject, refs, kb = repo[0]
                size = {'bytes': (kb or 0) * 1024, 'files': refs or 0, 'entries': refs or 0}
                info['src'] = {'mount': sm and sm['target'], 'fstype': sm and sm['fstype'], **size}
                say('ok', f'{"bare " if bare else ""}repository · {branch or "detached"} · {refs or 0} branches and tags · '
                          f'{_fmt(size["bytes"])}' + (f' · last: {subject}' if subject else ''))
            if not dst.endswith('.git'):
                say('note', 'bare archives are usually named <name>.git')
            sm = None
        elif not sm:
            say('warn', f'{src} is not on a scanned mount of {sh["name"]}; size unknown')
        elif sm['state'] != 'indexed':
            say('warn', f'{sm["target"]} on {sh["name"]} was not indexed (skipped); size unknown')
        else:
            size = subtree(conn, sm, src)
            if s.get('only'):                 # just the chosen files, which must be directly in the folder
                rows = conn.all('''SELECT f.filename, f.file_size_bytes FROM file_records f JOIN directories d ON d.dir_id = f.dir_id
                                   WHERE d.mount_id = :m AND d.path = :p AND NOT f.is_directory''', {'m': sm['id'], 'p': src})
                have = {n: b or 0 for n, b in rows if n in set(s['only'])}
                gone = [n for n in s['only'] if n not in have]
                if gone:
                    say('warn', f'not in the index under {src}: {", ".join(gone[:5])}' + (f' and {len(gone) - 5} more' if len(gone) > 5 else ''))
                size = {'entries': len(have), 'files': len(have), 'bytes': sum(have.values())}
            info['src'] = {'mount': sm['target'], 'fstype': sm['fstype'], **size}
            if not size['entries']:
                say('warn', f'{src} is not in the index: it may not exist, or the last scan could not read it')
            else:
                say('ok', f'{size["files"]:,} files, {_fmt(size["bytes"])} to transfer')
            nested = [m['target'] for m in sh['mounts'] if m['target'] != sm['target'] and _under(m['target'], src)
                      and m['state'] != 'gone']
            if nested:
                say('note', 'other filesystems mounted inside the source are left out (one filesystem only): '
                            + ', '.join(nested[:5]) + (' …' if len(nested) > 5 else '') if s['options']['one_fs']
                    else 'mounts inside the source are included: ' + ', '.join(nested[:5]))
            denied = conn.scalar("""SELECT count(*) FROM scan_denied d WHERE d.scan_id = (SELECT max(scan_id) FROM scans
                                    WHERE host_id = :h AND status <> 'running') AND (d.path = :p OR d.path LIKE :like)""",
                                 {'h': sh['id'], 'p': src, 'like': src.rstrip('/') + '/%'})
            if denied:
                say('warn', f'{denied} folder(s) inside the source were unreadable to the scan user; the copy needs root '
                            f'on {sh["name"]}' + ('' if same_host else ' (keep "sudo rsync on the source" on)'))
        dm = mount_of(dh, dst)
        planned = [t for t in _planned_mounts(conn, dh['name']) if _under(dst, t)]
        planned_mp = max(planned, key=len, default=None)
        info['dst'] = {'mount': dm and dm['target'], 'planned_mount': None}
        if planned_mp and (not dm or len(planned_mp) > len(dm['target'])):
            info['dst']['planned_mount'] = planned_mp
            say('warn', f'{planned_mp} is a planned mount that is not mounted yet: set it up first (planner script or '
                        f'storage-setup.sh --setup); the script refuses to write to {dm["target"] if dm else "/"} instead')
        elif dm:
            free = (dm['total'] or 0) - (dm['used'] or 0) if dm['total'] else None
            info['dst'].update(fstype=dm['fstype'], free=free)
            if s['method'] == 'rsnapshot' and dm['fstype'] in ('vfat', 'msdos', 'exfat', 'fuse.exfat', 'cifs', 'smb3'):
                say('crit', f'{dst} is on {dm["fstype"]}, which has no hard links: each rsnapshot snapshot would be a full copy. Use ext4 or xfs there, or a mirror step.')
            elif s['method'] == 'rsnapshot' and same_host and dm['fstype'] == 'btrfs' and mount_of(sh, src) == dm:
                say('note', 'source and destination share one btrfs volume: snapper is instant and takes less room (Deploy > New snapshot job).')
            if dm['target'] == '/' and dst.startswith(('/mnt/', '/media/', '/srv/')):
                say('warn', f'{dst} is on the root filesystem of {dh["name"]}. If a disk should be mounted there, '
                            'mount it first')
            if size and s['method'] != 'rsnapshot':
                key = (dh['name'], dm['target'])
                space.setdefault(key, {'host': dh['name'], 'mount': dm['target'], 'free': free, 'need': 0, 'steps': []})
                space[key]['need'] += size['bytes']
                space[key]['steps'].append(i)
            if sm and same_host and dm['target'] == sm['target'] and s['method'] in ('copy', 'move'):
                if s['method'] == 'move':
                    say('note', 'same filesystem: rsync copies every byte, where a plain mv would be instant')
                elif dm['fstype'] in ('btrfs', 'xfs'):
                    say('note', f'same {dm["fstype"]} filesystem: rsync copies every byte, where '
                                'cp -a --reflink=always would share the data instantly')
            if size and sm and dm['state'] == 'indexed' and size['files']:
                there = subtree(conn, dm, dst)
                if there['files']:
                    a, b = (None, None) if s.get('only') else (_relset(conn, sm, src, compare_limit), _relset(conn, dm, dst, compare_limit))
                    if a is not None and b is not None:
                        same = a & b
                        say('note', f'{len(same):,} of the files are already at the destination with the same size; '
                                    f'rsync skips those' if same else
                            f'the destination already holds {there["files"]:,} other files; they are kept'
                            + (' (mirror with --delete would remove them)' if s['options']['delete'] else ''))
                        info['already_there'] = len(same)
        else:
            say('crit', f'{dst} is not under any mount of {dh["name"]}')
        if size:
            mbps = LOCAL_MBPS if same_host else min(plan.get('net_mbps') or NET_MBPS, (s['options']['bwlimit'] or 1e12) / 1000)
            info['eta_s'] = int(size['bytes'] / (mbps * 1e6)) + size['files'] // 2000
        if not same_host:
            login = s['options']['src_login'] or f'{sh["ssh_user"] or "root"}@{sh["ssh_host"]}'
            info['src_login'] = login
            say('note', f'runs on {dh["name"]} and pulls from {login} over SSH'
                        + (' (git reads the repository as that user)' if s['method'] == 'git'
                           else ' with sudo rsync there' if s['options']['remote_sudo'] else ''))
        from .docker import users_of
        for side, h0, p0 in (('source', sh, src), ('destination', dh, dst)):
            users = [u for u in users_of(conn, h0['name'], p0) if u['state'] == 'running']
            if users:
                names = sorted({u['container'] for u in users})
                stacks = sorted({u['stack'] for u in users if u['stack']})
                say('warn' if s['method'] in ('move', 'copy') else 'note',
                    f'{len(names)} running container(s) use the {side}: {", ".join(names[:6])}{" …" if len(names) > 6 else ""}. '
                    + ('Stop them first (' + ', '.join(f'docker compose -p {x} stop' for x in stacks[:3]) + ')' if stacks
                       else 'Stop them first') + ', or files can change while rsync copies' + (' and the cutover breaks them'
                                                                                               if s['method'] == 'move' and side == 'source' else ''))
        if s['method'] == 'move':
            moved_away.append((sh['name'], src))
        out.append({**info, 'items': items})
    for sp in space.values():
        if sp['free'] is None:
            continue
        if sp['need'] > sp['free'] * 0.95:
            for st in out:
                if st['step'] in sp['steps']:
                    st['items'].append({'level': 'crit', 'text': f'{sp["mount"]} on {sp["host"]} has {_fmt(sp["free"])} free; '
                                        f'step(s) {", ".join(map(str, sp["steps"]))} need {_fmt(sp["need"])}'})
        elif sp['need'] > sp['free'] * 0.8:
            for st in out:
                if st['step'] in sp['steps']:
                    st['items'].append({'level': 'warn', 'text': f'{sp["mount"]} on {sp["host"]} will be over 80% full'})
    levels = [it['level'] for st in out for it in st['items']]
    return {'steps': out, 'space': list(space.values()), 'crit': levels.count('crit'), 'warn': levels.count('warn'),
            'bytes': sum((st.get('src') or {}).get('bytes', 0) for st in out),
            'eta_s': sum(st.get('eta_s', 0) for st in out)}


def _fmt(n) -> str:
    n = float(n or 0)
    for u in ('B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB'):
        if n < 1024 or u == 'PiB':
            return f'{n:.0f} {u}' if u == 'B' else f'{n:.1f} {u}'
        n /= 1024


# ── storage ────────────────────────────────────────────────────────────
def _deployed_at(marks: list[dict], plan_id: int, body: dict) -> int | None:
    """When the plan, as it is now, was last deployed as jobs on all its hosts. An edit waits for the next deploy."""
    from . import deploy, jobs
    if not body.get('steps'):
        return None
    try:
        return deploy.finished_at(marks, f'p{plan_id}', jobs.plan_hash(body))
    except ValueError:             # saved under older rules: it can't be the version that was deployed
        return None


def list_plans(conn: Conn) -> list[dict]:
    from . import deploy
    marks, out = deploy.deployed(conn, kind='jobs'), []
    for r in conn.all('SELECT plan_id, name, body_json, updated_at, updated_by FROM move_plans ORDER BY name'):
        body = json.loads(r[2])
        out.append({'id': r[0], 'name': r[1], 'steps': len(body.get('steps') or []), 'updated_at': r[3], 'updated_by': r[4],
                    'deployed_at': _deployed_at(marks, r[0], body)})
    return out


def get_plan(conn: Conn, plan_id: int) -> dict:
    from . import deploy
    rows = conn.all('SELECT plan_id, body_json, updated_at FROM move_plans WHERE plan_id = :i', {'i': plan_id})
    if not rows:
        raise LookupError(f'no move plan #{plan_id}')
    body = json.loads(rows[0][1])
    return {'id': rows[0][0], **body, 'updated_at': rows[0][2], 'progress': progress(conn, body),
            'deployed_at': _deployed_at(deploy.deployed(conn, kind='jobs'), rows[0][0], body)}


def progress(conn: Conn, plan: dict) -> list[dict]:
    """Per step, what the script reported on its destination host at the last scan: {copied, cutover}, each a text or None.
    The script keeps these under the plan's name, so renaming a plan starts its progress over."""
    marks: dict[str, dict] = {}
    for name, inv in conn.all('SELECT hostname, inventory_json FROM hosts'):
        inv = inv if isinstance(inv, dict) else json.loads(inv or '{}')
        marks[host_slug(name)] = dict(line.split('\t', 1) for line in (inv.get('moves') or '').splitlines() if '\t' in line)
    plan_dir = slug(plan['name'])
    out = []
    for i, s in enumerate(plan['steps']):
        m = marks.get(host_slug(s['dst']['host']), {})
        out.append({'copied': m.get(f'{plan_dir}/{i}.done'), 'cutover': m.get(f'{plan_dir}/{i}.cutover')})
    return out


def copy_plan(conn: Conn, plan_id: int, actor: str) -> int:
    plan = get_plan(conn, plan_id)
    names = {p['name'].lower() for p in list_plans(conn)}
    name = next(n for n in (f'{plan["name"]} (copy{"" if i == 1 else f" {i}"})' for i in range(1, 10000)) if n.lower() not in names)
    return save_plan(conn, {**plan, 'name': name}, actor)


def save_plan(conn: Conn, body: dict, actor: str, plan_id: int | None = None) -> int:
    plan = normalize(body)
    now = int(time.time())
    clash = conn.scalar('SELECT plan_id FROM move_plans WHERE lower(name) = lower(:n)', {'n': plan['name']})
    if clash and clash != plan_id:
        raise ValueError(f'a plan named "{plan["name"]}" already exists')
    with conn.tx():
        if plan_id:
            if not conn.scalar('SELECT 1 FROM move_plans WHERE plan_id = :i', {'i': plan_id}):
                raise LookupError(f'no move plan #{plan_id}')
            conn.execute('UPDATE move_plans SET name = :n, body_json = :b, updated_at = :t, updated_by = :a WHERE plan_id = :i',
                         {'n': plan['name'], 'b': json.dumps(plan), 't': now, 'a': actor, 'i': plan_id})
            return plan_id
        return conn.scalar("""INSERT INTO move_plans (name, body_json, created_at, updated_at, updated_by)
                              VALUES (:n, :b, :t, :t, :a) RETURNING plan_id""",
                           {'n': plan['name'], 'b': json.dumps(plan), 't': now, 'a': actor})


def delete_plan(conn: Conn, plan_id: int):
    conn.execute('DELETE FROM move_plans WHERE plan_id = :i', {'i': plan_id})


# ── the script ─────────────────────────────────────────────────────────
def script(conn: Conn, plan: dict) -> str:
    plan = normalize(plan)
    hs, chk = hosts(conn), check(conn, plan)
    q = shlex.quote
    arrays = {k: [] for k in ('S_METHOD', 'S_RUNNER', 'S_SRC_HOST', 'S_SRC', 'S_SRC_LOGIN', 'S_SRC_PORT', 'S_DST',
                              'S_DST_MOUNT', 'S_BYTES', 'S_FILES', 'S_EXCLUDES', 'S_ONLY', 'S_FLAGS', 'S_SCHEDULE', 'S_KEEP', 'S_DESC')}
    summary = []
    for s, c in zip(plan['steps'], chk['steps']):
        sh, dh = find_host(hs, s['src']['host']), find_host(hs, s['dst']['host'])
        o = s['options']
        dst_mount = (c.get('dst') or {}).get('planned_mount') or (c.get('dst') or {}).get('mount') or '/'
        flags = ' '.join(f for f, on in (('checksum', o['checksum']), ('delete', o['delete']), ('sudo', o['remote_sudo']),
                                          ('onefs', o['one_fs']), ('link', o['link_back'])) if on)
        if o['bwlimit']:
            flags += f' bwlimit={o["bwlimit"]}'
        vals = {
            'S_METHOD': s['method'], 'S_RUNNER': host_slug(dh['name'] if dh else s['dst']['host']),
            'S_SRC_HOST': host_slug(sh['name'] if sh else s['src']['host']), 'S_SRC': s['src']['path'],
            'S_SRC_LOGIN': c.get('src_login') or o['src_login'] or '', 'S_SRC_PORT': str((sh or {}).get('ssh_port') or 22),
            'S_DST': s['dst']['path'], 'S_DST_MOUNT': dst_mount,
            'S_BYTES': str((c.get('src') or {}).get('bytes') or 0), 'S_FILES': str((c.get('src') or {}).get('files') or 0),
            'S_EXCLUDES': '\n'.join(s['excludes']), 'S_ONLY': '\n'.join(only_filters(s.get('only') or [])), 'S_FLAGS': flags.strip(), 'S_SCHEDULE': o['schedule'],
            'S_KEEP': ' '.join(f'{k}={v}' for k, v in o['keep'].items() if v),
            'S_DESC': f'{s["method"]} {s["src"]["host"]}:{s["src"]["path"]} -> {s["dst"]["host"]}:{s["dst"]["path"]}',
        }
        for k, v in vals.items():
            arrays[k].append(v)
        size = (c.get('src') or {}).get('bytes')
        summary.append(f'#   {len(summary) + 1}. {vals["S_DESC"]}' + (f'  ({_fmt(size)})' if size else '')
                       + (f'  [{s["note"]}]' if s['note'] else ''))
    problems = [f'#   step {st["step"]}: {it["level"].upper()}: {it["text"]}' for st in chk['steps'] for it in st['items']
                if it['level'] in ('crit', 'warn')]
    decl = '\n'.join(f'{k}=({" ".join(q(v) for v in vs)})' for k, vs in arrays.items())
    return (SCRIPT_HEAD.format(name=one_line(plan['name']), slug=slug(plan['name']),
                               date=dt.datetime.now().strftime('%Y-%m-%d %H:%M'), steps=comments(summary, '#   (no steps)'),
                               problems=comments(problems, '#   none'),
                               total=_fmt(chk['bytes']), eta=_eta(chk['eta_s']))
            + f'PLAN={q(slug(plan["name"]))}\nPLAN_NAME={q(plan["name"])}\n{decl}\n' + SCRIPT_BODY)


def _eta(s: int) -> str:
    return f'{s // 3600} h {s % 3600 // 60} min' if s >= 3600 else f'{max(1, s // 60)} min'


SCRIPT_HEAD = r"""#!/usr/bin/env bash
# {slug}.sh — StorageForge move plan "{name}", generated {date}.
#
# Steps ({total} in all, roughly {eta} at the plan's speeds):
{steps}
#
# What StorageForge flagged from the index when this was generated:
{problems}
#
#   ./{slug}.sh                  report: sources, destination mounts, free space, SSH (read-only; also --check)
#   ./{slug}.sh --dry-run        rsync -n: what each step would transfer, nothing written
#   sudo ./{slug}.sh --run       copy (copy, move and mirror steps; resumable, rerun any time)
#   sudo ./{slug}.sh --verify    compare source and destination (add --checksum to read every byte)
#   sudo ./{slug}.sh --cutover   move steps only, after a clean verify: rename the source to
#                                <name>.migrated-<date> and link the old path to the new one (same host)
#   sudo ./{slug}.sh --install   mirror and rsnapshot steps: write systemd timers / rsnapshot configs
#   --step N                     only step N        --host [user@]host   run on that machine instead
#   --forward-agent              with --host: lend that machine your SSH agent (for steps that pull from a third host)
#
# Each step runs on its destination host and pulls from the source (over SSH when it is another host).
# Steps for other hosts are listed and skipped; run the script there, or with --host from here.
# It never deletes: no rsync --delete (except a mirror step you marked so), and cutover renames.
# A destination mount that is not mounted stops the step, so nothing lands on the root filesystem.
set -euo pipefail

"""

SCRIPT_BODY = r"""
N=${#S_METHOD[@]}
MODE=check; ONLY=; HOST=; CHECKSUM=0; ARGS=("$@")
usage() { sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'; }
while (($#)); do
  case $1 in
    --check|--report) MODE=check ;;
    --dry-run) MODE=dryrun ;; --run) MODE=run ;; --verify) MODE=verify ;;
    --cutover) MODE=cutover ;; --install) MODE=install ;;
    --checksum) CHECKSUM=1 ;;
    --step) ONLY=${2:?--step needs a number}; shift ;;
    --host) HOST=${2:?--host needs [user@]host}; shift ;;
    --forward-agent) FWD_AGENT=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1 (try --help)" >&2; exit 2 ;;
  esac
  shift
done

""" + HELPERS + r"""has() { [[ " ${S_FLAGS[$1]} " == *" $2 "* ]]; }
flag_val() { tr ' ' '\n' <<<"${S_FLAGS[$1]}" | sed -n "s/^$2=//p"; }

""" + REMOTE + r"""
ME=$(host_slug "$(uname -n)")
if [[ $MODE =~ ^(run|verify|cutover|install)$ && $EUID -ne 0 ]]; then
  echo "--$MODE needs root (ownership, permissions and every unreadable folder): sudo $0 ${ARGS[*]}" >&2; exit 1
fi
command -v rsync >/dev/null || { echo "rsync is not installed on $(uname -n)" >&2; exit 1; }
if [[ $MODE != check ]]; then
  exec 9>"/run/lock/sf-move-$PLAN.lock" 2>/dev/null || exec 9>"/tmp/sf-move-$PLAN.lock"
  flock -n 9 || { echo "another run of $PLAN_NAME is in progress on this machine" >&2; exit 1; }
fi
if [[ $MODE =~ ^(run|cutover|install)$ ]]; then
  LOG_DIR=/var/log/storageforge; mkdir -p "$LOG_DIR"
  LOG="$LOG_DIR/move-$PLAN-$(date +%Y%m%d-%H%M%S).log"
  exec > >(tee -a "$LOG") 2>&1
  echo "log: $LOG"
fi
STATE=/var/lib/storageforge/moves/$PLAN

src_is_local() { [[ ${S_SRC_HOST[$1]} == "$ME" ]]; }
src_spec() { if src_is_local "$1"; then printf '%s/' "${S_SRC[$1]%/}"; else printf '%s:%s/' "${S_SRC_LOGIN[$1]}" "${S_SRC[$1]%/}"; fi; }
ssh_src() { local i=$1; shift; ssh -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new -p "${S_SRC_PORT[$i]}" "${S_SRC_LOGIN[$i]}" "$@"; }
rsync_args() { # step [extra...] -> RS array
  local i=$1; shift
  RS=(rsync -aHAXS '--filter=-x_system.*' --filter=-x_security.selinux --numeric-ids --protect-args --partial --partial-dir=.rsync-partial --human-readable)
  has "$i" onefs && RS+=(-x)
  { has "$i" checksum || ((CHECKSUM)); } && RS+=(-c)
  has "$i" delete && RS+=(--delete-after)
  local bw; bw=$(flag_val "$i" bwlimit); [[ -n $bw ]] && RS+=(--bwlimit="$bw")
  if ! src_is_local "$i"; then
    RS+=(-e "ssh -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new -p ${S_SRC_PORT[$i]}")
    has "$i" sudo && RS+=(--rsync-path="sudo -n rsync")
  fi
  local x; while IFS= read -r x; do [[ -n $x ]] && RS+=(--exclude="$x"); done <<<"${S_EXCLUDES[$i]}"
  while IFS= read -r x; do [[ -n $x ]] && RS+=("$x"); done <<<"${S_ONLY[$i]}"
  RS+=("$@" "$(src_spec "$i")" "${S_DST[$i]%/}/")
}
avail() { local p=$1; while [[ ! -e $p && $p != / ]]; do p=$(dirname "$p"); done; df -B1 --output=avail "$p" | tail -1 | tr -d ' '; }
dst_guard() { # step -> 0 if the destination mount is really there
  local m=${S_DST_MOUNT[$1]}
  if [[ $m != / ]] && ! mountpoint -q "$m"; then
    conflict "$m is not mounted: the copy would land on the root filesystem. Mount it first."; return 1
  fi
}

git_url() { if src_is_local "$1"; then printf '%s' "${S_SRC[$1]}"; else printf 'ssh://%s:%s%s' "${S_SRC_LOGIN[$1]}" "${S_SRC_PORT[$1]}" "${S_SRC[$1]}"; fi; }
export GIT_SSH_COMMAND="ssh -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new"
# The source repo belongs to another user and git refuses "dubious ownership" even for root. A -c option does not
# reach the upload-pack git spawns for local clones, but a global config file does.
GIT_SAFE=/etc/storageforge/git-safe.conf
if [[ $EUID -eq 0 ]]; then mkdir -p /etc/storageforge; [[ -e $GIT_SAFE ]] || printf '[safe]\n\tdirectory = *\n' >"$GIT_SAFE"
else GIT_SAFE=$(mktemp); printf '[safe]\n\tdirectory = *\n' >"$GIT_SAFE"; trap 'rm -f "$GIT_SAFE"' EXIT; fi
export GIT_CONFIG_GLOBAL=$GIT_SAFE
GIT=(git)
git_refs() { sort | awk '$2 != "HEAD"' ; }
git_step() { # step mode
  local i=$1 url refs; url=$(git_url "$i")
  command -v git >/dev/null || { conflict "git is not installed on $(uname -n)"; return 1; }
  case $2 in
    check)
      if refs=$("${GIT[@]}" ls-remote "$url" 2>/dev/null); then ok "source repository $url ($(grep -c . <<<"$refs") refs)"
      else conflict "cannot read the repository at $url (path, SSH key, or permissions)"; fi
      if [[ -d ${S_DST[$i]} ]]; then info "archive exists: --run fetches what is new"; else info "archive will be created by --run"; fi ;;
    dryrun)
      if [[ -d ${S_DST[$i]} ]]; then "${GIT[@]}" -C "${S_DST[$i]}" fetch --dry-run --prune origin 2>&1 | sed 's/^/            /' || true
      else info "would run: git clone --mirror $url ${S_DST[$i]}"; fi ;;
    run)
      if [[ -d ${S_DST[$i]} ]]; then doing "git remote update --prune in ${S_DST[$i]}"; "${GIT[@]}" -C "${S_DST[$i]}" remote update --prune
      else mkdir -p "$(dirname "${S_DST[$i]}")"; doing "git clone --mirror $url ${S_DST[$i]}"; "${GIT[@]}" clone --mirror "$url" "${S_DST[$i]}"; fi
      mkdir -p "$STATE"; date '+%F %T' >"$STATE/$i.done"; ok "archive up to date" ;;
    verify)
      local a b
      a=$("${GIT[@]}" ls-remote "$url" | git_refs) && [[ -n $a ]] || { conflict "cannot read the source repository $url"; return 1; }
      b=$("${GIT[@]}" -C "${S_DST[$i]}" show-ref | awk '{print $1 "\t" $2}' | git_refs) && [[ -n $b ]] || { conflict "no archive at ${S_DST[$i]} yet: --run creates it"; return 1; }
      if [[ $a == "$b" ]]; then ok "archive has every branch and tag at the same commit"; return 0; fi
      conflict "archive differs from the source:"; diff <(echo "$a") <(echo "$b") | grep '^[<>]' | head -10 | sed 's/^/            /'; return 1 ;;
  esac
}
check_step() {
  local i=$1
  if [[ ${S_METHOD[$i]} == git ]]; then git_step "$i" check; dst_guard "$i" && ok "destination mount ${S_DST_MOUNT[$i]}"; return 0; fi
  if src_is_local "$i"; then
    if [[ -d ${S_SRC[$i]} ]]; then ok "source ${S_SRC[$i]}"; else conflict "source ${S_SRC[$i]} does not exist"; fi
  else
    if ssh_src "$i" test -d "$(printf %q "${S_SRC[$i]}")" 2>/dev/null; then ok "source ${S_SRC_LOGIN[$i]}:${S_SRC[$i]} (SSH works)"
    else conflict "cannot reach ${S_SRC_LOGIN[$i]}:${S_SRC[$i]} with a key over SSH (BatchMode). As root here: ssh-copy-id ${S_SRC_LOGIN[$i]}, or run with --host --forward-agent from a machine whose agent has the key"; fi
    if has "$i" sudo; then
      # only rsync's sending (read-only) side is needed on the source, so sudoers can allow just that
      if ssh_src "$i" sudo -n -l rsync --server --sender -logDtpre.iLsfxCIvu . / >/dev/null 2>&1; then ok "sudo rsync (sending side) is allowed on the source"
      else conflict "sudo on ${S_SRC_LOGIN[$i]} needs a password for rsync. Allow read-only rsync there with: echo '${S_SRC_LOGIN[$i]%@*} ALL=(root) NOPASSWD: /usr/bin/rsync --server --sender *' | sudo tee /etc/sudoers.d/storageforge-rsync && sudo chmod 440 /etc/sudoers.d/storageforge-rsync; or turn off sudo for this step"; fi
    fi
  fi
  if dst_guard "$i"; then ok "destination mount ${S_DST_MOUNT[$i]}"; fi
  if [[ ${S_METHOD[$i]} != rsnapshot && ${S_BYTES[$i]} -gt 0 ]]; then
    local free; free=$(avail "${S_DST[$i]}")
    if ((free > S_BYTES[i])); then ok "space: $(human "${S_BYTES[$i]}") needed, $(human "$free") free"
    else conflict "space: $(human "${S_BYTES[$i]}") needed, only $(human "$free") free on $(df --output=target "$(dirname "${S_DST[$i]}")" 2>/dev/null | tail -1)"; fi
  fi
  if [[ -d ${S_DST[$i]} ]] && [[ -n $(ls -A "${S_DST[$i]}" 2>/dev/null) ]]; then info "destination already has data; rsync adds and updates, never removes$(has "$i" delete && echo ' (except: mirror --delete)')"; fi
  [[ -e $STATE/$i.done ]] && info "last copied: $(cat "$STATE/$i.done")"
  [[ -e $STATE/$i.cutover ]] && info "cut over: $(cat "$STATE/$i.cutover")"
  return 0
}
run_step() {
  local i=$1
  dst_guard "$i" || return 1
  [[ ${S_METHOD[$i]} == git ]] && { git_step "$i" run; return; }
  mkdir -p "${S_DST[$i]}"
  rsync_args "$i" --info=progress2,stats2
  doing "${RS[*]}"
  "${RS[@]}"
  mkdir -p "$STATE"; date '+%F %T' >"$STATE/$i.done"
  ok "copied"
}
dryrun_step() {
  local i=$1
  dst_guard "$i" || return 1
  [[ ${S_METHOD[$i]} == git ]] && { git_step "$i" dryrun; return; }
  rsync_args "$i" -n --stats
  "${RS[@]}" | grep -E '^(Number of (created|regular) files|Number of regular files transferred|Total file size|Total transferred file size)' | sed 's/^/            /'
}
verify_step() { # -> 0 if destination matches source
  local i=$1 out n rc=0
  dst_guard "$i" || return 1
  [[ ${S_METHOD[$i]} == git ]] && { git_step "$i" verify; return; }
  rsync_args "$i" -n -i
  # rsync's errors go to stderr: a run that failed (host down, source gone) lists no differences, and cutover
  # trusts this check, so only a clean exit counts
  out=$("${RS[@]}") || rc=$?
  if ((rc)); then conflict "rsync could not compare the folders (exit $rc): not a match"; return 1; fi
  out=$(grep -v '^\.d' <<<"$out" | grep -v '^cd' || true)
  n=$(grep -c . <<<"$out" || true)
  if ((n == 0)); then ok "destination matches the source$( { has "$i" checksum || ((CHECKSUM)); } && echo ' (checksums)')"; return 0; fi
  conflict "$n difference(s); first ones:"; head -10 <<<"$out" | sed 's/^/            /'; return 1
}
cutover_step() {
  local i=$1 when; when=$(date +%Y%m%d)
  [[ ${S_METHOD[$i]} == move ]] || { info "not a move step"; return 0; }
  [[ -e $STATE/$i.cutover ]] && { ok "already cut over: $(cat "$STATE/$i.cutover")"; return 0; }
  verify_step "$i" || { conflict "not cutting over until --verify is clean"; return 1; }
  local src=${S_SRC[$i]%/} old="${S_SRC[$i]%/}.migrated-$when"
  if src_is_local "$i"; then
    [[ -e $old ]] && { conflict "$old already exists"; return 1; }
    doing "mv $src $old"; mv -- "$src" "$old"
    if has "$i" link; then doing "ln -s ${S_DST[$i]%/} $src"; ln -s -- "${S_DST[$i]%/}" "$src"; fi
  else
    doing "on ${S_SRC_LOGIN[$i]}: mv $src $old"
    ssh_src "$i" sudo -n mv -- "$(printf %q "$src")" "$(printf %q "$old")"
    info "nothing links the old path on the source host to this one; repoint its users (NFS export, mounts) by hand"
  fi
  mkdir -p "$STATE"; echo "$(date '+%F %T') · source kept as $old" >"$STATE/$i.cutover"
  ok "cut over; delete $old yourself once you are sure"
}
unit_name() { echo "sf-move-$PLAN-$1"; }
sd_words() { # args -> one systemd ExecStart line (its own quoting: "…", \\ \" escapes, %% and $$ for literals)
  local a out=; for a; do a=${a//\\/\\\\}; a=${a//\"/\\\"}; a=${a//%/%%}; a=${a//\$/\$\$}; out+=" \"$a\""; done; echo "${out# }"
}
root_key_ok() { # step -> timers run as root without your agent: root here needs its own key on the source
  src_is_local "$1" && return 0
  if env -u SSH_AUTH_SOCK ssh -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new -p "${S_SRC_PORT[$1]}" "${S_SRC_LOGIN[$1]}" true 2>/dev/null; then
    ok "root on $(uname -n) can reach ${S_SRC_LOGIN[$1]} with its own key"; return 0; fi
  conflict "timers run as root without your SSH agent, and root here has no key for ${S_SRC_LOGIN[$1]}: sudo ssh-keygen -t ed25519 (if root has none), then sudo ssh-copy-id ${S_SRC_LOGIN[$1]}"
  return 1
}
SUDO_RSYNC=/usr/local/bin/sf-sudo-rsync   # rsnapshot cannot pass "sudo -n rsync" as one --rsync-path
ensure_sudo_rsync() { # step -> the wrapper exists on the source (only creates)
  if ssh_src "$1" test -x "$SUDO_RSYNC"; then ok "$SUDO_RSYNC on the source"; return 0; fi
  doing "create $SUDO_RSYNC on ${S_SRC_LOGIN[$1]}"
  printf '#!/bin/sh\nexec sudo -n rsync "$@"\n' | ssh_src "$1" "sudo -n tee $SUDO_RSYNC >/dev/null && sudo -n chmod 755 $SUDO_RSYNC" \
    || { conflict "could not create $SUDO_RSYNC on the source (sudo needs a password?)"; return 1; }
}
write_new() { # file content -> creates it, or reports a conflict if it exists with other content
  if [[ -e $1 ]]; then
    if [[ $(cat "$1") == "$2" ]]; then ok "$1"; else conflict "$1 exists with different content; not touched"; fi
  else doing "write $1"; printf '%s\n' "$2" >"$1"; fi
}
install_step() {
  local i=$1 u; u=$(unit_name "$i")
  if [[ ${S_METHOD[$i]} =~ ^(mirror|rsnapshot|git)$ ]] && ! command -v systemctl >/dev/null; then
    conflict "no systemd on $(uname -n): schedule it with cron instead"; return 1; fi
  case ${S_METHOD[$i]} in
    mirror)
      root_key_ok "$i" || return 1
      rsync_args "$i" --info=stats2
      write_new "/etc/systemd/system/$u.service" "[Unit]
Description=StorageForge mirror: ${S_DESC[$i]}
After=network-online.target
Wants=network-online.target
RequiresMountsFor=${S_DST_MOUNT[$i]}

[Service]
Type=oneshot
Nice=10
IOSchedulingClass=idle
ExecStart=$(sd_words "${RS[@]}")"
      write_new "/etc/systemd/system/$u.timer" "[Unit]
Description=StorageForge mirror timer: ${S_DESC[$i]}

[Timer]
OnCalendar=${S_SCHEDULE[$i]}
Persistent=true
RandomizedDelaySec=10min

[Install]
WantedBy=timers.target"
      systemctl daemon-reload; systemctl enable --now "$u.timer"; ok "timer $u.timer (${S_SCHEDULE[$i]})" ;;
    rsnapshot)
      command -v rsnapshot >/dev/null || { conflict "rsnapshot is not installed"; return 1; }
      root_key_ok "$i" || return 1
      mkdir -p /etc/rsnapshot.d "${S_DST[$i]}"
      local conf=/etc/rsnapshot.d/$u.conf src lv cnt rsargs="--numeric-ids --protect-args --filter=-x_system.* --filter=-x_security.selinux"
      src=$(src_spec "$i")
      has "$i" onefs && rsargs+=" --one-file-system"
      if ! src_is_local "$i" && has "$i" sudo; then ensure_sudo_rsync "$i" || return 1; rsargs+=" --rsync-path=$SUDO_RSYNC"; fi
      local body; body=$(printf 'config_version\t1.2\nsnapshot_root\t%s/\nno_create_root\t1\ncmd_rsync\t%s\ncmd_ssh\t%s\nssh_args\t-o BatchMode=yes -p %s\nrsync_short_args\t-aHAXS\nrsync_long_args\t%s\nlockfile\t/run/%s.pid\n' \
        "${S_DST[$i]%/}" "$(command -v rsync)" "$(command -v ssh)" "${S_SRC_PORT[$i]}" "$rsargs" "$u")
      for kv in ${S_KEEP[$i]}; do body+=$(printf '\nretain\t%s\t%s' "${kv%=*}" "${kv#*=}"); done
      while IFS= read -r x; do [[ -n $x ]] && body+=$(printf '\nexclude\t%s' "$x"); done <<<"${S_EXCLUDES[$i]}"
      body+=$(printf '\nbackup\t%s\t%s/' "$src" "$(basename "${S_SRC[$i]%/}")")
      write_new "$conf" "$body"
      rsnapshot -c "$conf" configtest >/dev/null && ok "rsnapshot configtest" || conflict "rsnapshot configtest failed: rsnapshot -c $conf configtest"
      for kv in ${S_KEEP[$i]}; do
        lv=${kv%=*}; cnt=${kv#*=}; ((cnt > 0)) || continue
        write_new "/etc/systemd/system/$u-$lv.service" "[Unit]
Description=StorageForge rsnapshot $lv: ${S_DESC[$i]}
RequiresMountsFor=${S_DST_MOUNT[$i]}

[Service]
Type=oneshot
Nice=10
IOSchedulingClass=idle
ExecStart=$(command -v rsnapshot) -c $conf $lv"
        write_new "/etc/systemd/system/$u-$lv.timer" "[Unit]
Description=StorageForge rsnapshot $lv timer

[Timer]
OnCalendar=$lv
Persistent=true

[Install]
WantedBy=timers.target"
      done
      systemctl daemon-reload
      for kv in ${S_KEEP[$i]}; do ((${kv#*=} > 0)) && systemctl enable --now "$u-${kv%=*}.timer"; done
      ok "rsnapshot timers enabled" ;;
    git)
      root_key_ok "$i" || return 1
      [[ -d ${S_DST[$i]} ]] || { conflict "run --run first to create the archive"; return 1; }
      write_new "/etc/systemd/system/$u.service" "[Unit]
Description=StorageForge git archive: ${S_DESC[$i]}
After=network-online.target
Wants=network-online.target
RequiresMountsFor=${S_DST_MOUNT[$i]}

[Service]
Type=oneshot
Nice=10
Environment=$(sd_words "GIT_SSH_COMMAND=$GIT_SSH_COMMAND" "GIT_CONFIG_GLOBAL=$GIT_SAFE")
ExecStart=$(sd_words "$(command -v git)" -C "${S_DST[$i]}" remote update --prune)"
      write_new "/etc/systemd/system/$u.timer" "[Unit]
Description=StorageForge git archive timer: ${S_DESC[$i]}

[Timer]
OnCalendar=${S_SCHEDULE[$i]}
Persistent=true
RandomizedDelaySec=10min

[Install]
WantedBy=timers.target"
      systemctl daemon-reload; systemctl enable --now "$u.timer"; ok "timer $u.timer (${S_SCHEDULE[$i]})" ;;
    *) info "nothing to install for a ${S_METHOD[$i]} step" ;;
  esac
}

echo "${H}$PLAN_NAME${N0} · $MODE on $(uname -n)"
for ((i = 0; i < N; i++)); do
  [[ -n $ONLY && $ONLY != $((i + 1)) ]] && continue
  section "step $((i + 1)): ${S_DESC[$i]}"
  if [[ ${S_RUNNER[$i]} != "$ME" ]]; then skip "runs on ${S_RUNNER[$i]}: ./$(basename "$0") --host <user>@${S_RUNNER[$i]} ${ARGS[*]}"; continue; fi
  case $MODE in
    check) check_step "$i" ;;
    dryrun) dryrun_step "$i" || true ;;
    run) if [[ ${S_METHOD[$i]} == rsnapshot ]]; then info "rsnapshot step: --install sets it up; its first snapshot runs on the timer"; else run_step "$i" || true; fi ;;
    verify) [[ ${S_METHOD[$i]} == rsnapshot ]] && info "rsnapshot step: nothing to verify" || verify_step "$i" || true ;;
    cutover) cutover_step "$i" || true ;;
    install) install_step "$i" || true ;;
  esac
done
echo
if ((PROBLEMS)); then echo "${R}$PROBLEMS problem(s)${N0}"; exit 1; fi
[[ $MODE =~ ^(run|cutover|install)$ ]] && APPLY=1
finished
"""
