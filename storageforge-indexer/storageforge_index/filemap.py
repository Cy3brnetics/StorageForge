"""The Graph view's file map: where duplicates live, from the index alone, as folders and the lines between them.

Exact copies come from checksums (only files whose size collided with another's are hashed, on a --checksum scan).
Whole-folder copies come from folders.duplicate_folders, by name and size. A file group whose every copy sits inside a
reported folder copy is left out: the folder already says it. Space is counted per host: a copy on another host is more
likely a backup than waste. The index holds no inode numbers, so hard links count as copies and free nothing.
"""
from __future__ import annotations

import json
import posixpath

from . import moves
from .analysis import resolve
from .db import Conn, epoch
from .folders import ignore_lists, is_ignored
from .graph import load as graph_load
from .search import join_path

MAX_GROUPS, MAX_FOLDERS, MAX_PAIRED = 300, 500, 8
APP_DIRS = ('/opt',)                       # packaged apps bundle the same libraries: copies, but not ones to clean up by hand


def _same_host_reclaim(copies: list[dict], size: int) -> int:
    hosts = {c['host'] for c in copies}
    return size * (len(copies) - len(hosts))


def file_groups(conn: Conn, host: str | None, min_size: int, ignore: dict, system: bool) -> tuple[list[dict], dict]:
    """Files with the same checksum anywhere in the fleet. With a host, the groups with a copy there, with every copy: the
    host filter used to sit inside the count too, so a file whose only copy was on another host was never a duplicate."""
    mine = 'AND sum(CASE WHEN h.hostname = :host OR h.ip_address = :host THEN 1 ELSE 0 END) > 0' if host else ''
    found: dict[str, dict] = {}
    cur = conn.execute(f"""SELECT f.checksum_hash, h.hostname, m.mount_point, d.path, f.filename, f.file_size_bytes, f.modified_at
                           FROM file_records f JOIN directories d ON d.dir_id = f.dir_id
                           JOIN mounts m ON m.mount_id = f.mount_id JOIN hosts h ON h.host_id = m.host_id
                           WHERE f.checksum_hash IS NOT NULL AND f.file_size_bytes >= :min AND NOT f.is_directory AND NOT f.is_symlink
                             AND f.checksum_hash IN (SELECT x.checksum_hash FROM file_records x JOIN mounts xm ON xm.mount_id = x.mount_id
                                                     JOIN hosts h ON h.host_id = xm.host_id
                                                     WHERE x.checksum_hash IS NOT NULL AND x.file_size_bytes >= :min
                                                       AND NOT x.is_directory AND NOT x.is_symlink
                                                     GROUP BY x.checksum_hash HAVING count(*) > 1 {mine})""",
                       {'min': min_size, 'host': host})
    while rows := cur.fetchmany(50_000):
        for sha, hn, mount, parent, name, size, mtime in rows:
            g = found.setdefault(sha, {'sha256': sha, 'size': size, 'copies': [], 'hidden': 0})
            path = join_path(parent, name)
            if is_ignored(hn, path, ignore, system=not system, extra=() if system else APP_DIRS):
                g['hidden'] += 1
            else:
                g['copies'].append({'host': hn, 'mount': mount, 'path': path, 'modified_at': epoch(mtime)})
    groups, hidden = [], {'groups': 0, 'bytes': 0}
    for g in found.values():
        if len(g['copies']) + g['hidden'] < 2:
            continue
        if len(g['copies']) < 2:              # the other copies are system files or ignored
            hidden['groups'] += 1
            hidden['bytes'] += g['size'] * (len(g['copies']) + g['hidden'] - 1)
            continue
        g['copies'].sort(key=lambda c: (c['host'], c['path']))
        g['scope'] = 'same host' if len({c['host'] for c in g['copies']}) == 1 else 'across hosts'
        g['reclaimable'] = _same_host_reclaim(g['copies'], g['size'])
        groups.append(g)
    groups.sort(key=lambda g: (-g['reclaimable'], -g['size'] * len(g['copies'])))
    return groups, hidden


def build(conn: Conn, host: str | None, min_size: int, system: bool = False, twins: dict | None = None) -> dict:
    ignore = ignore_lists(conn)
    groups, hidden = file_groups(conn, host, min_size, ignore, system)

    folder_copies = []
    for t in (twins or {}).get('groups', []):
        copies = [c for c in t['copies'] if not is_ignored(c['host'], c['path'], ignore, system=not system, extra=() if system else APP_DIRS)]
        if len(copies) < 2:
            continue
        hosts = {c['host'] for c in copies}
        folder_copies.append({**t, 'copies': copies, 'count': len(copies), 'reclaimable': t['bytes'] * (len(copies) - len(hosts)),
                              'scope': 'same host' if len(hosts) == 1 else 'across hosts'})

    whole = {(c['host'], c['path']) for t in folder_copies for c in t['copies']}

    def in_folder_copy(c):
        path = c['path']
        while path not in ('/', ''):
            path = posixpath.dirname(path)
            if (c['host'], path) in whole:
                return True
        return False

    groups = [g for g in groups if not all(in_folder_copy(c) for c in g['copies'])]
    for g in groups:                       # the folder copy already counts what is inside it
        per_host: dict[str, set] = {}
        for i, c in enumerate(g['copies']):
            per_host.setdefault(c['host'], set()).add('folder' if in_folder_copy(c) else i)
        g['reclaimable'] = g['size'] * sum(len(v) - 1 for v in per_host.values())
    groups.sort(key=lambda g: (-g['reclaimable'], -g['size'] * len(g['copies'])))
    total_groups = len(groups)
    shown = groups[:MAX_GROUPS]

    folders: dict[str, dict] = {}

    def folder(c, path):
        k = f'{c["host"]}\0{path}'
        return folders.setdefault(k, {'key': k, 'host': c['host'], 'mount': c['mount'], 'path': path, 'files': 0, 'bytes': 0, 'whole': False})

    links: dict[tuple, dict] = {}

    def join(keys, files, size, kind):
        keys = sorted(set(keys))[:MAX_PAIRED]
        for i, a in enumerate(keys):
            for b in keys[i + 1:]:
                e = links.setdefault((a, b), {'a': a, 'b': b, 'files': 0, 'bytes': 0, 'kind': 'files',
                                              'scope': 'same host' if a.split('\0')[0] == b.split('\0')[0] else 'across hosts'})
                if kind == 'files' and e['kind'] == 'folder':
                    continue                # the folder copy already counts this file
                e['files'] += files
                e['bytes'] += size
                e['kind'] = kind

    for t in folder_copies:
        for c in t['copies']:
            f = folder(c, c['path'])
            f['whole'] = True
            f['files'] += t['files']
            f['bytes'] += t['bytes']
        join([f'{c["host"]}\0{c["path"]}' for c in t['copies']], t['files'], t['bytes'], 'folder')
    for g in shown:
        keys = []
        for c in g['copies']:
            f = folder(c, posixpath.dirname(c['path']))
            if not in_folder_copy(c):
                f['files'] += 1
                f['bytes'] += g['size']
            keys.append(f['key'])
        join(keys, 1, g['size'], 'files')

    top = sorted(folders.values(), key=lambda f: -f['bytes'])[:MAX_FOLDERS]
    keep = {f['key'] for f in top}
    hsql = 'WHERE (h.hostname = :host OR h.ip_address = :host)' if host else ''
    checksummed = conn.scalar(f"""SELECT count(*) FROM file_records f JOIN mounts m ON m.mount_id = f.mount_id JOIN hosts h ON h.host_id = m.host_id
                                  {hsql} {'AND' if host else 'WHERE'} f.checksum_hash IS NOT NULL""", {'host': host})
    return {'folders': top, 'folders_total': len(folders), 'links': [e for e in links.values() if e['a'] in keep and e['b'] in keep],
            'groups': shown, 'groups_total': total_groups, 'folder_copies': folder_copies, 'folders_compared': twins is not None,
            'reclaimable': sum(g['reclaimable'] for g in groups) + sum(t['reclaimable'] for t in folder_copies),
            'hidden': hidden, 'checksummed': checksummed or 0, 'broken_links': broken_links(conn, host, ignore),
            'relations': relations(conn, host, ignore, system), 'ignore': ignore}


def relations(conn: Conn, host: str | None, ignore: dict, system: bool = False) -> list[dict]:
    """What already joins folders, beyond copies: symlinks, bind mounts, shares mounted from another host, deployed jobs
    and backups. src and dst are {host, path}; a dst that is not a scanned host has only a name."""
    g = graph_load(conn)
    nodes = {n['id']: n for n in g['nodes']}
    mount_of_fs = {e['src']: nodes[e['dst']]['label'] for e in g['edges'] if e['rel'] == 'MOUNTED_AT' and e['src'] in nodes and e['dst'] in nodes
                   and nodes[e['src']]['kind'] == 'Filesystem'}
    names = {moves.host_slug(r[0]): r[0] for r in conn.all('SELECT hostname FROM hosts')}
    out = []

    def add(kind, shost, spath, dhost, dpath, **extra):
        out.append({'kind': kind, 'src': {'host': shost, 'path': spath}, 'dst': {'host': dhost, 'path': dpath}, **extra})

    for e in g['edges']:
        s, t, p = nodes.get(e['src']), nodes.get(e['dst']), e['props']
        if not s or not t:
            continue
        if e['rel'] == 'SYMLINK_TO' and s['kind'] == 'Symlink' and p.get('target'):
            if not is_ignored(s['host'], s['label'], ignore, system=not system):
                add('symlink', s['host'], s['label'], s['host'], resolve(s['label'], p['target']), broken=s['health'] == 'broken')
        elif e['rel'] == 'MOUNTED_AT' and p.get('bind') and p.get('source'):
            add('bind', t['host'], p['source'], t['host'], t['label'])
        elif e['rel'] == 'MOUNTED_AT' and p.get('remote') and p.get('server'):
            add('share', p['server'], p.get('path') or s['label'], t['host'], t['label'], label=p.get('share'))
        elif e['rel'] == 'REPLICATES_TO' and not str(p.get('detail') or '').startswith('job ') and e['src'] in mount_of_fs:
            scanned = t['label'] in names.values()
            add('backup', s['host'], mount_of_fs[e['src']], t['label'] if scanned else None, '/' if scanned else None,
                label=p.get('detail') or t['label'], broken=p.get('health') == 'broken')
    try:
        from .jobs import overview
        for j in overview(conn):
            places = j.get('places') or [{'host': j.get('source') or j.get('runner'), 'path': s} for s in (j.get('sources') or ([j['src']] if j.get('src') else []))]
            for p in places if j.get('dst') else ():     # each source on its own host
                add('job', names.get(moves.host_slug(p['host']), p['host']), p['path'], names.get(moves.host_slug(j['runner']), j['runner']), j['dst'],
                    label=f'{j["method"]} job', broken=j.get('state') == 'failed')
    except Exception:                       # an older schema without jobs: nothing to add
        pass
    if host:
        out = [r for r in out if host in (r['src']['host'], r['dst']['host'])]
    return out


def broken_links(conn: Conn, host: str | None, ignore: dict) -> list[dict]:
    rows = conn.all(f"""SELECT host, label, props_json FROM graph_nodes WHERE kind = 'Symlink' AND health = 'broken'
                        {'AND host = :host' if host else ''} ORDER BY host, label""", {'host': host})
    out = []
    for h, path, props in rows:
        if is_ignored(h, path, ignore):
            continue
        p = json.loads(props or '{}')
        out.append({'host': h, 'path': path, 'target': p.get('target'), 'note': p.get('note')})
    return out
