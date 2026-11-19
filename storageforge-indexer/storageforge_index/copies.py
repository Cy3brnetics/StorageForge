"""Copies of the same content, and what a plan would leave of them.

The duplicates views say where copies are. This module says what they are worth: a copy on another host is a possible backup, not
waste, and a plan that moves copies to the trash is checked for what it would leave behind.

The trash check (changes.check calls it) looks at the `trash` tasks of one plan together:

    last-copy        critical: two or more tasks between them move every copy the index knows of some content to the trash
    only-copy-left   warning: the content is on more than one host now, and afterwards on one host only

Content is what the duplicates views show: files with the same checksum, and folders holding the same file names and sizes in the
same layout (folders.py). Nothing here reads the whole index: the files and folders under each trashed path are read, and other copies
of them are looked up by checksum, or by the size and name of a folder's largest file and then compared in full. A copy already in
.storageforge-trash is nobody's copy: that folder is there to be emptied.

Keeping a pair in sync (prepare_sync) saves a Moves plan with one mirror step, which the user deploys as any plan. Once its job is
deployed the pair is "kept in sync" (syncs), and its destination is no longer a duplicate of its source (split_kept), in the
duplicates views and in the file map.
"""
from __future__ import annotations

import heapq
import json
import posixpath

from .db import Conn, epoch
from .moves import _fmt, _path, _subtree_sql, find_host, get_plan, host_slug, hosts, mount_of, normalize, save_plan
from .moves import check as moves_check
from .remote import is_under

M64 = (1 << 64) - 1
TRASH = '.storageforge-trash'
MIN_FILES, MIN_BYTES = 3, 1 << 20       # what the duplicates views compare by default: a smaller folder alike by name and size says little
MAX_LOOKUPS = 2000                      # folders of one plan looked up in the rest of the index, largest first
MAX_CANDIDATES = 32                     # places compared in full for one folder
MAX_SAID = 6                            # findings named one by one on a task; the rest are counted


def in_trash(path: str) -> bool:
    return f'/{TRASH}/' in path + '/'


# ── kept in sync ────────────────────────────────────────────────────
# Two folders are kept in sync by what already syncs folders here: a `mirror` step of a Moves plan (moves.py), deployed as a job
# that runs on the destination host on a timer and pulls from the source (jobs.py, jobscript.py). Nothing else is made: the action
# below saves such a plan and the user reads and deploys it in Moves, with the password, as any plan. A deployed mirror job is what
# makes a pair "kept in sync", whoever wrote its plan.
SCHEDULES = ('hourly', 'daily', 'weekly')
STATE_TEXT = {'ok': 'in sync at its last run', 'failed': 'the last run failed', 'stale': 'behind: no good run on schedule', 'never-ran': 'deployed, waiting for its first run',
              'paused': 'paused', 'missing': 'its job is gone from the host'}


def syncs(conn: Conn, now: float | None = None) -> list[dict]:
    """Every deployed mirror job, with its state and last runs as the Deploy tab has them (jobs.overview)."""
    from .jobs import overview
    flags = {r[0]: (json.loads(r[1] or '{}').get('flags') or '').split() for r in conn.all(
        "SELECT job_id, spec_json FROM jobs WHERE removed_at IS NULL AND method = 'mirror'")}
    out = []
    for j in overview(conn, now):
        if j['method'] != 'mirror' or not j.get('src') or not j.get('dst'):
            continue
        src_host = j['source'] or j['runner']
        out.append({'job': j['id'], 'plan': j['plan_id'], 'name': j['name'], 'src': {'host': src_host, 'path': j['src']},
                    'dst': {'host': j['runner'], 'path': j['dst']}, 'across': host_slug(src_host) != host_slug(j['runner']),
                    'state': j['state'], 'state_text': STATE_TEXT.get(j['state'], j['state']), 'schedule': j['schedule'], 'paused': j['paused'],
                    'deployed_at': j['deployed_at'], 'last': j['last'], 'last_ok': j['last_ok'], 'delete': 'delete' in flags.get(j['id'], ())})
    return out


def kept_by(copy: dict, copies: list[dict], links: list[dict]) -> dict | None:
    """The sync this copy is the destination of, when the same set holds what it is synced from: then it is that sync's copy, not a
    duplicate. A file the sync left behind at the destination, with no source any more, is still a duplicate of whatever else holds it."""
    for s in links:
        if s['dst']['host'] != copy['host'] or not is_under(copy['path'], s['dst']['path']):
            continue
        src = (s['src']['path'].rstrip('/') + _rel(s['dst']['path'], copy['path'])) or '/'
        if any(c['host'] == s['src']['host'] and c['path'] == src for c in copies):
            return s
    return None


def split_kept(copies: list[dict], links: list[dict]) -> tuple[list[dict], list[dict]]:
    """(the copies that are still duplicates of each other, the ones a sync keeps: each with its 'job')."""
    if not links:
        return copies, []
    rest, kept = [], []
    for c in copies:
        s = kept_by(c, copies, links)
        if s:
            kept.append({**c, 'job': s['job']})
        else:
            rest.append(c)
    return rest, kept


def prepared(conn: Conn) -> list[dict]:
    """Mirror steps of saved Moves plans that are not deployed as jobs: a sync someone prepared and has not deployed yet."""
    from .jobs import job_id
    live = {r[0] for r in conn.all('SELECT job_id FROM jobs WHERE removed_at IS NULL')}
    out = []
    for pid, name, body in conn.all('SELECT plan_id, name, body_json FROM move_plans ORDER BY plan_id'):
        for s in json.loads(body).get('steps') or []:
            if s.get('method') == 'mirror' and job_id(pid, s.get('id')) not in live:
                out.append({'plan': pid, 'name': name, 'src': s['src'], 'dst': s['dst'], 'delete': bool((s.get('options') or {}).get('delete'))})
    return out


def _place(conn: Conn, hs: dict, p, what: str) -> dict:
    if not isinstance(p, dict) or not p.get('host') or not p.get('path'):
        raise ValueError(f'{what}: give a host and a folder')
    h = find_host(hs, str(p['host']))
    if not h:
        raise ValueError(f'{what}: {p["host"]} has not been scanned')
    return {'host': h['name'], 'path': _path(p['path'], what)}


def sides(conn: Conn, places: list) -> dict:
    """For choosing which side is the source: each folder's files, size and newest change from the index, and which changed last."""
    hs = hosts(conn)
    out = []
    for n, p in enumerate(places[:16], 1):
        p = _place(conn, hs, p, f'folder {n}')
        m = mount_of(hs[p['host']], p['path'])
        if m and m['state'] == 'indexed':
            where, q = _subtree_sql(p['path'], m['target'])
            files, size, newest = conn.all(f"""SELECT count(*), coalesce(sum(f.file_size_bytes), 0), max(f.modified_at) FROM file_records f
                                               WHERE {where} AND NOT f.is_directory AND NOT f.is_symlink""", {'m': m['id'], **q})[0]
            out.append({**p, 'indexed': True, 'files': files, 'bytes': size, 'changed_at': epoch(newest)})
        else:
            out.append({**p, 'indexed': False, 'files': 0, 'bytes': 0, 'changed_at': None})
    if len(out) < 2:
        raise ValueError('give the two folders to keep in sync')
    newest = max(range(len(out)), key=lambda i: (out[i]['changed_at'] or 0, -i))
    return {'sides': out, 'source': newest}


def prepare_sync(conn: Conn, src, dst, actor: str, delete: bool = False, schedule: str = 'daily', keep_replaced: bool = False) -> dict:
    """Saves a Moves plan with one mirror step from src to dst and says which. One way, and nothing at the destination is deleted
    unless `delete` is asked for. Nothing runs: the plan is checked, reported and deployed in Moves, behind the password. A pair
    already kept in sync is refused, and a plan already prepared for it is given back instead of a second one."""
    hs = hosts(conn)
    src, dst = _place(conn, hs, src, 'the source'), _place(conn, hs, dst, 'the destination')
    if schedule not in SCHEDULES:
        raise ValueError(f'the sync runs {", ".join(SCHEDULES[:-1])} or {SCHEDULES[-1]}: other times are set on the plan in Moves')
    if src['host'] == dst['host'] and (is_under(src['path'], dst['path']) or is_under(dst['path'], src['path'])):
        raise ValueError('the two folders are the same, or one is inside the other')
    pair = {(src['host'], src['path']), (dst['host'], dst['path'])}
    for s in syncs(conn):
        if {(s['src']['host'], s['src']['path']), (s['dst']['host'], s['dst']['path'])} == pair:
            raise ValueError(f'these two are already kept in sync, from {s["src"]["host"]}:{s["src"]["path"]} to {s["dst"]["host"]}:{s["dst"]["path"]} (job {s["job"]})')
    for p in prepared(conn):
        if (p['src'], p['dst']) == (src, dst):
            plan = get_plan(conn, p['plan'])
            return {'plan': p['plan'], 'name': p['name'], 'existing': True, 'src': src, 'dst': dst, 'check': _levels(conn, plan)}
    base = f'Keep in sync: {src["host"]}:{src["path"]} to {dst["host"]}'
    base = base if len(base) <= 74 else base[:73] + '…'
    taken = {r[0].lower() for r in conn.all('SELECT name FROM move_plans')}
    name = next(n for n in (base if i == 1 else f'{base} ({i})' for i in range(1, 100_000)) if n.lower() not in taken)
    body = {'name': name, 'notes': 'Prepared from a pair of folder copies. One way, from the source to the destination: a file that differs there is '
                                   'replaced by the one from the source, and nothing else there is removed unless delete is ticked.',
            'steps': [{'method': 'mirror', 'src': src, 'dst': dst,
                       'options': {'delete': bool(delete), 'schedule': schedule, **({'keep_replaced': True} if keep_replaced else {})}}]}
    with conn.tx():
        pid = save_plan(conn, body, actor)
    return {'plan': pid, 'name': name, 'existing': False, 'src': src, 'dst': dst, 'check': _levels(conn, get_plan(conn, pid))}


# ── the pairs: suggested, kept, set aside ───────────────────────────
NOT_BACKUPS = 'copies.not_backups'      # the setting: sets of folders someone said are not a backup of each other, each a sorted list of host:path


def key_of(places: list[dict]) -> list[str]:
    return sorted(f'{c["host"]}:{c["path"]}' for c in places)


def not_backups(conn: Conn) -> list[list[str]]:
    from .alerts import get_setting
    return get_setting(conn, NOT_BACKUPS) or []


def overview(conn: Conn, twins: dict, now: float | None = None) -> dict:
    """What the Cleanup panel lists under "Copies on other hosts", from the fleet's duplicate folders (folders.duplicate_folders at its
    defaults, with the syncs taken out): the sets across hosts that nothing keeps in sync, largest first, each with the plan
    prepared for it when there is one; the pairs kept in sync, with their state and last runs; and the sets someone set aside."""
    ready, said = prepared(conn), not_backups(conn)
    suggested, aside = [], []
    for g in twins.get('groups') or []:
        if g['scope'] == 'same host':
            continue
        where = {(c['host'], c['path']) for c in g['copies']}
        plan = next((p for p in ready if (p['src']['host'], p['src']['path']) in where and (p['dst']['host'], p['dst']['path']) in where), None)
        item = {'key': key_of(g['copies']), 'files': g['files'], 'bytes': g['bytes'], 'copies': g['copies'], 'same_name': g['same_name'],
                'hosts': g['hosts'], 'prepared': plan}
        (aside if item['key'] in said else suggested).append(item)
    suggested.sort(key=lambda s: (-s['bytes'], s['key']))
    return {'suggested': suggested, 'kept': syncs(conn, now), 'dismissed': aside, 'stale': bool(twins.get('stale')),
            'across_hosts_groups': twins.get('across_hosts_groups', 0), 'listed': len(suggested) + len(aside)}


def _levels(conn: Conn, plan: dict) -> dict:
    """What Moves' own check says of the plan, so the page can say at once that it has something to read."""
    r = moves_check(conn, normalize(plan))
    return {'crit': r['crit'], 'warn': r['warn'], 'items': [it for st in r['steps'] for it in st['items'] if it['level'] in ('crit', 'warn')][:8]}


def _rel(root: str, path: str) -> str:
    """path below root, as '' or '/sub/dir'."""
    return '' if path == root else path[len(root.rstrip('/')):]


def tree_prints(rows, root: str) -> tuple[dict, dict, dict]:
    """The folders at and under root, from the file rows of that subtree (parent, name, size, is_directory, is_symlink), as
    folders.dir_index makes them for a whole mount: {path: (fingerprint, files, bytes)}. Also {path: its subfolders} and
    {path: (size, folder, name) of the largest file below it}. One difference: a folder with no row of its own between root and a
    file still passes its files up, so a folder's count here is always everything under it. Fingerprints are Python hashes: they
    hold within one process and are never kept."""
    own: dict[str, list] = {}
    best: dict[str, tuple] = {}
    for parent, name, size, is_dir, is_link in rows:
        if is_link:
            continue
        if is_dir:
            path = (f'/{name}' if parent == '/' else f'{parent}/{name}') if parent else '/'
            own.setdefault(path, [0, 0, 0])
            if parent:
                own.setdefault(parent, [0, 0, 0])
            continue
        acc = own.setdefault(parent, [0, 0, 0])
        acc[0] = (acc[0] + hash((name, size))) & M64
        acc[1] += 1
        acc[2] += size or 0
        mine = (size or 0, parent, name)
        if parent not in best or mine > best[parent]:
            best[parent] = mine
    for path in list(own):
        while path != root and path != '/' and is_under(path, root):
            path = path.rpartition('/')[0] or '/'
            if path in own:
                break
            own[path] = [0, 0, 0]
    prints, kids = {}, {}
    for path in sorted(own, key=lambda p: 0 if p == '/' else p.count('/'), reverse=True):
        acc = own[path]
        fp = hash(('dir', acc[0], acc[1])) & M64
        prints[path] = (fp, acc[1], acc[2])
        if path != '/':
            up, _, name = path.rpartition('/')
            up = up or '/'
            p = own.get(up)
            if p is not None:
                p[0] = (p[0] + hash((name, fp))) & M64
                p[1] += acc[1]
                p[2] += acc[2]
                kids.setdefault(up, []).append(path)
                if path in best and (up not in best or best[path] > best[up]):
                    best[up] = best[path]
    return prints, kids, best


def _rows_under(conn: Conn, mount_id: int, mount_point: str, path: str):
    where, p = _subtree_sql(path, mount_point)
    cur = conn.execute(f"""SELECT d.path, f.filename, f.file_size_bytes, f.is_directory, f.is_symlink
                           FROM file_records f JOIN directories d ON d.dir_id = f.dir_id WHERE {where}""", {'m': mount_id, **p})
    while rows := cur.fetchmany(50_000):
        yield from rows


class Finder:
    """Folders anywhere in the index with the same files as one folder. What it read is kept for the length of one check."""

    def __init__(self, conn: Conn):
        self.conn = conn
        self.lookups = 0
        self._print: dict[tuple, tuple | None] = {}

    def print_of(self, mount_id: int, mount_point: str, path: str, want: tuple | None = None) -> tuple | None:
        """(fingerprint, files, bytes) of a folder. With `want`, the files are counted first, and a folder that cannot match is not read."""
        key = (mount_id, path)
        if key not in self._print:
            if want is not None:
                where, p = _subtree_sql(path, mount_point)
                n, size = self.conn.all(f"""SELECT count(*), coalesce(sum(f.file_size_bytes), 0) FROM file_records f
                                            WHERE {where} AND NOT f.is_directory AND NOT f.is_symlink""", {'m': mount_id, **p})[0]
                if (n, size) != (want[1], want[2]):
                    return None                # not kept: it was not read
            self._print[key] = tree_prints(_rows_under(self.conn, mount_id, mount_point, path), path)[0].get(path)
        return self._print[key]

    def copies(self, host: str, path: str, mine: tuple, anchor: tuple) -> tuple[list[dict], bool]:
        """Every other folder with this one's fingerprint: found by its largest file's size and name, then compared whole.
        Returns them and whether there were more places to compare than MAX_CANDIDATES."""
        self.lookups += 1
        size, folder, name = anchor
        rel = _rel(path, folder)
        seen, out = set(), []
        hits = self.conn.all("""SELECT m.mount_id, h.hostname, m.mount_point, d.path
                                FROM file_records f JOIN directories d ON d.dir_id = f.dir_id
                                JOIN mounts m ON m.mount_id = f.mount_id JOIN hosts h ON h.host_id = m.host_id
                                WHERE f.file_size_bytes = :s AND f.filename = :n AND NOT f.is_directory AND NOT f.is_symlink
                                  AND m.scan_state = 'indexed'""", {'s': size, 'n': name})
        places = []
        for mid, hn, mp, at in sorted(tuple(r) for r in hits):
            if rel and not at.endswith(rel):
                continue
            root = (at[:-len(rel)] if rel else at) or '/'
            if (hn == host and root == path) or (mid, root) in seen or in_trash(root) or not is_under(root, mp):
                continue
            seen.add((mid, root))
            places.append((mid, hn, mp, root))
        for mid, hn, mp, root in places[:MAX_CANDIDATES]:
            if self.print_of(mid, mp, root, want=mine) == mine:
                out.append({'host': hn, 'path': root})
        return out, len(places) > MAX_CANDIDATES


def _roots(conn: Conn, hs: dict, tasks: list[dict]) -> list[dict]:
    """The trash tasks whose path the index holds: {task, host, mount, path, kind: 'file' | 'dir', sha}."""
    out = []
    for i, t in enumerate(tasks, 1):
        if t.get('type') != 'trash':
            continue
        h = find_host(hs, t['host'])
        path = (t.get('params') or {}).get('path')
        m = mount_of(h, path) if h and path else None
        if not m or m['state'] != 'indexed':
            continue
        parent, name = posixpath.split(path)
        row = conn.all("""SELECT f.is_directory, f.is_symlink, f.checksum_hash FROM file_records f JOIN directories d ON d.dir_id = f.dir_id
                          WHERE d.mount_id = :m AND d.path = :p AND f.filename = :n""", {'m': m['id'], 'p': parent, 'n': name})
        if row and row[0][1]:
            continue                            # a link holds no content of its own
        kind = 'file' if row and not row[0][0] else 'dir'
        out.append({'task': i, 'host': h['name'], 'mount': m, 'path': path, 'kind': kind, 'sha': row[0][2] if row and kind == 'file' else None})
    return out


def _file_contents(conn: Conn, roots: list[dict]) -> dict[str, dict]:
    """Every checksum found under the trashed paths, with all its copies: {sha: {'size', 'copies': {(host, path)}}}."""
    found: dict[str, dict] = {}

    def take(cur):
        while rows := cur.fetchmany(50_000):
            for sha, hn, parent, name, size in rows:
                path = f'/{name}' if parent == '/' else f'{parent}/{name}'
                if not in_trash(path):
                    found.setdefault(sha, {'size': size or 0, 'copies': set()})['copies'].add((hn, path))

    select = """SELECT f.checksum_hash, h.hostname, d.path, f.filename, f.file_size_bytes
                FROM file_records f JOIN directories d ON d.dir_id = f.dir_id
                JOIN mounts m ON m.mount_id = f.mount_id JOIN hosts h ON h.host_id = m.host_id
                WHERE m.scan_state = 'indexed' AND f.checksum_hash IS NOT NULL AND NOT f.is_directory AND NOT f.is_symlink AND f.checksum_hash IN """
    for r in roots:
        if r['kind'] != 'dir':
            continue
        where, p = _subtree_sql(r['path'], r['mount']['target'])
        inner = where.replace('f.', 'x.')
        take(conn.execute(f'{select}(SELECT x.checksum_hash FROM file_records x WHERE x.checksum_hash IS NOT NULL AND {inner})', {'m': r['mount']['id'], **p}))
    single = sorted({r['sha'] for r in roots if r['sha']} - set(found))
    for at in range(0, len(single), 400):
        part = single[at:at + 400]
        take(conn.execute(f'{select}({", ".join(f":c{n}" for n in range(len(part)))})', {f'c{n}': sha for n, sha in enumerate(part)}))
    return found


def _folder_contents(conn: Conn, roots: list[dict]) -> tuple[list[dict], list[tuple[int, str]]]:
    """The folders under the trashed paths that have a copy elsewhere, outermost first: [{'host', 'path', 'files', 'bytes', 'copies'}],
    and notes for the tasks where not everything could be compared."""
    finder, groups, notes = Finder(conn), [], []
    dirs = [r for r in roots if r['kind'] == 'dir']
    outer = [r for r in dirs if not any(o is not r and o['host'] == r['host'] and o['path'] != r['path'] and is_under(r['path'], o['path']) for o in dirs)]
    seen = set()
    for r in outer:
        if (r['host'], r['path']) in seen:      # the same folder staged twice
            continue
        seen.add((r['host'], r['path']))
        prints, kids, best = tree_prints(_rows_under(conn, r['mount']['id'], r['mount']['target'], r['path']), r['path'])
        if r['path'] not in prints:
            continue
        heap = [(-prints[r['path']][2], r['path'])]
        skipped = 0
        while heap:
            _, path = heapq.heappop(heap)
            mine = prints[path]
            if mine[1] < MIN_FILES or mine[2] < MIN_BYTES:
                continue                        # and so is everything inside it
            if finder.lookups >= MAX_LOOKUPS:
                skipped += 1
                continue
            copies, more = finder.copies(r['host'], path, mine, best[path])
            if more:
                notes.append((r['task'], f'{path} has a file that is in more than {MAX_CANDIDATES} places: only those were compared with it'))
            if copies:                          # what is inside it is in those copies too: said once, here
                groups.append({'host': r['host'], 'path': path, 'files': mine[1], 'bytes': mine[2], 'copies': copies})
                continue
            for kid in kids.get(path, ()):
                heapq.heappush(heap, (-prints[kid][2], kid))
        if skipped:
            notes.append((r['task'], f'only the {MAX_LOOKUPS:,} largest folders of this plan were compared with the rest of the index: '
                                     f'{skipped:,} smaller ones inside {r["path"]} were not'))
    return groups, notes


def _verdict(members: list[tuple[str, str]], gone) -> tuple | None:
    """What the plan leaves of one content. members: (host, path) of every copy; gone(host, path) → the task that removes it, or None.
    ('last-copy', task, other tasks) when two or more tasks remove every copy; ('only-copy-left', task, host, what is left) when
    the copies were on more than one host and what is left is on one."""
    by = [(m, gone(*m)) for m in members]
    removed = sorted({t for _, t in by if t is not None})
    left = [m for m, t in by if t is None]
    if not removed:
        return None
    if not left:
        return ('last-copy', removed[-1], removed[:-1]) if len(removed) > 1 else None
    hosts_left = {h for h, _ in left}
    if len({h for h, _ in members}) > 1 and len(hosts_left) == 1:
        return ('only-copy-left', removed[-1], next(iter(hosts_left)), left)
    return None


def _tasks(numbers: list[int]) -> str:
    return ('task ' if len(numbers) == 1 else 'tasks ') + ', '.join(map(str, numbers))


def _only_left(host: str, left: int) -> str:
    return f'the copy on {host} would be the only one left' if left == 1 else f'the {left} copies on {host} would be the only ones left'


def _places(members) -> str:
    said = sorted(f'{h}:{p}' for h, p in members)
    return ', '.join(said[:4]) + (f' and {len(said) - 4} more' if len(said) > 4 else '')


def trash_findings(conn: Conn, hs: dict, tasks: list[dict]) -> list[tuple[int, str, str, str]]:
    """(task number, level, code, text) for the plan's trash tasks, taken together. See the module's first lines."""
    roots = _roots(conn, hs, tasks)
    if not roots:
        return []

    def gone(host, path):
        return min((r['task'] for r in roots if r['host'] == host and is_under(path, r['path'])), default=None)

    out: list[tuple[int, str, str, str]] = []
    said: dict[tuple, int] = {}

    def say(task, level, code, text):
        said[(task, code)] = said.get((task, code), 0) + 1
        if said[(task, code)] <= MAX_SAID:
            out.append((task, level, code, text))

    folders_found, notes = _folder_contents(conn, roots)
    groups = []
    for g in folders_found:
        members = [(g['host'], g['path'])] + [(c['host'], c['path']) for c in g['copies']]
        if any(set(members) == set(x) for x in groups):
            continue                            # the same copies, met from the other side
        groups.append(members)
        v = _verdict(members, gone)
        what = f'{g["files"]:,} files, {_fmt(g["bytes"])}'
        if v and v[0] == 'last-copy':
            say(v[1], 'crit', 'last-copy', f'the last copy: this and {_tasks(v[2])} move every copy the index knows of one folder to the trash '
                                           f'({what}): {_places(members)}. Keep one of them')
        elif v:
            say(v[1], 'warn', 'only-copy-left', f'{_only_left(v[2], len(v[3]))} of a folder ({what}): {_places(v[3])}. '
                                                'A copy on another host may be its backup')

    def in_group(host, path):
        """(which set of folder copies, the folder in it) holding this path, or None."""
        return next(((n, m) for n, members in enumerate(groups) for m in members if m[0] == host and is_under(path, m[1])), None)

    files: dict[tuple, dict] = {}
    for sha, c in sorted(_file_contents(conn, roots).items()):
        members = sorted(c['copies'])
        if len(members) < 2:
            continue
        held = [in_group(*m) for m in members]
        if (all(held) and len({h[0] for h in held}) == 1
                and all(gone(*m) is None or gone(*h[1]) is not None for m, h in zip(members, held))):
            continue                            # every copy is inside one set of folder copies and goes or stays with its folder: that set has its own line
        v = _verdict(members, gone)
        if v:
            f = files.setdefault(v[:3] if v[0] == 'only-copy-left' else (v[0], v[1], tuple(v[2])), {'n': 0, 'bytes': 0, 'first': None})
            f['n'] += 1
            f['bytes'] += c['size']
            f['first'] = f['first'] or (members, v)
    for key, f in files.items():
        members, v = f['first']
        name = posixpath.basename(members[0][1])
        many = f'{f["n"]:,} files' if f['n'] > 1 else 'a file'
        if key[0] == 'last-copy':
            say(key[1], 'crit', 'last-copy', f'the last copy of {many} ({_fmt(f["bytes"])}): this and {_tasks(v[2])} move every copy the index knows '
                                             f'to the trash{", such as" if f["n"] > 1 else ":"} {name} ({_places(members)}). Keep one copy')
        else:
            lead = _only_left(key[2], len(v[3])) if f['n'] == 1 else f'the copies on {key[2]} would be the only ones left'
            say(key[1], 'warn', 'only-copy-left', f'{lead} of {many} ({_fmt(f["bytes"])})'
                                                  f'{", such as" if f["n"] > 1 else ":"} {name} ({_places(v[3])}). A copy on another host may be its backup')
    for (task, code), n in said.items():
        if n > MAX_SAID:
            out.append((task, 'crit' if code == 'last-copy' else 'warn', code, f'and {n - MAX_SAID:,} more like the lines above'))
    out += [(task, 'note', 'not-compared', text) for task, text in notes]
    return sorted(out, key=lambda x: x[0])
