"""Storage tasks: small programs built from blocks (copy with rsync, snapshots, guards, conditions, commands) that run
on one host, by hand or on a systemd timer.

A task is a list of blocks run top to bottom; "if" and "try" blocks hold blocks of their own. Each block type below
declares its parameters, and the editor builds its form from that. check() reads the plan against the index (paths,
filesystems, missing guards); script() writes one Bash script in the style of the other StorageForge scripts:

    ./task.sh                 read-only: checks the guards and prints what each block would run
    sudo ./task.sh --run      runs it
    sudo ./task.sh --install  copies itself to /usr/local/lib/storageforge/tasks and adds a systemd service (+ timer)
    sudo ./task.sh --uninstall

Deploys from the web UI run the same script through storageforge-run: report, --install (apply) or --run.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
import shlex
import time

from . import receiving, site
from .db import Conn
from .moves import _path, _under, find_host, host_slug, hosts, mount_of, slug, subtree
from .scriptkit import HELPERS, RECEIVE_KIT, REMOTE, SEND_KIT, comments, one_line

NAME_RE = re.compile(r'[^\n\r\t]{1,80}')
# [user@]host; neither part starts with '-', which rsync and ssh would read as an option
HOST_RE = re.compile(r'(?!-)([A-Za-z0-9._-]{1,32}@)?(?!-)[A-Za-z0-9.:_\[\]-]{1,253}')
PREFIX_RE = re.compile(r'[A-Za-z0-9_.-]{1,40}')
DATASET_RE = re.compile(r'(?!-)[A-Za-z0-9_.:/-]{1,200}')
UNIT_RE = re.compile(r'[A-Za-z0-9@_.:\\-]{1,120}')
SCHEDULE_RE = re.compile(r'[A-Za-z0-9 *:,./~-]{1,80}')
MAX_BLOCKS, MAX_DEPTH = 200, 6
STOP_OK = 100

# a parameter: (name, kind, label, default, extra). kinds: path, host, text, int, bool, select, lines, cmd, prefix,
# dataset, unit. extra: on= the host parameter a path belongs to ('' = the task's host), choices=, min=, max=,
# optional=, placeholder=
P = lambda name, kind, label, default=None, **extra: {'name': name, 'kind': kind, 'label': label,   # noqa: E731
                                                      'default': default, **extra}
CATEGORIES = {'guard': 'Guards', 'control': 'Control', 'copy': 'Copy', 'snapshot': 'Snapshots',
              'service': 'Services', 'other': 'Other'}
TYPES: dict[str, dict] = {
    'require_mounted': {'cat': 'guard', 'label': 'Require mounted', 'text': 'stop unless {path} is mounted',
                        'help': 'Stops the task when a disk is missing, so nothing is copied onto the system disk instead.',
                        'params': [P('path', 'path', 'Mount point')]},
    'require_free': {'cat': 'guard', 'label': 'Require free space', 'text': 'stop unless {path} has {gib} GiB free',
                     'params': [P('path', 'path', 'Folder'), P('gib', 'int', 'GiB free', 10, min=1, max=1_000_000)]},
    'require_reachable': {'cat': 'guard', 'label': 'Require host up', 'text': 'stop unless {host} answers SSH',
                          'params': [P('host', 'host', 'Host', required=True)]},
    'if': {'cat': 'control', 'label': 'If', 'text': 'if {cond} {arg}', 'slots': ['then', 'else'],
           'help': 'Runs the blocks under "then" when the condition holds, the ones under "else" when it does not.',
           'params': [P('cond', 'select', 'Condition', 'mounted', choices=['mounted', 'exists', 'free below', 'weekday',
                                                                           'day of month', 'host up', 'command succeeds']),
                      P('arg', 'text', 'Path, host, days or command', '', placeholder='/mnt/backup  ·  Sat,Sun  ·  1'),
                      P('value', 'int', 'GiB (free below)', 50, min=0, max=1_000_000, optional=True),
                      P('negate', 'bool', 'not', False)]},
    'try': {'cat': 'control', 'label': 'Try', 'text': 'try, and if it fails', 'slots': ['do', 'fallback'],
            'help': 'If a block under "do" fails, the task does not stop: the "fallback" blocks run and it carries on.',
            'params': []},
    'stop': {'cat': 'control', 'label': 'Stop', 'text': 'stop the task ({outcome})',
             'params': [P('outcome', 'select', 'As', 'ok', choices=['ok', 'failed']), P('message', 'text', 'Message', '', optional=True)]},
    'rsync': {'cat': 'copy', 'label': 'Copy with rsync', 'text': 'copy {src} → {dst}',
              'help': 'Copies what is inside "From" into "To". Mirror also deletes files at "To" that are gone from "From". '
                      'One side may be another host (over SSH, as root on this host).',
              'params': [P('src_host', 'host', 'From host', '', optional=True), P('src', 'path', 'From', on='src_host'),
                         P('dst_host', 'host', 'To host', '', optional=True), P('dst', 'path', 'To', on='dst_host'),
                         P('mode', 'select', 'Mode', 'copy', choices=['copy', 'mirror']),
                         P('one_fs', 'bool', 'stay on one filesystem', True), P('checksum', 'bool', 'compare by checksum', False),
                         P('sudo', 'bool', 'sudo rsync on the other host', True),
                         P('bwlimit', 'int', 'Bandwidth limit (KB/s, 0 = none)', 0, min=0, max=10_000_000, optional=True),
                         P('excludes', 'lines', 'Excludes', [], optional=True, placeholder='*.tmp\n.Trash-*\ncache/')]},
    'rotate': {'cat': 'copy', 'label': 'Rotating backup', 'text': 'back up {src} → {dst}, keep {keep}',
               'help': 'rsnapshot-style: each run is a dated folder under "Into"; unchanged files are hard links to the '
                       'previous run, so every folder is a full copy but only changes take space.',
               'params': [P('src_host', 'host', 'From host', '', optional=True), P('src', 'path', 'From', on='src_host'),
                          P('dst', 'path', 'Into (on this host)'), P('keep', 'int', 'Keep', 14, min=1, max=9999),
                          P('one_fs', 'bool', 'stay on one filesystem', True), P('sudo', 'bool', 'sudo rsync on the other host', True),
                          P('excludes', 'lines', 'Excludes', [], optional=True)]},
    'verify': {'cat': 'copy', 'label': 'Verify copy', 'text': 'compare {src} with {dst} by checksum',
               'params': [P('src_host', 'host', 'From host', '', optional=True), P('src', 'path', 'From', on='src_host'),
                          P('dst', 'path', 'Copy (on this host)'), P('fail', 'bool', 'fail when they differ', True),
                          P('sudo', 'bool', 'sudo rsync on the other host', True)]},
    'btrfs_snapshot': {'cat': 'snapshot', 'label': 'btrfs snapshot', 'text': 'snapshot {subvol} into {into}',
                       'params': [P('subvol', 'path', 'Subvolume'), P('into', 'path', 'Into folder', optional=True,
                                                                         placeholder='<subvolume>/.snapshots'),
                                  P('prefix', 'prefix', 'Name prefix', 'auto'), P('readonly', 'bool', 'read-only', True)]},
    'btrfs_prune': {'cat': 'snapshot', 'label': 'Prune btrfs snapshots', 'text': 'keep the newest {keep} {prefix}-* in {into}',
                    'params': [P('into', 'path', 'Snapshot folder'), P('prefix', 'prefix', 'Name prefix', 'auto'),
                               P('keep', 'int', 'Keep', 14, min=1, max=9999)]},
    'zfs_snapshot': {'cat': 'snapshot', 'label': 'ZFS snapshot', 'text': 'snapshot {dataset}',
                     'params': [P('dataset', 'dataset', 'Dataset', placeholder='tank/media'), P('prefix', 'prefix', 'Name prefix', 'auto'),
                                P('recursive', 'bool', 'with child datasets', False)]},
    'zfs_prune': {'cat': 'snapshot', 'label': 'Prune ZFS snapshots', 'text': 'keep the newest {keep} {dataset}@{prefix}-*',
                  'params': [P('dataset', 'dataset', 'Dataset'), P('prefix', 'prefix', 'Name prefix', 'auto'),
                             P('keep', 'int', 'Keep', 14, min=1, max=9999), P('recursive', 'bool', 'with child datasets', False)]},
    'btrfs_send': {'cat': 'snapshot', 'label': 'Send btrfs snapshots', 'text': 'send the newest {prefix}-* in {into} to {dst}',
                   'help': 'Sends the newest read-only snapshot with btrfs send, only the changes when both sides still share an '
                           'earlier one. Keep at least that one when you prune here. Older snapshots on this host are not sent. '
                           'Another host must be enrolled for deploys: each side is a signed run, and no root key is needed between them.',
                   'params': [P('into', 'path', 'Snapshot folder'), P('prefix', 'prefix', 'Name prefix', 'auto'),
                              P('dst_host', 'host', 'To host', '', optional=True), P('dst', 'path', 'Into folder', on='dst_host'),
                              P('keep', 'int', 'Keep there (0 = all)', 0, min=0, max=9999)]},
    'zfs_send': {'cat': 'snapshot', 'label': 'Send ZFS snapshots', 'text': 'send the newest {dataset}@{prefix}-* to {dst}',
                 'help': 'Sends the newest snapshot with zfs send, only the changes when both sides still share an earlier one. '
                         'It never overwrites a dataset it shares nothing with. Keep at least the shared one when you prune here. '
                         'Another host must be enrolled for deploys: each side is a signed run, and no root key is needed between them.',
                 'params': [P('dataset', 'dataset', 'Dataset'), P('prefix', 'prefix', 'Name prefix', 'auto'),
                            P('dst_host', 'host', 'To host', '', optional=True), P('dst', 'dataset', 'Into dataset', placeholder='backup/media'),
                            P('keep', 'int', 'Keep there (0 = all)', 0, min=0, max=9999), P('recursive', 'bool', 'with child datasets', False),
                            P('raw', 'bool', 'raw (stays encrypted, without its key)', False)]},
    'compose': {'cat': 'service', 'label': 'Docker compose', 'text': '{action} the {project} stack',
                'params': [P('project', 'unit', 'Compose project', placeholder='immich'),
                           P('action', 'select', 'Action', 'stop', choices=['stop', 'start', 'restart'])]},
    'service': {'cat': 'service', 'label': 'systemd service', 'text': '{action} {unit}',
                'params': [P('unit', 'unit', 'Unit', placeholder='smbd.service'),
                           P('action', 'select', 'Action', 'stop', choices=['stop', 'start', 'restart'])]},
    'mkdir': {'cat': 'other', 'label': 'Make folder', 'text': 'make folder {path}', 'params': [P('path', 'path', 'Folder')]},
    'scrub': {'cat': 'other', 'label': 'btrfs scrub', 'text': 'scrub {path}', 'params': [P('path', 'path', 'Mount point')]},
    'btrfs_balance': {'cat': 'other', 'label': 'btrfs reclaim space', 'text': 'pack half-empty chunks on {path}',
                      'help': 'A filtered balance: hands back space stuck in half-empty chunks, so writes never fail with "no space" while df shows room.',
                      'params': [P('path', 'path', 'Mount point'), P('dusage', 'int', 'Data chunks up to (% full)', 50, min=0, max=100),
                                 P('musage', 'int', 'Metadata chunks up to (% full)', 30, min=0, max=100)]},
    'command': {'cat': 'other', 'label': 'Run command', 'text': 'run: {cmd}',
                'help': 'A shell command, run as root with bash. Its failure fails the task (put it in a Try to allow it).',
                'params': [P('cmd', 'cmd', 'Command', placeholder='echo hello')]},
    'wait': {'cat': 'other', 'label': 'Wait', 'text': 'wait {seconds} s',
             'params': [P('seconds', 'int', 'Seconds', 30, min=1, max=86400)]},
    'log': {'cat': 'other', 'label': 'Log', 'text': 'log "{message}"', 'params': [P('message', 'text', 'Message')]},
}
SCHEDULES = {'': 'by hand only', 'hourly': 'hourly', '*-*-* 02:30:00': 'daily at 02:30', '*-*-* 00/6:00:00': 'every 6 hours',
             'Sun *-*-* 03:00:00': 'Sundays at 03:00', '*-*-01 04:00:00': 'monthly (the 1st, 04:00)'}


def _b(type_, slots=None, **params) -> dict:
    return {'type': type_, 'params': params, **({'slots': slots} if slots else {})}


TEMPLATES = [
    {'name': 'Nightly mirror', 'help': 'Copy a folder to a backup disk every night, deleting what was deleted.',
     'schedule': '*-*-* 02:30:00',
     'blocks': [_b('require_mounted', path=''), _b('rsync', src='', dst='', mode='mirror')]},
    {'name': 'btrfs snapshots', 'help': 'Snapshot a subvolume every hour and keep the newest 48.', 'schedule': 'hourly',
     'blocks': [_b('btrfs_snapshot', subvol='', prefix='hourly'), _b('btrfs_prune', into='', prefix='hourly', keep=48)]},
    {'name': 'ZFS snapshots', 'help': 'Snapshot a dataset every night and keep two weeks.', 'schedule': '*-*-* 02:30:00',
     'blocks': [_b('zfs_snapshot', dataset='', prefix='daily'), _b('zfs_prune', dataset='', prefix='daily', keep=14)]},
    {'name': 'btrfs replication', 'help': 'Snapshot a subvolume every night and send it to another host, changes only after the first.',
     'schedule': '*-*-* 02:30:00',
     'blocks': [_b('btrfs_snapshot', subvol='', prefix='daily'), _b('btrfs_send', into='', prefix='daily', dst_host='', dst='', keep=30),
                _b('btrfs_prune', into='', prefix='daily', keep=7)]},
    {'name': 'ZFS replication', 'help': 'Snapshot a dataset every night and send it to another host, changes only after the first.',
     'schedule': '*-*-* 02:30:00',
     'blocks': [_b('zfs_snapshot', dataset='', prefix='daily'), _b('zfs_send', dataset='', prefix='daily', dst_host='', dst='', keep=30),
                _b('zfs_prune', dataset='', prefix='daily', keep=7)]},
    {'name': 'Rotating backups', 'help': 'Pull a folder from another host into dated, hard-linked folders.',
     'schedule': '*-*-* 02:30:00',
     'blocks': [_b('require_mounted', path=''), _b('require_reachable', host=''), _b('rotate', src='', dst='', keep=14)]},
    {'name': 'Stop, snapshot, start', 'help': 'Stop a compose stack for a consistent btrfs snapshot, then copy the snapshot.',
     'schedule': '*-*-* 02:30:00',
     'blocks': [_b('try', {'do': [_b('compose', project='', action='stop'), _b('btrfs_snapshot', subvol='', prefix='app')],
                           'fallback': [_b('log', message='snapshot failed: starting the stack again')]}),
                _b('compose', project='', action='start'), _b('btrfs_prune', into='', prefix='app', keep=7)]},
    {'name': 'Monthly btrfs tidy', 'help': 'Reclaim space stuck in half-empty chunks on the first Sunday of the month, only when the disk is there.',
     'schedule': 'Sun *-*-01..07 04:00:00',
     'blocks': [_b('if', {'then': [_b('btrfs_balance', path='')], 'else': [_b('log', message='not mounted: no balance')]},
                   cond='mounted', arg='')]},
    {'name': 'Weekend scrub', 'help': 'Scrub a btrfs filesystem on Sundays, only when the disk is there.', 'schedule': 'Sun *-*-* 03:00:00',
     'blocks': [_b('if', {'then': [_b('scrub', path='')], 'else': [_b('log', message='not mounted: no scrub')]},
                   cond='mounted', arg='')]},
]


# ── normalize ───────────────────────────────────────────────────────────────
def _param(spec: dict, v, where: str):
    kind, label = spec['kind'], f'{where}: {spec["label"]}'
    if v is None or v == '' or v == []:
        if spec['kind'] == 'bool':
            return bool(spec['default'])
        if spec.get('optional') or spec['kind'] == 'host' and not spec.get('required'):
            return spec['default'] if spec['default'] is not None else ''
        if spec['kind'] in ('int', 'select') and spec['default'] is not None:
            return spec['default']
        return ''                               # required but empty: check() reports it, the script refuses it
    if kind == 'path':
        return _path(v, label)
    if kind == 'host':
        v = str(v).strip()
        if not HOST_RE.fullmatch(v):
            raise ValueError(f'{label} must be a host name or user@host')
        return v
    if kind == 'int':
        try:
            n = int(v)
        except (TypeError, ValueError):
            raise ValueError(f'{label} must be a whole number') from None
        if not spec.get('min', 0) <= n <= spec.get('max', 10**12):
            raise ValueError(f'{label} must be between {spec.get("min", 0)} and {spec.get("max")}')
        return n
    if kind == 'bool':
        return bool(v)
    if kind == 'select':
        if v not in spec['choices']:
            raise ValueError(f'{label} is one of {", ".join(spec["choices"])}')
        return v
    if kind == 'lines':
        lines = v.split('\n') if isinstance(v, str) else list(v)
        out = [str(x).strip() for x in lines if str(x).strip()]
        if len(out) > 100 or any(len(x) > 200 or '\n' in x for x in out):
            raise ValueError(f'{label}: up to 100 lines of up to 200 characters')
        return out
    if kind == 'cmd':
        v = str(v).replace('\r', '').strip()
        if len(v) > 4000:
            raise ValueError(f'{label} is too long')
        return v
    rx = {'prefix': PREFIX_RE, 'dataset': DATASET_RE, 'unit': UNIT_RE}.get(kind)
    v = str(v).strip()
    if rx and not rx.fullmatch(v):
        raise ValueError(f'{label}: {v!r} has characters it cannot have')
    if not rx and (len(v) > 300 or '\n' in v):
        raise ValueError(f'{label} must be one line')
    return v


def _blocks(raw, depth: int, count: list, where: str) -> list[dict]:
    if depth > MAX_DEPTH:
        raise ValueError(f'blocks nest at most {MAX_DEPTH} deep')
    out = []
    for i, b in enumerate(raw or [], 1):
        count[0] += 1
        if count[0] > MAX_BLOCKS:
            raise ValueError(f'a task holds at most {MAX_BLOCKS} blocks')
        t = TYPES.get((b or {}).get('type'))
        if not t:
            raise ValueError(f'{where} block {i}: unknown block type {(b or {}).get("type")!r}')
        here = f'{where}{i}'
        params = {s['name']: _param(s, (b.get('params') or {}).get(s['name']), f'block {here} ({t["label"]})') for s in t['params']}
        if b['type'] in ('rsync',) and params['src_host'] and params['dst_host']:
            raise ValueError(f'block {here}: one side of the copy must be the host the task runs on')
        nb = {'type': b['type'], 'params': params, 'off': bool(b.get('off')), 'note': str(b.get('note') or '')[:200]}
        if t.get('slots'):
            nb['slots'] = {s: _blocks((b.get('slots') or {}).get(s), depth + 1, count, f'{here}.') for s in t['slots']}
        out.append(nb)
    return out


def normalize(body: dict) -> dict:
    name = str(body.get('name') or '').strip()
    if not NAME_RE.fullmatch(name):
        raise ValueError('give the task a name (one line, up to 80 characters)')
    host = str(body.get('host') or '').strip()
    if host and not HOST_RE.fullmatch(host):
        raise ValueError('the task host must be a host name')
    schedule = ' '.join(str(body.get('schedule') or '').split())
    if schedule and not SCHEDULE_RE.fullmatch(schedule):
        raise ValueError('the schedule must be a systemd calendar time like "*-*-* 02:30:00" or "hourly"')
    count = [0]
    timeout = int(body.get('timeout_min') or 0)
    if not 0 <= timeout <= 7 * 24 * 60:
        raise ValueError('the timeout is 0 (none) to 10080 minutes')
    return {'name': name, 'host': host, 'schedule': schedule, 'description': str(body.get('description') or '')[:500],
            'timeout_min': timeout, 'blocks': _blocks(body.get('blocks'), 0, count, ''),
            'on_fail': _blocks(body.get('on_fail'), 0, count, 'on failure ')}


def has_command(task: dict) -> bool:
    """A Run command block or a "command succeeds" condition anywhere, switched off or not: its value is code, so it takes hosts.command."""
    def code(b: dict) -> bool:
        return b.get('type') == 'command' or (b.get('type') == 'if' and (b.get('params') or {}).get('cond') == 'command succeeds')

    def holds(blocks) -> bool:
        return any(code(b) or any(holds(v) for v in (b.get('slots') or {}).values()) for b in blocks or [])
    return holds(task.get('blocks')) or holds(task.get('on_fail'))


def walk(blocks, path=()):
    """(path, block) for every block in run order; path is a tuple of indices and slot names."""
    for i, b in enumerate(blocks):
        yield (*path, i), b
        for s, kids in (b.get('slots') or {}).items():
            yield from walk(kids, (*path, i, s))


# ── storage ─────────────────────────────────────────────────────────────────
def list_tasks(conn: Conn) -> list[dict]:
    out = []
    for tid, body, at, by in conn.all('SELECT task_id, body_json, updated_at, updated_by FROM storage_tasks ORDER BY name'):
        b = json.loads(body)
        out.append({'id': tid, 'name': b['name'], 'slug': slug(b['name']), 'host': b['host'], 'schedule': b['schedule'],
                    'blocks': sum(1 for _ in walk(b['blocks'])), 'hash': task_hash(b), 'updated_at': at, 'updated_by': by})
    return out


def get_task(conn: Conn, task_id: int) -> dict:
    rows = conn.all('SELECT task_id, body_json, updated_at FROM storage_tasks WHERE task_id = :i', {'i': task_id})
    if not rows:
        raise LookupError(f'no task #{task_id}')
    body = json.loads(rows[0][1])
    return {'id': rows[0][0], **body, 'slug': slug(body['name']), 'hash': task_hash(body), 'updated_at': rows[0][2]}


def save_task(conn: Conn, body: dict, actor: str, task_id: int | None = None) -> int:
    task = normalize(body)
    now = int(time.time())
    clash = conn.scalar('SELECT task_id FROM storage_tasks WHERE lower(name) = lower(:n)', {'n': task['name']})
    if clash and clash != task_id:
        raise ValueError(f'a task named "{task["name"]}" already exists')
    p = {'n': task['name'], 'b': json.dumps(task), 't': now, 'a': actor}
    with conn.tx():
        if task_id:
            if not conn.scalar('SELECT 1 FROM storage_tasks WHERE task_id = :i', {'i': task_id}):
                raise LookupError(f'no task #{task_id}')
            conn.execute('UPDATE storage_tasks SET name = :n, body_json = :b, updated_at = :t, updated_by = :a WHERE task_id = :i',
                         {**p, 'i': task_id})
            return task_id
        return conn.scalar("""INSERT INTO storage_tasks (name, body_json, created_at, updated_at, updated_by)
                              VALUES (:n, :b, :t, :t, :a) RETURNING task_id""", p)


def delete_task(conn: Conn, task_id: int):
    conn.execute('DELETE FROM storage_tasks WHERE task_id = :i', {'i': task_id})


# ── check against the index ─────────────────────────────────────────────────
def _label(b: dict) -> str:
    t = TYPES[b['type']]
    p = b['params']
    shown = {k: (v if v not in ('', None, []) else '…') for k, v in p.items()}
    if b['type'] in ('rsync', 'rotate', 'verify'):
        for side in ('src', 'dst'):
            h = p.get(side + '_host')
            if h:
                shown[side] = f'{h}:{p[side] or "…"}'
    try:
        return t['text'].format(**shown)
    except (KeyError, IndexError):
        return t['label']


def _copy_paths(p, host_of):
    return (('source', host_of(p.get('src_host', '')), p['src']), ('destination', host_of(p.get('dst_host', '')), p['dst']))


CONTAINER_PATHS = {'rsync': _copy_paths, 'rotate': _copy_paths,
                   'btrfs_snapshot': lambda p, host_of: (('subvolume', host_of(''), p['subvol']),)}


def removes_root(cmd: str) -> bool:
    """Whether a command line removes the root of the filesystem: rm, recursive, on / or everything in it. Every spelling
    seen: -rf, -fr, -R, -r -f, --recursive, --no-preserve-root, /*, /., after sudo or env, in any part of a; or && list."""
    for part in re.split(r'&&|\|\||[;|\n]', cmd):
        try:
            words = shlex.split(part, posix=True)
        except ValueError:
            words = part.split()
        while words and (words[0] in ('sudo', 'env', 'nice', 'ionice', 'doas', 'command', 'exec') or words[0].startswith('-') or '=' in words[0]):
            words = words[1:]                    # what runs rm: sudo -n, env X=1, nice -n 5
        if not words or words[0].rsplit('/', 1)[-1] != 'rm':
            continue
        recursive, targets, opts = False, [], True
        for w in words[1:]:
            if opts and w == '--':
                opts = False
            elif opts and w.startswith('--'):
                recursive |= w == '--recursive'
            elif opts and w.startswith('-') and len(w) > 1:
                recursive |= 'r' in w or 'R' in w
            else:
                targets.append(w)
        if recursive and any(t.rstrip('/') in ('', '/*', '/.') or t in ('/', '/*', '/.') for t in targets):
            return True
    return False


def check(conn: Conn, task: dict) -> dict:
    """Per block: [{level, text, fix?}] in run order. fix is a block the editor can insert before this one."""
    from .runtimes.docker import users_of
    task = normalize({**task, 'name': str(task.get('name') or '').strip() or 'untitled'})   # a draft may have no name yet
    hs = hosts(conn)
    home = find_host(hs, task['host']) if task['host'] else None
    out, general = [], []
    say = general.append
    if not task['host']:
        say({'level': 'crit', 'text': 'pick the host the task runs on'})
    elif not home:
        say({'level': 'warn', 'text': f'{task["host"]} has not been scanned: paths cannot be checked'})
    say({'level': 'note', 'text': f'runs {SCHEDULES.get(task["schedule"], task["schedule"])}' if task['schedule']
         else 'no schedule: it runs when you start it (Run now, or the script with --run)'})
    if not any(not b['off'] for _, b in walk(task['blocks'])):
        say({'level': 'warn', 'text': 'the task has no blocks yet'})

    def host_of(name):                          # '' = the task's host
        if not name:
            return home
        return find_host(hs, name.split('@')[-1])

    def info(h, path):
        if not h or not path:
            return None, None
        m = mount_of(h, path)
        return m, (m and m['state'] == 'indexed' and subtree(conn, m, path))

    def run(blocks, path, guards: set, mounted_ifs: set):
        for i, b in enumerate(blocks):
            here = (*path, i)
            items = []
            add = lambda level, text, fix=None: items.append({'level': level, 'text': text, **({'fix': fix} if fix else {})})   # noqa: E731
            p, t = b['params'], b['type']
            if b['off']:
                out.append({'path': list(here), 'label': _label(b), 'items': [{'level': 'note', 'text': 'turned off: skipped'}]})
                continue
            for s in TYPES[t]['params']:
                if (not s.get('optional') and (s['kind'] not in ('bool', 'host') or s.get('required'))
                        and p[s['name']] in ('', None, [])):
                    if not (t == 'btrfs_snapshot' and s['name'] == 'into'):
                        add('crit', f'{s["label"]} is empty')
            if t == 'require_mounted' and p['path']:
                m = home and mount_of(home, p['path'])
                if home and not any(x['target'] == p['path'] for x in home['mounts']):
                    add('warn', f'{p["path"]} is not a mount point in the last scan'
                        + (f' (it is inside {m["target"]})' if m else ''))
                elif home:
                    add('ok', f'{p["path"]} is mounted now ({next(x["fstype"] for x in home["mounts"] if x["target"] == p["path"])})')
                guards.add(p['path'])
            elif t == 'require_free' and p['path'] and home:
                m = mount_of(home, p['path'])
                if m and m['total']:
                    free = (m['total'] - (m['used'] or 0)) / 2**30
                    add('ok' if free >= p['gib'] else 'warn', f'{m["target"]} had {free:,.0f} GiB free at the last scan')
            elif t in ('rsync', 'rotate', 'verify'):
                sh, dh = host_of(p.get('src_host', '')), host_of(p.get('dst_host', ''))
                remote = p.get('src_host') or p.get('dst_host')
                if remote and not host_of(remote) and '@' not in remote:
                    add('warn', f'{remote} has not been scanned: give it as user@address if it is not')
                if remote:
                    add('note', f'root on {task["host"] or "the task host"} logs in to {remote} with its SSH key '
                                f'(/root/.ssh): set that up once (ssh-copy-id)')
                sm = sh and p['src'] and mount_of(sh, p['src'])
                ssize = sm and sm['state'] == 'indexed' and subtree(conn, sm, p['src'])
                if sh and p['src']:
                    if not sm:
                        add('warn', f'{p["src"]} is not on a scanned mount of {sh["name"]}')
                    elif sm['state'] == 'indexed' and not (ssize or {}).get('entries'):
                        add('warn', f'{p["src"]} is not in the index of {sh["name"]} (or is empty)')
                    elif ssize:
                        add('ok', f'{p["src"]}: {ssize["files"]:,} files, {ssize["bytes"] / 2**30:,.1f} GiB at the last scan')
                dm = dh and p['dst'] and mount_of(dh, p['dst'])
                if dm:
                    covered = guards | mounted_ifs
                    if dh is home and dm['target'] != '/' and dm['target'] not in covered:
                        add('warn', f'{p["dst"]} is on {dm["target"]}: if that disk is not mounted, the copy lands on the '
                                    f'system disk. Add "Require mounted {dm["target"]}" before this block',
                            {'type': 'require_mounted', 'params': {'path': dm['target']}})
                    if ssize and dm['total'] and t != 'verify':
                        free = dm['total'] - (dm['used'] or 0)
                        if ssize['bytes'] > free:
                            add('warn', f'{ssize["bytes"] / 2**30:,.0f} GiB to copy, {free / 2**30:,.0f} GiB free on {dm["target"]}')
                    if t == 'rotate' and (dm['fstype'] or '').lower() in ('cifs', 'smb3', 'vfat', 'exfat'):
                        add('crit', f'{dm["target"]} is {dm["fstype"]}: it has no hard links, so every run is a full copy')
                if sh is dh and sh and p['src'] and p['dst'] and (_under(p['dst'], p['src']) or _under(p['src'], p['dst'])):
                    add('crit', 'From and To overlap: the copy would copy itself')
                if (t == 'rsync' and p['mode'] == 'mirror' and sm and sm['target'] != '/' and sh is home
                        and sm['target'] not in guards | mounted_ifs):
                    add('warn', f'mirror deletes at the destination what is missing at the source: if {sm["target"]} is '
                                f'not mounted, the copy gets emptied. Add "Require mounted {sm["target"]}" first',
                        {'type': 'require_mounted', 'params': {'path': sm['target']}})
            elif t == 'btrfs_snapshot' and p['subvol'] and home:
                m = mount_of(home, p['subvol'])
                into = p['into'] or p['subvol'].rstrip('/') + '/.snapshots'
                im = mount_of(home, into)
                if m and (m['fstype'] or '').lower() != 'btrfs':
                    add('crit', f'{p["subvol"]} is on {m["fstype"]}, not btrfs')
                elif m and im and (im['source'] or '').split('[')[0] != (m['source'] or '').split('[')[0]:
                    add('crit', f'{into} is on another filesystem ({im["source"]}): snapshots must stay on {m["source"]}')
                elif m:
                    add('ok', f'snapshots of {p["subvol"]} go to {into}/{p["prefix"]}-<date>')
            elif t in ('zfs_snapshot', 'zfs_prune') and p['dataset'] and home:
                known = {(x['source'] or '').split('@')[0] for x in home['mounts'] if (x['fstype'] or '').lower() == 'zfs'}
                if known and p['dataset'] not in known:
                    add('warn', f'{p["dataset"]} is not a mounted dataset on {home["name"]} at the last scan')
            elif t in ('btrfs_send', 'zfs_send'):
                for level, text in receiving.check(conn, hs, home, p['dst_host'], t.split('_')[0], p['dst'], prefix=p['prefix']):
                    add(level, text)
                if p['dst_host'] and p['keep'] and not receiving.is_local(hs, home, p['dst_host']):
                    add('note', f'keeps the newest {p["keep"]} there: the signed run on the receiver holds that number, so this key cannot ask for fewer')
                if t == 'btrfs_send' and p['dst']:
                    dh = host_of(p['dst_host'])
                    dm = dh and mount_of(dh, p['dst'])
                    if dm and (dm['fstype'] or '').lower() != 'btrfs':
                        add('crit', f'{p["dst"]} is on {dm["fstype"]} on {dh["name"]}, not btrfs')
                if t == 'zfs_send' and p['dst'] and '/' not in p['dst']:
                    add('crit', f'{p["dst"]} is a whole pool, and receiving onto one means overwriting it: give pool/name')
            elif t in ('scrub', 'btrfs_balance') and p['path'] and home:
                m = mount_of(home, p['path'])
                if m and (m['fstype'] or '').lower() != 'btrfs':
                    add('crit', f'{p["path"]} is on {m["fstype"]}: {"scrub" if t == "scrub" else "balance"} is for btrfs')
            elif t == 'command' and p['cmd']:
                if removes_root(p['cmd']):
                    add('crit', 'this removes the root of the filesystem')
                add('note', 'runs as root with bash')
            elif t == 'if' and p['cond'] in ('mounted', 'exists', 'free below') and p['arg'] and not p['arg'].startswith('/'):
                add('crit', f'"{p["cond"]}" needs an absolute path')
            for side, h0, p0 in CONTAINER_PATHS.get(t, lambda *_: ())(p, host_of):
                names = sorted({u['container'] for u in users_of(conn, h0['name'], p0) if u['state'] == 'running'} if h0 and p0 else ())
                if names:
                    add('warn', f'{len(names)} running container(s) use the {side}: {", ".join(names[:6])}{" …" if len(names) > 6 else ""}. '
                                'Stop them first (a Docker compose block), or files can change while this runs')
            if TYPES[t].get('slots') and not any((b['slots'] or {}).values()):
                add('note', 'holds no blocks yet')
            out.append({'path': list(here), 'label': _label(b), 'items': items})
            if TYPES[t].get('slots'):
                for s, kids in b['slots'].items():
                    inner = set(mounted_ifs)
                    if t == 'if' and p['cond'] == 'mounted' and not p['negate'] and s == 'then':
                        inner.add(p['arg'])
                    run(kids, (*here, s), set(guards), inner)
    run(task['blocks'], (), set(), set())
    fails = []
    for i, b in enumerate(task['on_fail']):
        fails.append({'path': ['on_fail', i], 'label': _label(b), 'items': []})
    items = [x for blk in out for x in blk['items']] + general
    return {'task': task['name'], 'general': general, 'blocks': out + fails,
            'crit': sum(1 for x in items if x['level'] == 'crit'), 'warn': sum(1 for x in items if x['level'] == 'warn')}


# ── the Bash script ─────────────────────────────────────────────────────────
def _login(hs: dict, name: str) -> tuple[str, int]:
    """user@address and port for a host parameter: a scanned host's SSH login, or what was typed."""
    h = find_host(hs, name.split('@')[-1]) if name else None
    if '@' in name:
        return name, (h['ssh_port'] if h else 22)
    if h:
        return (f'{h["ssh_user"]}@{h["ssh_host"]}' if h['ssh_user'] else h['ssh_host']), h['ssh_port']
    return name, 22


class _Emit:
    def __init__(self, conn: Conn, hs: dict, task: dict, owner: str):
        self.conn, self.hs, self.task, self.owner, self.lines, self.n = conn, hs, task, owner, [], 0
        self.home = find_host(hs, task['host']) if task['host'] else None

    def local(self, name: str) -> bool:
        if not name:
            return True
        h = find_host(self.hs, name.split('@')[-1])
        return bool(h and self.home and h['id'] == self.home['id'])

    def w(self, depth: int, line: str):
        self.lines.append('  ' * depth + line)

    def rsync_side(self, host: str, path: str, sudo: bool) -> tuple[str, list[str]]:
        q = shlex.quote
        p = path.rstrip('/') + '/'
        if self.local(host):
            return q(p), []
        login, port = _login(self.hs, host)
        args = ['-e', q(f'ssh -p {int(port)} -o BatchMode=yes -o ConnectTimeout=15')]
        if sudo:
            args.append(q('--rsync-path=sudo rsync'))
        return q(f'{login}:{p}'), args

    def blocks(self, blocks: list, depth: int):
        for b in blocks:
            self.block(b, depth)

    def block(self, b: dict, d: int):
        q = shlex.quote
        p, t = b['params'], b['type']
        self.n += 1
        n, label = self.n, _label(b)
        if not b['off']:
            for spec in TYPES[t]['params']:
                if (not spec.get('optional') and (spec['kind'] not in ('bool', 'host') or spec.get('required'))
                        and p[spec['name']] in ('', None, [])
                        and not (t == 'btrfs_snapshot' and spec['name'] == 'into')):
                    raise ValueError(f'block {n} ({TYPES[t]["label"]}): {spec["label"]} is empty')
        if b['off']:
            self.w(d, f'step {self.n} {q(label + "  (turned off)")}; skip "turned off"')
            return
        self.w(d, f'step {self.n} {q(label)}')
        if t == 'require_mounted':
            self.w(d, f'need {q(p["path"] + " is mounted")} mountpoint -q -- {q(p["path"])}')
        elif t == 'require_free':
            what = f'{p["gib"]} GiB free on {p["path"]}'
            self.w(d, f'need {q(what)} free_ge {q(p["path"])} {int(p["gib"])}')
        elif t == 'require_reachable':
            login, port = _login(self.hs, p['host'])
            self.w(d, f'need {q(p["host"] + " answers SSH")} reach {q(login.split("@")[-1])} {int(port)}')
        elif t == 'if':
            self.w(d, f'if {self.cond(p)}; then')
            self.w(d + 1, 'info "condition holds: then"')
            self.blocks(b['slots']['then'], d + 1)
            self.w(d, 'else')
            self.w(d + 1, 'info "condition does not hold: else"')
            self.blocks(b['slots']['else'], d + 1)
            self.w(d, 'fi')
        elif t == 'try':
            self.w(d, '(')
            self.blocks(b['slots']['do'], d + 1)
            self.w(d + 1, ':')
            self.w(d, '); rc=$?')
            self.w(d, f'if ((rc == {STOP_OK})); then exit {STOP_OK}; elif ((rc)); then')
            self.w(d + 1, f'warnl "something in step {n} failed (exit $rc): running the fallback"')
            self.blocks(b['slots']['fallback'], d + 1)
            self.w(d + 1, ':')
            self.w(d, 'fi')
        elif t == 'stop':
            self.w(d, f'{"stop_ok" if p["outcome"] == "ok" else "fail"} {q(p["message"] or "stopped by the task")}')
        elif t in ('rsync', 'rotate', 'verify'):
            src, sargs = self.rsync_side(p.get('src_host', ''), p['src'], p.get('sudo', True))
            dst_host = p.get('dst_host', '') if t == 'rsync' else ''
            dst, dargs = self.rsync_side(dst_host, p['dst'], p.get('sudo', True))
            args = ['-aHAXS', '--filter=-x_system.*', '--filter=-x_security.selinux', '--numeric-ids', '--info=stats1', '--partial'] + sargs + dargs
            if p.get('one_fs'):
                args.append('-x')
            if p.get('checksum'):
                args.append('--checksum')
            if p.get('bwlimit'):
                args.append(f'--bwlimit={int(p["bwlimit"])}')
            args += [q(f'--exclude={e}') for e in p.get('excludes') or []]
            if t == 'rsync':
                if p['mode'] == 'mirror':
                    args.append('--delete-after')
                if self.local(dst_host):
                    self.w(d, f'x mkdir -p -- {q(p["dst"])} || fail {q("cannot make " + p["dst"])}')
                self.w(d, f'rs {" ".join(args)} {src} {dst} || fail "rsync failed (exit $?)"')
            elif t == 'rotate':
                self.w(d, f'rotate {q(p["dst"].rstrip("/"))} {int(p["keep"])} {src} {" ".join(args)} || fail "backup failed"')
            else:
                v = ['-aHAXSn', '--filter=-x_system.*', '--filter=-x_security.selinux', '--checksum', '--numeric-ids', '-i', '--delete'] + sargs + dargs
                self.w(d, f'verify_copy {1 if p["fail"] else 0} {" ".join(v)} {src} {dst} || fail "the copy differs"')
        elif t == 'btrfs_snapshot':
            into = p['into'] or p['subvol'].rstrip('/') + '/.snapshots'
            flag = '-r ' if p['readonly'] else ''
            self.w(d, f'x mkdir -p -- {q(into)} || fail {q("cannot make " + into)}')
            # a second run in the same second: btrfs would nest it inside the first, read-only, and say only "Read-only file system"
            self.w(d, f'while [[ -e {q(into)}/{q(p["prefix"])}-$STAMP ]]; do sleep 1; STAMP=$(date +%Y-%m-%d_%H%M%S); done')
            self.w(d, f'x btrfs subvolume snapshot {flag}-- {q(p["subvol"])} {q(into)}/{q(p["prefix"])}-"$STAMP" '
                      f'|| fail "snapshot failed"')
        elif t == 'btrfs_prune':
            self.w(d, f'prune_btrfs {q(p["into"])} {q(p["prefix"])} {int(p["keep"])} || fail "prune failed"')
        elif t == 'zfs_snapshot':
            self.w(d, f'x zfs snapshot {"-r " if p["recursive"] else ""}-- {q(p["dataset"] + "@" + p["prefix"])}-"$STAMP" '
                      f'|| fail "snapshot failed"')
        elif t == 'zfs_prune':
            self.w(d, f'prune_zfs {q(p["dataset"])} {q(p["prefix"])} {int(p["keep"])} {1 if p["recursive"] else 0} || fail "prune failed"')
        elif t in ('btrfs_send', 'zfs_send'):
            sid, addr, port = receiving.script_args(block_send(self.conn, self.hs, self.home, self.task, b, self.owner))
            if t == 'btrfs_send':
                self.w(d, f'send_btrfs {q(p["into"])} {q(p["prefix"])} {q(sid)} {q(addr)} {int(port)} {q(p["dst"])} {int(p["keep"])} || fail "send failed"')
            else:
                self.w(d, f'send_zfs {q(p["dataset"])} {q(p["prefix"])} {q(sid)} {q(addr)} {int(port)} {q(p["dst"])} {int(p["keep"])} '
                          f'{1 if p["recursive"] else 0} {1 if p["raw"] else 0} || fail "send failed"')
        elif t == 'compose':
            self.w(d, f'x docker compose -p {q(p["project"])} {p["action"]} || fail "docker compose {p["action"]} failed"')
        elif t == 'service':
            self.w(d, f'x systemctl {p["action"]} -- {q(p["unit"])} || fail "systemctl {p["action"]} failed"')
        elif t == 'mkdir':
            self.w(d, f'x mkdir -p -- {q(p["path"])} || fail {q("cannot make " + p["path"])}')
        elif t == 'scrub':
            self.w(d, f'x btrfs scrub start -B -- {q(p["path"])} || fail "scrub failed or found errors"')
        elif t == 'btrfs_balance':
            self.w(d, f'x btrfs balance start -dusage={int(p["dusage"])} -musage={int(p["musage"])} -- {q(p["path"])} || fail "balance failed"')
        elif t == 'command':
            self.w(d, f'xsh {q(p["cmd"])} || fail "the command failed (exit $?)"')
        elif t == 'wait':
            self.w(d, f'x sleep {int(p["seconds"])}')
        elif t == 'log':
            self.w(d, f'logmsg {q(p["message"])}')

    def cond(self, p: dict) -> str:
        q = shlex.quote
        c, a = p['cond'], p['arg']
        login, port = _login(self.hs, a) if c == 'host up' else ('', 22)
        expr = {
            'mounted': f'mountpoint -q -- {q(a)}',
            'exists': f'[[ -e {q(a)} ]]',
            'free below': f'! free_ge {q(a)} {int(p["value"] or 0)}',
            'weekday': f'[[ ,{q(a.replace(" ", ""))}, == *,$(date +%a),* ]]',
            'day of month': f'[[ ,{q(a.replace(" ", ""))}, == *,$(date +%-d),* ]]',
            'host up': f'reach {q(login.split("@")[-1])} {int(port)}',
            'command succeeds': f'bash -c {q(a)} >/dev/null 2>&1',
        }[c]
        return f'! {{ {expr}; }}' if p['negate'] else expr


def block_send(conn: Conn, hs: dict, home: dict | None, task: dict, b: dict, owner: str) -> dict:
    """What a Send block is to receiving.py."""
    p = b['params']
    return receiving.send(conn, hs, home, task['host'], p['dst_host'], b['type'].split('_')[0], p['dst'], owner, p['prefix'], p['keep'], p.get('recursive', False))


def _send_time(task: dict) -> dict:
    """A run that holds a send may take hours, and a deploy stopped halfway starts the send again from nothing."""
    return {'timeout': receiving.LONG_RUN} if any(b['type'] in ('btrfs_send', 'zfs_send') for _, b in (*walk(task['blocks']), *walk(task['on_fail']))) else {}


def sends(conn: Conn, task: dict, owner: str) -> list[dict]:
    """This task's sends to other hosts, in its blocks and in what runs when it fails. A block turned off sends nothing."""
    hs = hosts(conn)
    home = find_host(hs, task['host']) if task['host'] else None
    made = [block_send(conn, hs, home, task, b, owner) for _, b in (*walk(task['blocks']), *walk(task['on_fail'])) if b['type'] in ('btrfs_send', 'zfs_send') and not b['off']]
    return receiving.only_between_hosts(made)


@site.stamped
def script(conn: Conn, task: dict, owner: str | None = None) -> str:
    """owner: whose sends these are, when a schedule runs this task and keeps its own keys."""
    owner = owner or f't{task.get("id") or 0}'
    task = normalize(task)
    chk = check(conn, task)
    hs = hosts(conn)
    em = _Emit(conn, hs, task, owner)
    em.blocks(task['blocks'], 1)
    main = '\n'.join(em.lines) or '  info "no blocks"'
    em.lines = []
    em.blocks(task['on_fail'], 1)
    fail_body = '\n'.join(em.lines) or '  :'
    problems = [f'#   {x["level"].upper()}: {b["label"]}: {x["text"]}' for b in chk['blocks'] for x in b['items']
                if x['level'] in ('crit', 'warn')] + [f'#   {x["level"].upper()}: {x["text"]}' for x in chk['general']
                                                      if x['level'] in ('crit', 'warn')]
    outline = []

    def tree(blocks, depth):
        for b in blocks:
            outline.append('#   ' + '  ' * depth + ('(off) ' if b['off'] else '') + _label(b))
            for s, kids in (b.get('slots') or {}).items():
                outline.append('#   ' + '  ' * (depth + 1) + s + ':')
                tree(kids, depth + 2)
    tree(task['blocks'], 0)
    q = shlex.quote
    sl = slug(task['name'])
    return (TASK_HEAD.format(name=one_line(task['name']), slug=sl, host=task['host'] or '(any)',
                             date=dt.datetime.now().strftime('%Y-%m-%d %H:%M'),
                             schedule=task['schedule'] or 'none (by hand)', outline=comments(outline, '#   (no blocks)'),
                             problems=comments(problems, '#   none'))
            + f'TASK={q(sl)}\nTASK_NAME={q(task["name"])}\nTASK_HOST={q(host_slug(task["host"]) if task["host"] else "")}\n'
            + f'SCHEDULE={q(task["schedule"])}\nTIMEOUT_MIN={int(task["timeout_min"])}\n'
            + TASK_BODY_1 + HELPERS + RECEIVE_KIT + SEND_KIT + TASK_FUNCS + REMOTE.replace('sf-move', 'sf-task').replace('move.sh', 'task.sh')
            + f'\nmain() {{\n{main}\n}}\n\non_failure() {{\n{fail_body}\n}}\n' + TASK_TAIL)


def task_hash(task: dict) -> str:
    return hashlib.sha256(json.dumps(normalize(task), sort_keys=True).encode()).hexdigest()[:16]


def second_hops(task: dict) -> list[str]:
    """The machines this task's rsync blocks log in to with its host's own key, where nothing is signed. A send's other side is not one: see receivers."""
    task = normalize(task)
    return sorted({x for _, b in (*walk(task['blocks']), *walk(task['on_fail'])) if b['type'] not in ('btrfs_send', 'zfs_send')
                   for x in (b['params'].get(k) for k in ('src_host', 'dst_host')) if isinstance(x, str) and x})


def receivers(conn: Conn, task: dict) -> list[str]:
    """The hosts this task's sends reach, each through a signed run of its own: what the audit row of a deploy names."""
    return receiving.receivers(sends(conn, normalize(task), 't0'))


def deploy_items(db, conn: Conn, task: dict, mode: str, actor: str, run_now: bool = False, remove: bool = False) -> list[dict]:
    """deploy.start_group items. report: the dry run; apply: --install (--uninstall with remove); run_now: --run once.
    A task moved to another host is uninstalled from the host it was installed on."""
    from . import deploy
    owner = f't{task.get("id") or 0}'
    task = normalize(task)
    home = find_host(hosts(conn), task['host'])
    if not home:
        raise ValueError(f'{task["host"] or "the task host"} has not been scanned')
    sl, text = slug(task['name']), script(conn, task, owner=owner)
    wanted = sends(conn, task, owner)

    def mark(host, gone=False):
        def hook(_res):
            c = db.connect()
            try:
                if gone:
                    c.execute("DELETE FROM deployed WHERE host = :h AND kind = 'tasks' AND ref = :r", {'h': host, 'r': sl})
                else:
                    deploy.mark_deployed(c, host, 'tasks', sl, task_hash(task),
                                         {'name': task['name'], 'schedule': task['schedule'], 'id': task.get('id')}, actor)
            finally:
                c.close()
        return hook
    if run_now:          # the key goes again after a run of a task not installed here: nothing on a timer needs it
        stays = any(d['ref'] == sl and d['host'] == home['name'] for d in deploy.deployed(conn, kind='tasks'))
        before, after = receiving.items(db, conn, wanted, owner, 'apply', actor, task['name'], one_off=not stays)
        return [*before, {'host': home['name'], 'script': text, 'args': ['--run'], 'kind': 'tasks', 'ref': sl, 'mode': 'apply', **_send_time(task)}, *after]
    if mode != 'apply':
        before, _ = receiving.items(db, conn, wanted, owner, mode, actor, task['name'])
        return [*before, {'host': home['name'], 'script': text, 'args': [], 'kind': 'tasks', 'ref': sl, 'mode': 'report'}]
    before, after = receiving.items(db, conn, wanted, owner, mode, actor, task['name'], remove=remove)
    items = [*before, {'host': home['name'], 'script': text, 'args': ['--uninstall' if remove else '--install'], 'kind': 'tasks',
                       'ref': sl, 'mode': 'apply', 'on_ok': mark(home['name'], remove)}]
    for d in deploy.deployed(conn, kind='tasks'):
        if d['ref'] == sl and d['host'] != home['name']:
            items.append({'host': d['host'], 'script': text, 'args': ['--uninstall'], 'kind': 'tasks', 'ref': sl,
                          'mode': 'apply', 'on_ok': mark(d['host'], True)})
    return [*items, *after]


def installed(conn: Conn) -> dict:
    """slug → [{host, hash, at, by}] for tasks deployed with --install."""
    from . import deploy
    out: dict[str, list] = {}
    for d in deploy.deployed(conn, kind='tasks'):
        out.setdefault(d['ref'], []).append({'host': d['host'], 'hash': d['hash'], 'at': d['at'], 'by': d['by']})
    return out


TASK_HEAD = r"""#!/usr/bin/env bash
# task-{slug}.sh — StorageForge task "{name}", generated {date}.
# Runs on: {host}    Schedule: {schedule}
#
#   ./task-{slug}.sh                  read-only: checks the guards, prints what each block would run
#   sudo ./task-{slug}.sh --run       runs it now
#   sudo ./task-{slug}.sh --install   installs it as sf-task-{slug}.service (+ .timer when it has a schedule)
#   sudo ./task-{slug}.sh --uninstall removes the service and timer
#   ./task-{slug}.sh --host user@host [...]   the same, on that host over SSH
#
# Blocks:
{outline}
#
# Found when it was generated:
{problems}
"""

TASK_BODY_1 = r"""set -uo pipefail
export LC_ALL=C PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
MODE=report HOST=
ARGS=("$@")
while (($#)); do
  case $1 in
    --run) MODE=run ;;
    --install) MODE=install ;;
    --uninstall) MODE=uninstall ;;
    --host) HOST=${2:?--host needs user@host}; shift ;;
    --forward-agent) FWD_AGENT=1 ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done
DRY=1; [[ $MODE == run ]] && DRY=0
"""

TASK_FUNCS = r"""
STAMP=$(date +%Y-%m-%d_%H%M%S)
STEP=0
warnl() { printf '  %-9s %s\n' "${Y}warning${N0}" "$*"; }
step() { STEP=$1; section "$1. $2"; }
skip() { printf '  %-9s %s\n' "${B}skip${N0}" "$*"; }
show() { printf '%q ' "$@"; }
x() {   # an action: printed in the report, run with --run
  if ((DRY)); then doing "would run: $(show "$@")"; return 0; fi
  doing "$(show "$@")"; "$@"
}
xsh() { if ((DRY)); then doing "would run: $1"; return 0; fi; doing "$1"; bash -c "$1"; }
fail() { printf '  %-9s %s\n' "${R}failed${N0}" "step $STEP: $*"; exit 1; }
stop_ok() { ok "stopping: $*"; exit 100; }
logmsg() { info "$*"; ((DRY)) || logger -t "sf-task-$TASK" -- "$*" 2>/dev/null || true; }
need() {   # need <what> <test...>: a guard. The report goes on past a failed guard to show the rest.
  local what=$1; shift
  if "$@"; then ok "$what"; return 0; fi
  if ((DRY)); then conflict "not met: $what (a real run stops here)"; return 0; fi
  fail "not met: $what"
}
free_ge() { local a; a=$(df -P -B1G -- "$1" 2>/dev/null | awk 'NR == 2 {print $4}'); [[ -n $a ]] && ((a >= $2)); }
reach() { local h=${1#[}; h=${h%]}; timeout 5 bash -c "</dev/tcp/$h/$2" 2>/dev/null; }   # bash wants [v6] bare
rs() {   # rsync; "some files vanished" (24) is fine for live data
  x rsync "$@"; local rc=$?
  if ((rc == 24)); then warnl "some files vanished while copying"; rc=0; fi
  return $rc
}
rotate() {   # rotate <into> <keep> <src> <rsync args...>: dated, hard-linked copies, newest <keep> kept
  local into=$1 keep=$2 src=$3; shift 3
  local prev; prev=$(find "$into" -mindepth 1 -maxdepth 1 -type d -name '20??-??-??_??????' 2>/dev/null | sort | tail -n 1)
  x mkdir -p -- "$into" || return 1
  local left; mapfile -t left < <(find "$into" -mindepth 1 -maxdepth 1 -type d -name '20??-??-??_??????.partial' 2>/dev/null)     # left by a failed run: each run starts its own
  for o in "${left[@]}"; do x rm -rf --one-file-system -- "$o"; done
  if [[ -n $prev ]]; then info "unchanged files link to $(basename "$prev")"; set -- "$@" --link-dest="$prev"; fi
  rs "$@" --delete "$src" "$into/$STAMP.partial/" || return 1
  x mv -- "$into/$STAMP.partial" "$into/$STAMP" || return 1
  local old; mapfile -t old < <(find "$into" -mindepth 1 -maxdepth 1 -type d -name '20??-??-??_??????' 2>/dev/null | sort | head -n "-$keep")
  for o in "${old[@]}"; do x rm -rf --one-file-system -- "$o"; done
  ok "$(find "$into" -mindepth 1 -maxdepth 1 -type d -name '20??-??-??_??????' 2>/dev/null | wc -l) backups in $into"
}
verify_copy() {   # verify_copy <fail on difference 0|1> <rsync args...>
  local strict=$1; shift
  local out; out=$(rsync "$@" 2>&1); local rc=$?
  ((rc == 0 || rc == 24)) || { printf '%s\n' "$out" | tail -n 5; return 1; }
  local n; n=$(printf '%s\n' "$out" | grep -c '^[<>ch*]' || true)
  if ((n == 0)); then ok "the copy matches"; return 0; fi
  printf '%s\n' "$out" | grep '^[<>ch*]' | head -n 20 | sed 's/^/    /'
  warnl "$n entries differ"
  ((strict && !DRY)) && return 1 || return 0
}
snapname() {   # snapname <prefix> <name>: one this prefix made, <prefix>-YYYY-MM-DD_HHMMSS. Not daily-db-... for daily, nor daily-notes
  local rest=${2#"$1-"}
  [[ $2 == "$1-"* && $rest =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}_[0-9]{6}$ ]]
}
ours() {   # ours <prefix>: the names on stdin that this prefix made, in their order
  local n; while IFS= read -r n; do snapname "$1" "${n##*/}" && printf '%s\n' "$n"; done; return 0
}
prune_btrfs() {   # prune_btrfs <folder> <prefix> <keep>
  local old; mapfile -t old < <(find "$1" -mindepth 1 -maxdepth 1 -name "$2-*" 2>/dev/null | ours "$2" | sort | head -n "-$3")
  ((${#old[@]})) || { ok "nothing to prune in $1"; return 0; }
  for o in "${old[@]}"; do x btrfs subvolume delete -- "$o" || return 1; done
}
prune_zfs() {   # prune_zfs <dataset> <prefix> <keep> <recursive>
  local old r=; (($4)) && r=-r
  # -d 1: this dataset's own snapshots, dataset@name, and a dataset name never holds an @
  mapfile -t old < <(zfs list -H -t snapshot -o name -s creation -d 1 -- "$1" 2>/dev/null | cut -d@ -f2 | ours "$2" | sed "s|^|$1@|" | head -n "-$3")
  ((${#old[@]})) || { ok "nothing to prune on $1"; return 0; }
  for o in "${old[@]}"; do x zfs destroy $r -- "$o" || return 1; done
}
send_reach() {   # the other side of this send, as far as it can be seen from here. 1: a real run cannot go on, and this says why
  local out
  case $(send_state) in
    not-enrolled) if ((DRY)); then conflict "$S_ADDR $NOT_ENROLLED: a real run fails here"; else warnl "$S_ADDR $NOT_ENROLLED"; fi; return 1 ;;
    no-key) if ((DRY)); then missing "$NO_KEY"; else warnl "$NO_KEY"; fi; return 1 ;;
  esac
  out=$(there recv-probe 2>&1) && return 0
  if ((DRY)); then conflict "cannot run $S_TOOL on $(there_name): $(send_why "$out"): a real run fails here"; else warnl "cannot run $S_TOOL on $(there_name): $(send_why "$out")"; fi
  return 1
}
send_prune() {   # retention on the other side: how many and which names are in the signed conf over there, not in this script
  local n
  if ((DRY)); then
    while IFS= read -r n; do doing "$n on $(there_name)"; done < <(there recv-prune dry 2>/dev/null)
    return 0
  fi
  there recv-prune
}
send_btrfs() {   # send_btrfs <folder> <prefix> <send id> <address> <port> <into> <keep>
  local into=$1 prefix=$2 dest=$6 keep=$7 newest parent= n done_=0 names=() listing st want
  send_to btrfs "$3" "$4" "$5" "$dest" "$prefix" "$keep"
  newest=$(find "$into" -mindepth 1 -maxdepth 1 -name "$prefix-*" 2>/dev/null | ours "$prefix" | sort | tail -n 1); newest=${newest##*/}
  if [[ -z $newest ]]; then
    if ((DRY)); then info "no $prefix-* in $into yet: a real run sends the snapshot taken before this block"; return 0; fi
    warnl "no $prefix-* in $into to send"; return 1
  fi
  if ! send_reach; then
    ((DRY)) || return 1
    doing "would run: btrfs send $into/$newest | btrfs receive $dest on $(there_name)"; return 0
  fi
  if ! listing=$(there recv-list); then warnl "could not list $dest on $(there_name)"; ((DRY)) && return 0; return 1; fi
  mapfile -t names < <(printf '%s\n' "$listing" | sort -r)
  for n in ${names[@]+"${names[@]}"}; do   # newest first: an interrupted receive leaves a subvolume that was never finished
    [[ $n != */* ]] && snapname "$prefix" "$n" || continue     # the name came from the other host, and is about to be a path here
    if ((!done_)); then
      st=$(there recv-state "$n" 2>/dev/null)
      case $st in
        done\ *) done_=1 ;;
        partial) warnl "$n on the other side is unfinished: removing it"; x there recv-discard "$n" || return 1; continue ;;
        *) warnl "$n on the other side is not a snapshot of this send (${st:-no answer}): leaving it"; continue ;;
      esac
    fi
    if [[ -d $into/$n ]]; then parent=$n; break; fi
  done
  want=$(send_id_btrfs "$into/$newest")
  if [[ $parent == "$newest" ]]; then
    st=$(there recv-state "$newest" 2>/dev/null)
    if [[ -n $want && $st != "done $want" ]]; then warnl "$newest on the other side is another snapshot with this name (${st:-no answer}): leaving it"; ((DRY)) && return 0; return 1; fi
    ok "$newest is already there"
  else
    [[ -n $parent ]] && info "changes since $parent" || info "no shared snapshot: sending all of $newest"
    if ((DRY)); then doing "would run: btrfs send ${parent:+-p $into/$parent }$into/$newest | btrfs receive $dest on $(there_name)"
    else
      doing "btrfs send ${parent:+-p $into/$parent }$into/$newest | btrfs receive $dest on $(there_name)"
      there recv-mkdir || return 1
      send_stream "$newest" "$want" btrfs send ${parent:+-p "$into/$parent"} -- "$into/$newest" || return 1
      ok "sent $newest, and the copy there says it is this snapshot"
    fi
  fi
  ((keep)) || return 0
  send_prune
}
send_zfs() {   # send_zfs <dataset> <prefix> <send id> <address> <port> <into> <keep> <recursive> <raw>
  local ds=$1 prefix=$2 dest=$6 keep=$7 flags=() here=() names=() listing newest parent= n want st
  send_to zfs "$3" "$4" "$5" "$dest" "$prefix" "$keep" "$8"
  ((${8})) && flags+=(-R)
  ((${9})) && flags+=(-w)
  mapfile -t here < <(zfs list -H -t snapshot -o name -s creation -d 1 -- "$ds" 2>/dev/null | grep -F "$ds@" | cut -d@ -f2 | ours "$prefix")
  newest=; ((${#here[@]})) && newest=${here[${#here[@]}-1]}
  if [[ -z $newest ]]; then
    if ((DRY)); then info "no $ds@$prefix-* yet: a real run sends the snapshot taken before this block"; return 0; fi
    warnl "no $ds@$prefix-* to send"; return 1
  fi
  if ! send_reach; then
    ((DRY)) || return 1
    doing "would run: zfs send ${flags[*]-} $ds@$newest | zfs receive -u $dest on $(there_name)"; return 0
  fi
  if ! listing=$(there recv-list); then warnl "could not list $dest on $(there_name)"; ((DRY)) && return 0; return 1; fi
  mapfile -t names <<<"$listing"
  for ((n = ${#names[@]} - 1; n >= 0; n--)); do   # newest shared snapshot
    snapname "$prefix" "${names[n]}" || continue
    if printf '%s\n' "${here[@]}" | grep -xF -- "${names[n]}" >/dev/null; then parent=${names[n]}; break; fi
  done
  want=$(send_id_zfs "$ds@$newest")
  if [[ $parent == "$newest" ]]; then
    st=$(there recv-state "$newest" 2>/dev/null)
    if [[ -n $want && $st != "done $want" ]]; then warnl "$newest on the other side is another snapshot with this name (${st:-no answer}): leaving it"; ((DRY)) && return 0; return 1; fi
    ok "$newest is already there"
  else
    if [[ -z $parent && $(there recv-root 2>/dev/null) == present ]]; then
      if ((DRY)); then conflict "$dest exists there and shares no snapshot with $ds: a real run fails here"; return 0; fi
      warnl "$dest exists there and shares no snapshot with $ds: not overwriting it"; return 1
    fi
    [[ -n $parent ]] && { flags+=(-i "@$parent"); info "changes since $parent"; } || info "no shared snapshot: sending all of $newest"
    if ((DRY)); then doing "would run: zfs send ${flags[*]-} $ds@$newest | zfs receive -u $dest on $(there_name)"
    else
      doing "zfs send ${flags[*]-} $ds@$newest | zfs receive -u $dest on $(there_name)"
      send_stream "$newest" "$want" zfs send ${flags[@]+"${flags[@]}"} -- "$ds@$newest" || return 1
      ok "sent $newest, and the copy there says it is this snapshot"
    fi
  fi
  ((keep)) || return 0
  send_prune
}
"""

TASK_TAIL = r"""
UNIT=sf-task-$TASK
LIB=/usr/local/lib/storageforge/tasks
STATE=/var/lib/storageforge/tasks
if [[ $MODE == install || $MODE == uninstall ]]; then
  ((EUID == 0)) || { echo "run --$MODE as root (sudo)" >&2; exit 1; }
  if [[ -n $TASK_HOST && $(host_slug "$(hostname)") != "$TASK_HOST" ]]; then
    echo "note: this task was made for $TASK_HOST; this is $(hostname)" >&2
  fi
fi
case $MODE in
  install)
    section "Install $UNIT"
    if [[ -n $SCHEDULE ]] && ! systemd-analyze calendar "$SCHEDULE" >/dev/null 2>&1; then
      echo "systemd does not understand the schedule \"$SCHEDULE\"" >&2; exit 1
    fi
    install -D -m 0750 "$0" "$LIB/$TASK.sh" && ok "$LIB/$TASK.sh"
    label_exec "$LIB/$TASK.sh"
    mkdir -p "$STATE" && chmod 0755 "$STATE" 2>/dev/null || true
    {
      echo "[Unit]"
      echo "Description=StorageForge task: ${TASK_NAME//$'\n'/ }"
      echo "Wants=network-online.target"
      echo "After=network-online.target local-fs.target"
      echo "[Service]"
      echo "Type=oneshot"
      echo "ExecStart=$LIB/$TASK.sh --run"
      echo "Nice=10"
      echo "IOSchedulingClass=best-effort"
      echo "IOSchedulingPriority=7"
      ((TIMEOUT_MIN)) && echo "TimeoutStartSec=${TIMEOUT_MIN}min" || echo "TimeoutStartSec=infinity"
    } >"/etc/systemd/system/$UNIT.service" && ok "/etc/systemd/system/$UNIT.service"
    if [[ -n $SCHEDULE ]]; then
      printf '[Unit]\nDescription=Timer for %s\n[Timer]\nOnCalendar=%s\nPersistent=true\nRandomizedDelaySec=60\n[Install]\nWantedBy=timers.target\n' \
        "$UNIT" "$SCHEDULE" >"/etc/systemd/system/$UNIT.timer" && ok "/etc/systemd/system/$UNIT.timer ($SCHEDULE)"
    else
      rm -f "/etc/systemd/system/$UNIT.timer"
    fi
    reload_systemd || exit 1
    if [[ -n $SCHEDULE ]]; then
      systemctl enable --now "$UNIT.timer" >/dev/null && ok "timer on: next run $(systemctl show -p NextElapseUSecRealtime --value "$UNIT.timer" 2>/dev/null)"
    else
      systemctl disable --now "$UNIT.timer" >/dev/null 2>&1 || true
      info "no schedule: start it with systemctl start $UNIT (or Run now in StorageForge)"
    fi
    exit 0 ;;
  uninstall)
    section "Remove $UNIT"
    systemctl disable --now "$UNIT.timer" >/dev/null 2>&1 || true
    rm -f "/etc/systemd/system/$UNIT.service" "/etc/systemd/system/$UNIT.timer" "$LIB/$TASK.sh"
    reload_systemd || exit 1
    ok "removed (its run history stays in $STATE/$TASK.last and the journal)"
    exit 0 ;;
esac

LOCKS=/run/lock
if ((EUID != 0)) && [[ -n ${STORAGEFORGE_TASK_STATE:-} ]]; then STATE=$STORAGEFORGE_TASK_STATE LOCKS=$STORAGEFORGE_TASK_STATE; fi   # tests only
if ((!DRY)); then
  ((EUID == 0)) || [[ -n ${STORAGEFORGE_TASK_STATE:-} ]] || { echo "run --run as root (sudo)" >&2; exit 1; }
  mkdir -p "$STATE" "$LOCKS"
  exec 9>"$LOCKS/$UNIT.lock"
  flock -n 9 || { echo "$TASK_NAME is already running"; exit 0; }
  printf '%sStorageForge task "%s" — running%s\n' "$H" "$TASK_NAME" "$N0"
else
  printf '%sStorageForge task "%s" — report only (nothing is changed; --run to run it)%s\n' "$H" "$TASK_NAME" "$N0"
fi
started=$(date +%s)
( main ); rc=$?
((rc == 100)) && rc=0
if ((rc)) && ((!DRY)); then
  section "On failure"
  ( on_failure ) || true
fi
if ((!DRY)); then
  printf '{"task":"%s","rc":%d,"started":%d,"finished":%d}\n' "$TASK" "$rc" "$started" "$(date +%s)" >"$STATE/$TASK.last"
  printf '{"task":"%s","rc":%d,"started":%d,"finished":%d}\n' "$TASK" "$rc" "$started" "$(date +%s)" >>"$STATE/runs.jsonl" 2>/dev/null || true
  chmod 0644 "$STATE/$TASK.last" "$STATE/runs.jsonl" 2>/dev/null || true
fi
section "Done"
if ((rc)); then printf '  %-9s %s\n' "${R}failed${N0}" "exit $rc after $(( $(date +%s) - started )) s"
else ok "finished in $(( $(date +%s) - started )) s"; fi
exit $rc
"""
