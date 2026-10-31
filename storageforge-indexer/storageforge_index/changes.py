"""Staged change plans for filesystems, folders and drives: an ordered list of tasks, like an Ansible playbook.

Tasks are staged in the topology view (or written as JSON), checked against the index in order, and turned into
either a Bash script in the style of storage-setup.sh or a real Ansible playbook. StorageForge never changes a
host itself.

Each task type is described once in TYPES: its fields (which the UI builds its forms from), whether it destroys
data, and how it is checked. The script makes every task idempotent: it looks first and reports ok (already so),
missing (would do) or conflict (blocked), and only --apply acts. Drive tasks (partition, format, adding a device to
a pool) also need --destructive. fstab edits keep a backup and roll back when findmnt --verify rejects them. Nothing
is deleted: "trash" moves things into .storageforge-trash on the same filesystem, and a converted folder's original
goes there too.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import posixpath
import re
import shlex
import time

from .db import Conn
from .moves import _fmt, _path, find_host, host_slug, hosts, mount_of, slug, subtree
from .scriptkit import DEST_CMD, HELPERS, REMOTE, comments, host_name, one_line
from .tasks import HOST_RE, _login

PROFILES = ['single', 'dup', 'raid1', 'raid1c3', 'raid1c4', 'raid10', 'raid5', 'raid6']
MIN_DEVICES = {'single': 1, 'dup': 1, 'raid1': 2, 'raid1c3': 3, 'raid1c4': 4, 'raid10': 4, 'raid5': 2, 'raid6': 3}
MKFS = ['ext4', 'xfs', 'btrfs', 'vfat', 'exfat']
MOUNT_FS = ['btrfs', 'ext4', 'xfs', 'vfat', 'exfat', 'ntfs3', 'f2fs', 'nfs4', 'nfs', 'cifs', 'zfs', 'none']
LABEL_MAX = {'ext2': 16, 'ext3': 16, 'ext4': 16, 'xfs': 12, 'btrfs': 255, 'vfat': 11, 'exfat': 15}
OS_MOUNTS = ('/', '/boot', '/boot/efi', '/efi', '/usr', '/var')
ZPOOL_LEVELS = ['stripe', 'mirror', 'raidz1', 'raidz2', 'raidz3']
ZPOOL_MIN = {'stripe': 1, 'mirror': 2, 'raidz1': 3, 'raidz2': 4, 'raidz3': 5}


def F(name, kind, label, **kw):
    return {'name': name, 'kind': kind, 'label': label, **kw}


PATH, TARGET = F('path', 'path', 'Path', required=True), F('target', 'path', 'Mount point', required=True)
OWNER, GROUP, MODE = F('owner', 'user', 'Owner'), F('group', 'user', 'Group'), F('mode', 'mode', 'Mode', placeholder='0755')
CONFIRM = F('confirm', 'confirm', 'Type the device again to confirm', required=True)
DEVICES = F('devices', 'devices', 'Devices', required=True, placeholder='/dev/sdb /dev/sdc')
CONFIRM_ALL = F('confirm', 'confirm', 'Type the devices again to confirm', required=True)
TO_HOST = F('dest_host', 'host', 'To host', placeholder='this host, or nas-02, or root@10.0.0.9')
TYPES = {
    'dir': {'group': 'Files and folders', 'label': 'Create folder', 'fields': [PATH, OWNER, GROUP, MODE]},
    'rename': {'group': 'Files and folders', 'label': 'Rename or move', 'fields': [
        F('path', 'path', 'From', required=True), F('dest', 'path', 'To', required=True)],
        'help': 'Within one filesystem, where it is an instant rename. Use Moves to copy to another disk.'},
    'trash': {'group': 'Files and folders', 'label': 'Move to trash', 'fields': [PATH],
              'help': 'Moved to .storageforge-trash/<date>/ at the top of its filesystem. Nothing is deleted.'},
    'symlink': {'group': 'Files and folders', 'label': 'Create symlink', 'fields': [
        F('path', 'path', 'Link', required=True), F('target', 'path', 'Points to', required=True)]},
    'perms': {'group': 'Files and folders', 'label': 'Owner and permissions', 'fields': [
        PATH, OWNER, GROUP, MODE, F('recursive', 'bool', 'Owner and group for everything inside too')]},
    'subvolume': {'group': 'btrfs', 'label': 'Create subvolume', 'fields': [
        PATH, F('nocow', 'bool', 'No copy-on-write (VM images, databases)')]},
    'snapshot': {'group': 'btrfs', 'label': 'Snapshot a subvolume', 'fields': [
        F('source', 'path', 'Subvolume', required=True), F('dest', 'path', 'Snapshot at', required=True),
        F('readonly', 'bool', 'Read-only', default=True)]},
    'to-subvolume': {'group': 'btrfs', 'label': 'Turn a folder into a subvolume', 'fields': [PATH],
                     'help': 'Copies with reflinks (instant, no extra space), swaps it in, and trashes the original folder.'},
    'btrfs-add': {'group': 'btrfs', 'label': 'Add a device to a pool', 'destructive': True, 'fields': [
        F('device', 'device', 'New device', required=True), F('target', 'path', 'Pool mounted at', required=True),
        F('wipe', 'bool', 'It has a filesystem: overwrite it'), CONFIRM]},
    'btrfs-balance': {'group': 'btrfs', 'label': 'Convert profile (balance)', 'fields': [
        F('target', 'path', 'Pool mounted at', required=True), F('data', 'choice', 'Data', options=PROFILES, required=True),
        F('metadata', 'choice', 'Metadata', options=PROFILES, required=True)]},
    'scrub': {'group': 'btrfs', 'label': 'Scrub (verify checksums)', 'fields': [F('target', 'path', 'Mounted at', required=True)]},
    'btrfs-send': {'group': 'btrfs', 'label': 'Send a snapshot to another host', 'fields': [
        F('source', 'path', 'Read-only snapshot', required=True), F('parent', 'path', 'Earlier snapshot (sends only the changes)'),
        TO_HOST, F('dest', 'path', 'Into folder there', required=True)],
        'help': 'btrfs send piped to btrfs receive. The earlier snapshot must exist on both sides. Root on this host logs in to the other one with its SSH key.'},
    'zfs-pool': {'group': 'ZFS', 'label': 'Create a pool', 'destructive': True, 'fields': [
        F('pool', 'name', 'Pool name', required=True), F('level', 'choice', 'Layout', options=ZPOOL_LEVELS, required=True),
        DEVICES, F('mountpoint', 'path', 'Mount at'), F('wipe', 'bool', 'They have a filesystem: overwrite it'), CONFIRM_ALL],
        'help': 'Prefer stable names from /dev/disk/by-id: sdX names can change at boot.'},
    'zfs-dataset': {'group': 'ZFS', 'label': 'Create a dataset', 'fields': [
        F('dataset', 'dataset', 'Dataset', required=True, placeholder='tank/media'), F('mountpoint', 'path', 'Mount at'),
        F('options', 'options', 'Properties', placeholder='compression=zstd,recordsize=1M,quota=500G')],
        'help': 'Properties on a dataset that already exists are set to these values.'},
    'zfs-snapshot': {'group': 'ZFS', 'label': 'Snapshot a dataset', 'fields': [
        F('dataset', 'dataset', 'Dataset', required=True), F('name', 'name', 'Snapshot name', required=True),
        F('recursive', 'bool', 'With child datasets')]},
    'zfs-send': {'group': 'ZFS', 'label': 'Send a snapshot to another host', 'fields': [
        F('dataset', 'dataset', 'Dataset', required=True), F('name', 'name', 'Snapshot name', required=True),
        F('base', 'name', 'Earlier snapshot (sends only the changes)'), TO_HOST,
        F('dest', 'dataset', 'Into dataset there', required=True, placeholder='backup/media'),
        F('recursive', 'bool', 'With child datasets'), F('raw', 'bool', 'Raw (an encrypted dataset stays encrypted, without its key)')],
        'help': 'zfs send piped to zfs receive -u. It never overwrites: without an earlier snapshot the dataset there must not exist yet.'},
    'zfs-scrub': {'group': 'ZFS', 'label': 'Scrub a pool', 'fields': [F('pool', 'name', 'Pool name', required=True)]},
    'lvm-vg': {'group': 'LVM', 'label': 'Create a volume group', 'destructive': True, 'fields': [
        F('vg', 'name', 'Volume group', required=True), DEVICES, F('wipe', 'bool', 'They have a filesystem: overwrite it'), CONFIRM_ALL]},
    'lvm-vg-extend': {'group': 'LVM', 'label': 'Add a device to a volume group', 'destructive': True, 'fields': [
        F('vg', 'name', 'Volume group', required=True), F('device', 'device', 'New device', required=True),
        F('wipe', 'bool', 'It has a filesystem: overwrite it'), CONFIRM]},
    'lvm-lv': {'group': 'LVM', 'label': 'Create a logical volume', 'fields': [
        F('vg', 'name', 'Volume group', required=True), F('lv', 'name', 'Name', required=True),
        F('size', 'size', 'Size', required=True, placeholder='100G'), F('fstype', 'choice', 'Then format as', options=[''] + MKFS),
        F('label', 'label', 'Label')]},
    'lvm-extend': {'group': 'LVM', 'label': 'Grow a logical volume', 'fields': [
        F('vg', 'name', 'Volume group', required=True), F('lv', 'name', 'Name', required=True),
        F('size', 'size', 'New total size', required=True, placeholder='200G')],
        'help': 'Grows the volume and the filesystem on it to this total. It never shrinks.'},
    'lvm-snapshot': {'group': 'LVM', 'label': 'Snapshot a logical volume', 'fields': [
        F('vg', 'name', 'Volume group', required=True), F('lv', 'name', 'Volume', required=True), F('name', 'name', 'Snapshot name', required=True),
        F('size', 'size', 'Space for changes (empty for a thin volume)', placeholder='10G')],
        'help': 'A classic snapshot stops working if its space fills up, so size it for the changes you expect while you keep it.'},
    'mount': {'group': 'Mounts', 'label': 'Add a mount', 'fields': [
        F('source', 'spec', 'Source', required=True, placeholder='UUID=…, LABEL=…, server:/path or //server/share'),
        F('subvol', 'text', 'btrfs subvolume', placeholder='@Media'), TARGET,
        F('fstype', 'choice', 'Filesystem', options=MOUNT_FS, required=True),
        F('options', 'options', 'Options', placeholder='defaults,noatime,nofail')]},
    'mount-options': {'group': 'Mounts', 'label': 'Change mount options', 'fields': [
        TARGET, F('options', 'options', 'New options', required=True, placeholder='noatime,compress=zstd:3,nofail')]},
    'unmount': {'group': 'Mounts', 'label': 'Unmount', 'fields': [TARGET],
                'help': 'Unmounts it and comments out its fstab line. The folder and the data stay.'},
    'partition': {'group': 'Drives', 'label': 'Partition a disk', 'destructive': True, 'fields': [
        F('disk', 'device', 'Disk', required=True), F('fstype', 'choice', 'Then format as', options=[''] + MKFS),
        F('label', 'label', 'Label'), F('wipe', 'bool', 'It has partitions: replace them'), CONFIRM],
        'help': 'A new GPT with one partition spanning the disk.'},
    'format': {'group': 'Drives', 'label': 'Format', 'destructive': True, 'fields': [
        F('device', 'device', 'Device', required=True), F('fstype', 'choice', 'Filesystem', options=MKFS, required=True),
        F('label', 'label', 'Label'), F('wipe', 'bool', 'It has a filesystem: destroy it'), CONFIRM]},
    'label': {'group': 'Drives', 'label': 'Set filesystem label', 'fields': [
        F('target', 'path', 'Mount point or device', required=True), F('label', 'label', 'Label', required=True)]},
}
CHECKS = {
    'path': re.compile(r'/[^\0\n]*'), 'device': re.compile(r'/dev/[A-Za-z0-9/_.:+-]+'),
    'user': re.compile(r'[A-Za-z_][A-Za-z0-9_.-]{0,31}|\d{1,10}'), 'mode': re.compile(r'0?[0-7]{3,4}'),
    'options': re.compile(r'[A-Za-z0-9_=,.:/@+-]{0,400}'), 'label': re.compile(r'[A-Za-z0-9_.-]{0,64}'),
    'text': re.compile(r'[^\0\n]{0,200}'), 'host': HOST_RE,
    'devices': re.compile(r'/dev/[A-Za-z0-9/_.:+-]+( +/dev/[A-Za-z0-9/_.:+-]+){0,63}'),
    'name': re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.:+-]{0,127}'), 'dataset': re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.:/-]{0,199}'),
    'size': re.compile(r'\d{1,12}(\.\d{1,3})?[KMGTP]'),
    'spec': re.compile(r'(UUID|LABEL|PARTUUID|PARTLABEL)=[A-Za-z0-9_.-]+|/dev/[A-Za-z0-9/_.:+-]+|[A-Za-z0-9_.-]+:/[^\0\n ]*|//[^\0\n /]+/[^\0\n ]+'),
}


def title(t: dict) -> str:
    p, k = t['params'], t['type']
    return {
        'dir': lambda: f'Create folder {p["path"]}', 'rename': lambda: f'Rename {p["path"]} → {p["dest"]}',
        'trash': lambda: f'Move {p["path"]} to the trash', 'symlink': lambda: f'Link {p["path"]} → {p["target"]}',
        'perms': lambda: f'Owner and permissions of {p["path"]}', 'subvolume': lambda: f'Create subvolume {p["path"]}',
        'snapshot': lambda: f'Snapshot {p["source"]} → {p["dest"]}', 'to-subvolume': lambda: f'Turn {p["path"]} into a subvolume',
        'btrfs-add': lambda: f'Add {p["device"]} to the btrfs pool at {p["target"]}',
        'btrfs-balance': lambda: f'Convert {p["target"]} to {p["data"]}/{p["metadata"]}', 'scrub': lambda: f'Scrub {p["target"]}',
        'mount': lambda: f'Mount {p["source"]}{"[" + p["subvol"] + "]" if p.get("subvol") else ""} at {p["target"]}',
        'mount-options': lambda: f'Mount options of {p["target"]}: {p["options"]}', 'unmount': lambda: f'Unmount {p["target"]}',
        'partition': lambda: f'Partition {p["disk"]}' + (f' and format it {p["fstype"]}' if p.get('fstype') else ''),
        'format': lambda: f'Format {p["device"]} as {p["fstype"]}', 'label': lambda: f'Label {p["target"]} "{p["label"]}"',
        'btrfs-send': lambda: f'Send {p["source"]} to {p["dest_host"] or "this host"}:{p["dest"]}',
        'zfs-pool': lambda: f'Create ZFS pool {p["pool"]} ({p["level"]}) on {p["devices"]}',
        'zfs-dataset': lambda: f'Create ZFS dataset {p["dataset"]}', 'zfs-snapshot': lambda: f'Snapshot {p["dataset"]}@{p["name"]}',
        'zfs-send': lambda: f'Send {p["dataset"]}@{p["name"]} to {p["dest_host"] or "this host"}:{p["dest"]}',
        'zfs-scrub': lambda: f'Scrub ZFS pool {p["pool"]}', 'lvm-vg': lambda: f'Create volume group {p["vg"]} on {p["devices"]}',
        'lvm-vg-extend': lambda: f'Add {p["device"]} to volume group {p["vg"]}', 'lvm-lv': lambda: f'Create volume {p["vg"]}/{p["lv"]} ({p["size"]})',
        'lvm-extend': lambda: f'Grow {p["vg"]}/{p["lv"]} to {p["size"]}', 'lvm-snapshot': lambda: f'Snapshot {p["vg"]}/{p["lv"]} as {p["name"]}',
    }[k]()


def normalize(body: dict) -> dict:
    name = str(body.get('name') or '').strip()
    if not name or len(name) > 80 or '\n' in name:
        raise ValueError('give the plan a name (up to 80 characters)')
    tasks = []
    for i, t in enumerate(body.get('tasks') or [], 1):
        kind = t.get('type')
        spec = TYPES.get(kind)
        if not spec:
            raise ValueError(f'task {i}: unknown type {kind!r}')
        if not str(t.get('host') or '').strip():
            raise ValueError(f'task {i}: pick a host')
        host = host_name(t['host'], f'task {i}: the host')
        raw, params = t.get('params') or {}, {}
        for f in spec['fields']:
            v = raw.get(f['name'], f.get('default'))
            if f['kind'] == 'bool':
                params[f['name']] = bool(v)
                continue
            v = '' if v is None else str(v).strip()
            if not v:
                if f.get('required'):
                    raise ValueError(f'task {i} ({spec["label"]}): {f["label"]} is required')
                params[f['name']] = ''
                continue
            if f['kind'] == 'path':
                v = _path(v, f'task {i} {f["label"]}')
            elif f['kind'] == 'choice':
                if v not in f['options']:
                    raise ValueError(f'task {i}: {f["label"]} must be one of {", ".join(x for x in f["options"] if x)}')
            elif f['kind'] != 'confirm' and not CHECKS[f['kind']].fullmatch(v):
                raise ValueError(f'task {i} ({spec["label"]}): {f["label"]} {v!r} is not valid')
            params[f['name']] = v
        if spec.get('destructive'):
            if params.get('devices'):
                params['devices'] = ' '.join(params['devices'].split())
                params['confirm'] = ' '.join(params.get('confirm', '').split())
            dev = params.get('device') or params.get('disk') or params.get('devices')
            if params.get('confirm') != dev:
                raise ValueError(f'task {i} ({spec["label"]}): type {dev} again in the confirm field')
        tasks.append({'id': str(t.get('id') or f't{i}'), 'type': kind, 'host': host, 'params': params,
                      'note': one_line(t.get('note') or '')[:300]})
    return {'name': name, 'notes': str(body.get('notes') or '')[:2000], 'tasks': tasks}


# ── checks against the index, in plan order ─────────────────────────────
class Host:
    """What the index knows about one host, plus the effect of the tasks checked so far."""

    def __init__(self, conn: Conn, h: dict):
        from .payloads import apply_btrfs, apply_lvs, apply_zpool_status, node_from_lsblk, parse_zpool_status
        self.conn, self.h = conn, h
        inv = conn.scalar('SELECT inventory_json FROM hosts WHERE host_id = :h', {'h': h['id']})
        inv = (inv if isinstance(inv, dict) else json.loads(inv or '{}')) or {}
        self.node = node_from_lsblk(inv['lsblk'], h['name']) if inv.get('lsblk') else {'disks': [], 'pools': []}
        if inv.get('zpool_status'):
            apply_zpool_status(self.node, parse_zpool_status(inv['zpool_status']))
        if inv.get('lvs'):
            apply_lvs(self.node, inv['lvs'])
        if inv.get('btrfs'):
            apply_btrfs(self.node, inv['btrfs'])
        self.mounted = {m['target']: m for m in h['mounts'] if m['state'] != 'gone'}
        self.made, self.gone, self.subvols, self.unmounted = set(), set(), set(), set()
        self.new_zpools, self.new_vgs = set(), set()
        self.new_mounts: dict[str, dict] = {}

    def mount_at(self, path: str):
        """The mount holding path, counting mounts added and removed earlier in the plan."""
        best, fstype = None, None
        for t, m in list(self.mounted.items()) + list(self.new_mounts.items()):
            if t in self.unmounted and t not in self.new_mounts:
                continue
            if (t == '/' or path == t or path.startswith(t.rstrip('/') + '/')) and (best is None or len(t) > len(best)):
                best, fstype = t, m.get('fstype') or m.get('fs')
        return best, fstype

    def state(self, path: str) -> str:
        """'dir', 'file', 'link', 'missing', or 'unknown' when the index doesn't cover it."""
        for g in self.gone:
            if path == g or path.startswith(g + '/'):
                return 'missing'
        if path in self.made or path in self.new_mounts:
            return 'dir'
        if path in self.mounted and path not in self.unmounted:
            return 'dir'
        m = mount_of(self.h, path)
        if not m or m['state'] != 'indexed':
            return 'unknown'
        parent, name = posixpath.split(path)
        row = self.conn.all('SELECT f.is_directory, f.is_symlink FROM file_records f JOIN directories d ON d.dir_id = f.dir_id '
                            'WHERE d.mount_id = :m AND d.path = :p AND f.filename = :n', {'m': m['id'], 'p': parent, 'n': name})
        if not row:
            return 'missing'
        return 'link' if row[0][1] else 'dir' if row[0][0] else 'file'

    def size(self, path: str):
        m = mount_of(self.h, path)
        return subtree(self.conn, m, path) if m and m['state'] == 'indexed' else None

    def device(self, dev: str):
        name = dev.removeprefix('/dev/')
        for d in self.node['disks']:
            if d['dev'] == name:
                return {'kind': 'disk', 'disk': d, 'fs': None, 'parts': d['parts'], 'member': d.get('member')}
            for p in d['parts']:
                if p['dev'] == name:
                    return {'kind': 'part', 'disk': d, 'part': p, 'fs': p.get('fs'), 'member': p.get('member'), 'label': p.get('label')}
        return None

    def mounted_from(self, dev: str) -> list[str]:
        """Mount points using dev or a partition on it (LUKS mappers included through their partition)."""
        info = self.device(dev)
        names = {dev.removeprefix('/dev/')}
        if info and info['kind'] == 'disk':
            names |= {p['dev'] for p in info['parts']}
        crypt = {p.get('crypt') for d in self.node['disks'] for p in d['parts'] if p['dev'] in names and p.get('crypt')}
        out = []
        for t, m in self.mounted.items():
            src = (m.get('source') or '').split('[')[0].removeprefix('/dev/')
            if src in names or src.removeprefix('mapper/') in crypt:
                out.append(t)
        return sorted(out)

    def zpools(self) -> set:
        return {p['name'] for p in self.node['pools'] if p['type'] == 'zfs'} | self.new_zpools

    def vgs(self) -> set:
        return {p.get('vg') for p in self.node['pools'] if p['type'] == 'lvm'} | self.new_vgs

    def pool_devices(self, target: str) -> int:
        src = (self.mounted.get(target, {}).get('source') or '').split('[')[0].removeprefix('/dev/')
        for p in self.node['pools']:
            if p['type'] == 'btrfs' and (src in p['members'] or src == p['name']):
                return len(p['members'])
        return 1


def _users(conn, host, path):
    from .docker import users_of
    try:
        return sorted({u['container'] for u in users_of(conn, host, path) if u['state'] == 'running'})
    except Exception:
        return []


def check(conn: Conn, plan: dict) -> dict:
    hs, ctx, out = hosts(conn), {}, []
    for i, t in enumerate(plan['tasks'], 1):
        items = []
        say = lambda level, text: items.append({'level': level, 'text': text})   # noqa: E731
        h = find_host(hs, t['host'])
        if not h:
            out.append({'task': i, 'title': title(t), 'items': [{'level': 'crit', 'text': f'{t["host"]} has not been scanned'}]})
            continue
        c = ctx.setdefault(h['name'], Host(conn, h))
        p, k = t['params'], t['type']
        _check_task(conn, c, h, k, p, say)
        containers = []
        for key in ('path', 'source', 'target', 'dest'):
            if p.get(key) and k in ('rename', 'trash', 'to-subvolume', 'unmount', 'perms', 'mount-options'):
                containers += _users(conn, h['name'], p[key])
        if containers:
            names = sorted(set(containers))
            say('warn', f'running containers use this: {", ".join(names[:6])}{" …" if len(names) > 6 else ""}. Stop them first')
        if TYPES[k].get('destructive'):
            say('note', 'destroys data on the device: the script only does it with --apply --destructive')
        if k in ('btrfs-send', 'zfs-send') and p['dest_host']:
            say('note', f'root on {h["name"]} logs in to {p["dest_host"]} with its SSH key (/root/.ssh): set that up once (ssh-copy-id)')
        undo = {'unmount': ('mount', 'target'), 'trash': ('dir', 'path')}.get(k)
        if undo:
            for j, e in enumerate(plan['tasks'][:i - 1], 1):
                if e['type'] == undo[0] and e['host'] == t['host'] and e['params'].get(undo[1]) == p.get(undo[1]):
                    say('warn', f'undoes task {j}: every rerun of the script does both again. Drop one of them')
        out.append({'task': i, 'title': title(t), 'host': h['name'], 'items': items})
    levels = [x['level'] for t in out for x in t['items']]
    return {'tasks': out, 'crit': levels.count('crit'), 'warn': levels.count('warn')}


def _check_task(conn, c: Host, h: dict, k: str, p: dict, say):
    def parent_ok(path, what='parent folder'):
        par = posixpath.dirname(path)
        st = c.state(par)
        if st == 'missing':
            say('note', f'the {what} {par} does not exist yet: it is created')
        return st

    def same_fs(a, b):
        return c.mount_at(a)[0] == c.mount_at(b)[0]

    if k == 'dir':
        st = c.state(p['path'])
        if st == 'dir':
            say('ok', 'already exists: only owner and mode are checked')
        elif st in ('file', 'link'):
            say('crit', f'{p["path"]} exists and is a {st}')
        else:
            parent_ok(p['path'])
            say('ok' if st == 'missing' else 'note', f'creates {p["path"]}' + ('' if st == 'missing' else ' (not in the index; the script looks)'))
        c.made.add(p['path'])
    elif k in ('rename', 'trash', 'to-subvolume'):
        src = p['path']
        st = c.state(src)
        if st == 'missing':
            say('crit', f'{src} does not exist (or the last scan could not see it)')
        elif st == 'unknown':
            say('warn', f'{src} is not in the index; the script checks it')
        if src in c.mounted and src not in c.unmounted:
            say('crit', f'{src} is a mount point: unmount it instead')
        size = c.size(src) if st == 'dir' else None
        if size and size['entries']:
            say('ok', f'{size["files"]:,} files, {_fmt(size["bytes"])}')
        if k == 'rename':
            dst = p['dest']
            if c.state(dst) not in ('missing', 'unknown'):
                say('crit', f'{dst} already exists')
            elif parent_ok(dst) == 'missing':
                say('warn', f'create {posixpath.dirname(dst)} first (a Create folder task before this one)')
            if not same_fs(src, dst):
                say('crit', f'{dst} is on another filesystem ({c.mount_at(dst)[0]}): a Moves step copies between disks')
            else:
                say('note', 'same filesystem: an instant rename (unless it crosses a btrfs subvolume; the script checks)')
            c.gone.add(src)
            c.made.add(dst)
        elif k == 'trash':
            mnt = c.mount_at(src)[0]
            say('note', f'goes to {mnt.rstrip("/")}/.storageforge-trash/<date>/; the space returns when you empty that folder')
            c.gone.add(src)
        else:
            if c.mount_at(src)[1] != 'btrfs':
                say('crit', f'{src} is not on btrfs')
            if src in c.subvols:
                say('note', 'already a subvolume by then')
            c.subvols.add(src)
    elif k == 'symlink':
        st = c.state(p['path'])
        if st == 'link':
            say('note', 'a link exists there; the script reports a conflict if it points elsewhere')
        elif st in ('dir', 'file'):
            say('crit', f'{p["path"]} exists and is a {st}')
        if c.state(p['target']) == 'missing':
            say('warn', f'{p["target"]} does not exist: the link dangles until it does')
        c.made.add(p['path'])
    elif k == 'perms':
        st = c.state(p['path'])
        if st == 'missing':
            say('crit', f'{p["path"]} does not exist')
        if not (p['owner'] or p['group'] or p['mode']):
            say('crit', 'set an owner, a group or a mode')
        if p['recursive'] and st == 'dir':
            size = c.size(p['path'])
            if size:
                say('note', f'changes owner and group of {size["entries"]:,} entries')
    elif k in ('subvolume', 'snapshot'):
        path = p['path'] if k == 'subvolume' else p['dest']
        mnt, fstype = c.mount_at(path)
        if fstype != 'btrfs':
            say('crit', f'{posixpath.dirname(path)} is on {fstype or "an unknown filesystem"} ({mnt}), not btrfs')
        st = c.state(path)
        if st != 'missing' and st != 'unknown':
            say('crit', f'{path} already exists')
        parent_ok(path)
        if k == 'snapshot':
            src = p['source']
            smnt, sfs = c.mount_at(src)
            if sfs != 'btrfs':
                say('crit', f'{src} is not on btrfs')
            elif src not in c.subvols and not (src in c.mounted and 'subvol' in str(c.mounted[src].get('source', '')) or
                                               '[' in str(c.mounted.get(src, {}).get('source', ''))):
                say('warn', f'{src} must be a subvolume (a mounted subvolume or one created earlier in the plan); the script checks')
            src_dev = (c.mounted.get(smnt, {}).get('source') or '').split('[')[0]
            dst_dev = (c.mounted.get(mnt, {}).get('source') or '').split('[')[0]
            if src_dev and dst_dev and src_dev != dst_dev:
                say('crit', 'a snapshot must be on the same btrfs filesystem as its subvolume')
            say('ok', f'{"read-only" if p["readonly"] else "writable"} snapshot; it shares all data until files change')
        else:
            say('ok', 'new subvolume' + (' without copy-on-write' if p['nocow'] else ''))
        c.subvols.add(path)
        c.made.add(path)
    elif k == 'mount':
        tgt = p['target']
        if tgt in c.mounted and tgt not in c.unmounted:
            say('crit', f'{tgt} is already mounted ({c.mounted[tgt]["fstype"]}): change its options, or unmount it first')
        if p['subvol'] and p['fstype'] != 'btrfs':
            say('crit', 'a subvolume needs fstype btrfs')
        src = p['source']
        m = re.match(r'(UUID|LABEL)=(.+)', src)
        if m:
            key = m.group(1).lower()
            found = [x for d in c.node['disks'] for x in d['parts'] if (x.get(key) or '').lower() == m.group(2).lower()]
            found += [x for x in c.node['pools'] if (x.get(key) or '').lower() == m.group(2).lower()]
            if not found:
                say('warn', f'no device with {src} was seen by the last scan')
            elif found[0].get('fs') and found[0]['fs'] != p['fstype'] and p['fstype'] != 'none':
                say('warn', f'{src} holds {found[0]["fs"]}, not {p["fstype"]}')
            else:
                say('ok', f'{src} is {found[0].get("dev") or found[0].get("name")}')
        net = p['fstype'] in ('nfs', 'nfs4', 'cifs')
        opts = p['options'].split(',') if p['options'] else []
        if 'nofail' not in opts:
            say('note', 'without nofail, boot waits (and can stop) if it is missing')
        if net and '_netdev' not in opts:
            say('note', 'network mounts want _netdev (and x-systemd.automount)')
        st = c.state(tgt)
        if st == 'missing':
            say('note', f'{tgt} is created')
        elif st == 'dir':
            size = c.size(tgt)
            if size and size['entries'] > 1:
                say('warn', f'{tgt} already holds {size["files"]:,} files: they are hidden while it is mounted')
        c.new_mounts[tgt] = {'fstype': p['fstype'], 'source': src}
        c.unmounted.discard(tgt)
    elif k == 'mount-options':
        tgt = p['target']
        if tgt not in c.mounted and tgt not in c.new_mounts:
            say('crit', f'{tgt} is not mounted')
        else:
            cur = ','.join(o for o in str((c.mounted.get(tgt) or {}).get('options') or '').split(',') if o)
            say('ok', f'now: {cur or "?"}')
            if c.mount_at(tgt)[1] == 'btrfs':
                say('note', 'btrfs takes filesystem-wide options (compress, ...) from whichever subvolume mounts first')
    elif k == 'unmount':
        tgt = p['target']
        if tgt in OS_MOUNTS or tgt == '/home':
            say('crit', f'{tgt} belongs to the running system')
        if tgt not in c.mounted and tgt not in c.new_mounts:
            say('warn', f'{tgt} is not mounted now; only its fstab line is looked at')
        inside = [t for t in c.mounted if t != tgt and t.startswith(tgt.rstrip('/') + '/') and t not in c.unmounted]
        if inside:
            say('crit', f'mounted inside it: {", ".join(inside[:5])}. Unmount those first (earlier in the plan)')
        c.unmounted.add(tgt)
        c.new_mounts.pop(tgt, None)
    elif k in ('partition', 'format', 'btrfs-add'):
        dev = p.get('disk') or p.get('device')
        info = c.device(dev)
        if not info:
            say('crit', f'{dev} was not seen by the last scan of {h["name"]}')
            return
        if k == 'partition' and info['kind'] != 'disk':
            say('crit', f'{dev} is a partition; pick its disk')
        used = c.mounted_from(dev)
        if used:
            os_use = [u for u in used if u in OS_MOUNTS or u == '/home']
            say('crit', f'{dev} is in use: mounted at {", ".join(used[:6])}' + (' (the operating system disk)' if os_use else ''))
        if info.get('member') or (info['kind'] == 'disk' and any(x.get('member') for x in info['parts'])):
            say('crit', f'{dev} belongs to {info.get("member") or "a pool"}')
        if k == 'partition':
            if info['parts'] and not p['wipe']:
                say('crit', f'{dev} has {len(info["parts"])} partition(s): tick "replace them" to wipe it')
            elif info['parts']:
                say('warn', 'replaces: ' + ', '.join(f'{x["dev"]} ({x.get("fs") or "no fs"})' for x in info['parts']))
            size = info['disk'].get('size')
            say('ok', f'{info["disk"].get("model") or dev} · {_fmt(size)}' if size else dev)
        else:
            fs = info.get('fs') or (info['kind'] == 'disk' and info['parts'] and 'partitions') or None
            if fs and not p['wipe']:
                say('crit', f'{dev} holds {fs}: tick the box to destroy it')
            elif fs:
                say('warn', f'destroys the {fs} on {dev}' + (f' ("{info["label"]}")' if info.get('label') else ''))
            if k == 'btrfs-add':
                mnt, fstype = c.mount_at(p['target'])
                if fstype != 'btrfs' or mnt != p['target']:
                    say('crit', f'{p["target"]} is not a mounted btrfs filesystem')
                say('note', 'existing data stays on the old devices until a balance spreads it')
            elif p.get('label') and len(p['label']) > LABEL_MAX.get(p['fstype'], 64):
                say('crit', f'{p["fstype"]} labels are at most {LABEL_MAX[p["fstype"]]} characters')
    elif k == 'label':
        tgt = p['target']
        if tgt.startswith('/dev/'):
            info = c.device(tgt)
            fs = info and info.get('fs')
            if not info:
                say('crit', f'{tgt} was not seen by the last scan')
        else:
            mnt, fs = c.mount_at(tgt)
            if mnt != tgt:
                say('crit', f'{tgt} is not a mount point')
        if fs and len(p['label']) > LABEL_MAX.get(fs, 64):
            say('crit', f'{fs} labels are at most {LABEL_MAX[fs]} characters')
        if fs == 'xfs' and not tgt.startswith('/dev/'):
            say('crit', 'xfs labels change only while unmounted')
        if fs and fs not in LABEL_MAX:
            say('warn', f'labels on {fs} are not handled by the script')
    elif k in ('btrfs-balance', 'scrub'):
        mnt, fstype = c.mount_at(p['target'])
        if fstype != 'btrfs' or mnt != p['target']:
            say('crit', f'{p["target"]} is not a mounted btrfs filesystem')
        if k == 'btrfs-balance':
            n = c.pool_devices(p['target'])
            for kind in ('data', 'metadata'):
                need = MIN_DEVICES[p[kind]]
                if n < need:
                    say('crit', f'{p[kind]} needs {need} devices; this filesystem has {n}')
            if 'raid5' in (p['data'], p['metadata']) or 'raid6' in (p['data'], p['metadata']):
                say('warn', 'btrfs raid5/6 still has a write hole; raid1/raid1c3 is the safe choice')
            say('note', 'a balance runs in the background for hours; the script starts it (btrfs balance status follows it)')
        else:
            say('note', 'reads every block and checks it; runs in the background')
    elif k == 'btrfs-send':
        if c.mount_at(p['source'])[1] not in ('btrfs', None):
            say('crit', f'{p["source"]} is not on btrfs')
        if p['parent'] and p['parent'] == p['source']:
            say('crit', 'the earlier snapshot is the one being sent')
        other = find_host(hosts(conn), p['dest_host'].split('@')[-1]) if p['dest_host'] else h
        dm = other and mount_of(other, p['dest'])
        if p['dest_host'] and not other and '@' not in p['dest_host']:
            say('warn', f'{p["dest_host"]} has not been scanned: give it as user@address if it is not')
        if dm and (dm['fstype'] or '').lower() != 'btrfs':
            say('crit', f'{p["dest"]} is on {dm["fstype"]} on {other["name"]}, not btrfs')
        elif dm:
            say('ok', f'{p["dest"]} is on btrfs on {other["name"]}')
        say('note', 'the snapshot must be read-only: the script checks' + ('' if p['parent'] else '. No earlier snapshot, so all of it is copied'))
    elif k == 'zfs-pool':
        if p['pool'] in c.zpools():
            say('ok', f'pool {p["pool"]} already exists: nothing to do')
            return
        devs = p['devices'].split()
        if len(devs) < ZPOOL_MIN[p['level']]:
            say('crit', f'{p["level"]} needs at least {ZPOOL_MIN[p["level"]]} devices')
        _check_devices(c, h, devs, p['wipe'], say)
        if any(re.fullmatch(r'/dev/(sd[a-z]+|vd[a-z]+)\d*', d) for d in devs):
            say('warn', 'sdX names can change at boot: /dev/disk/by-id/... names are safer for a pool')
        c.new_zpools.add(p['pool'])
    elif k == 'zfs-dataset':
        pool = p['dataset'].split('/')[0]
        if c.zpools() and pool not in c.zpools():
            say('crit', f'there is no pool {pool} on {h["name"]}')
        elif not c.zpools():
            say('note', f'no ZFS pool in the last scan of {h["name"]}; the script checks')
        for o in filter(None, p['options'].split(',')):
            if '=' not in o:
                say('crit', f'{o} is not property=value')
    elif k in ('zfs-snapshot', 'zfs-scrub'):
        pool = (p.get('dataset') or p['pool']).split('/')[0]
        if c.zpools() and pool not in c.zpools():
            say('crit', f'there is no pool {pool} on {h["name"]}')
        elif k == 'zfs-scrub':
            say('note', 'reads every block and checks it; runs in the background')
    elif k == 'zfs-send':
        pool = p['dataset'].split('/')[0]
        if c.zpools() and pool not in c.zpools():
            say('crit', f'there is no pool {pool} on {h["name"]}')
        if '/' not in p['dest']:
            say('crit', f'{p["dest"]} is a whole pool, and receiving onto one means overwriting it: give pool/name')
        if p['base'] and p['base'] == p['name']:
            say('crit', 'the earlier snapshot is the one being sent')
        if p['dest_host'] and not find_host(hosts(conn), p['dest_host'].split('@')[-1]) and '@' not in p['dest_host']:
            say('warn', f'{p["dest_host"]} has not been scanned: give it as user@address if it is not')
        say('note', 'received with -u, so it is not mounted over anything there' + ('' if p['base'] else '. No earlier snapshot, so all of it is copied'))
    elif k in ('lvm-vg', 'lvm-vg-extend'):
        if k == 'lvm-vg' and p['vg'] in c.vgs():
            say('ok', f'volume group {p["vg"]} already exists: nothing to do')
            return
        _check_devices(c, h, p['devices'].split() if k == 'lvm-vg' else [p['device']], p['wipe'], say)
        if k == 'lvm-vg':
            c.new_vgs.add(p['vg'])
    elif k in ('lvm-lv', 'lvm-extend', 'lvm-snapshot'):
        if k == 'lvm-extend':
            say('note', 'only grows: a size at or below the current one changes nothing')
        elif k == 'lvm-snapshot' and p['size']:
            say('warn', f'if {p["size"]} of changes is reached while you keep it, the snapshot stops working: extend or remove it before then')
        elif k == 'lvm-snapshot':
            say('note', 'no size: this only works for a thin volume')
        if k == 'lvm-lv' and p['label'] and p['fstype'] and len(p['label']) > LABEL_MAX.get(p['fstype'], 64):
            say('crit', f'{p["fstype"]} labels are at most {LABEL_MAX[p["fstype"]]} characters')
        if c.vgs() - {None} and p['vg'] not in c.vgs():
            say('warn', f'volume group {p["vg"]} was not seen by the last scan; the script checks')


def _check_devices(c: Host, h: dict, devs: list, wipe: bool, say):
    """Devices about to join a ZFS pool or a volume group: seen by the scan, unused, overwritten only when allowed."""
    for dev in devs:
        info = c.device(dev)
        if not info:
            if dev.startswith('/dev/disk/') or dev.startswith('/dev/mapper/'):
                say('note', f'{dev}: the scan knows short names only; the script checks that it is free')
            else:
                say('crit', f'{dev} was not seen by the last scan of {h["name"]}')
            continue
        used = c.mounted_from(dev)
        if used:
            say('crit', f'{dev} is in use: mounted at {", ".join(used[:6])}')
        if info.get('member') or (info['kind'] == 'disk' and any(x.get('member') for x in info['parts'])):
            say('crit', f'{dev} belongs to {info.get("member") or "a pool"}')
        fs = info.get('fs') or (info['kind'] == 'disk' and info['parts'] and 'partitions') or None
        if fs and not wipe:
            say('crit', f'{dev} holds {fs}: tick the box to destroy it')
        elif fs:
            say('warn', f'destroys the {fs} on {dev}')


# ── storage ─────────────────────────────────────────────────────────────
def plan_hash(plan: dict) -> str:
    return hashlib.sha256(json.dumps(plan.get('tasks') or [], sort_keys=True).encode()).hexdigest()[:16]


def _ran_at(marks: list[dict], plan_id: int, plan: dict) -> int | None:
    """When this plan, as it is now, last finished on all its hosts. Editing it makes it a plan to run again."""
    from . import deploy
    return deploy.finished_at(marks, str(plan_id), plan_hash(plan))


def list_plans(conn: Conn) -> list[dict]:
    from . import deploy
    marks = deploy.deployed(conn, kind='changes')
    out = []
    for r in conn.all('SELECT plan_id, name, body_json, updated_at FROM change_plans ORDER BY name'):
        body = json.loads(r[2])
        out.append({'id': r[0], 'name': r[1], 'tasks': len(body.get('tasks') or []), 'updated_at': r[3],
                    'ran_at': _ran_at(marks, r[0], body)})
    return out


def get_plan(conn: Conn, plan_id: int) -> dict:
    from . import deploy
    rows = conn.all('SELECT plan_id, body_json, updated_at FROM change_plans WHERE plan_id = :i', {'i': plan_id})
    if not rows:
        raise LookupError(f'no change plan #{plan_id}')
    body = json.loads(rows[0][1])
    return {'id': rows[0][0], **body, 'updated_at': rows[0][2],
            'ran_at': _ran_at(deploy.deployed(conn, kind='changes'), rows[0][0], body)}


def save_plan(conn: Conn, body: dict, actor: str, plan_id: int | None = None) -> int:
    plan = normalize(body)
    now = int(time.time())
    clash = conn.scalar('SELECT plan_id FROM change_plans WHERE lower(name) = lower(:n)', {'n': plan['name']})
    if clash and clash != plan_id:
        raise ValueError(f'a plan named "{plan["name"]}" already exists')
    with conn.tx():
        if plan_id:
            if not conn.scalar('SELECT 1 FROM change_plans WHERE plan_id = :i', {'i': plan_id}):
                raise LookupError(f'no change plan #{plan_id}')
            conn.execute('UPDATE change_plans SET name = :n, body_json = :b, updated_at = :t, updated_by = :a WHERE plan_id = :i',
                         {'n': plan['name'], 'b': json.dumps(plan), 't': now, 'a': actor, 'i': plan_id})
            return plan_id
        return conn.scalar("""INSERT INTO change_plans (name, body_json, created_at, updated_at, updated_by)
                              VALUES (:n, :b, :t, :t, :a) RETURNING plan_id""",
                           {'n': plan['name'], 'b': json.dumps(plan), 't': now, 'a': actor})


def delete_plan(conn: Conn, plan_id: int):
    conn.execute('DELETE FROM change_plans WHERE plan_id = :i', {'i': plan_id})
    conn.execute("DELETE FROM deployed WHERE kind = 'changes' AND ref = :r", {'r': str(plan_id)})    # ids can be reused


# ── the Bash script ─────────────────────────────────────────────────────
ARGS = {'dir': ('path', 'owner', 'group', 'mode'), 'rename': ('path', 'dest'), 'trash': ('path',),
        'symlink': ('path', 'target'), 'perms': ('path', 'owner', 'group', 'mode', 'recursive'),
        'subvolume': ('path', 'nocow'), 'snapshot': ('source', 'dest', 'readonly'), 'to-subvolume': ('path',),
        'btrfs-add': ('device', 'target', 'wipe'), 'btrfs-balance': ('target', 'data', 'metadata'), 'scrub': ('target',),
        'mount': ('source', 'subvol', 'target', 'fstype', 'options'), 'mount-options': ('target', 'options'),
        'unmount': ('target',), 'partition': ('disk', 'fstype', 'label', 'wipe'), 'format': ('device', 'fstype', 'label', 'wipe'),
        'label': ('target', 'label'), 'btrfs-send': ('source', 'parent', 'dest'),
        'zfs-pool': ('pool', 'level', 'devices', 'mountpoint', 'wipe'), 'zfs-dataset': ('dataset', 'mountpoint', 'options'),
        'zfs-snapshot': ('dataset', 'name', 'recursive'), 'zfs-send': ('dataset', 'name', 'base', 'dest', 'recursive', 'raw'),
        'zfs-scrub': ('pool',), 'lvm-vg': ('vg', 'devices', 'wipe'), 'lvm-vg-extend': ('vg', 'device', 'wipe'),
        'lvm-lv': ('vg', 'lv', 'size', 'fstype', 'label'), 'lvm-extend': ('vg', 'lv', 'size'), 'lvm-snapshot': ('vg', 'lv', 'name', 'size')}


def deploy_items(db, conn: Conn, plan: dict, mode: str, actor: str, destructive: bool = False) -> list[dict]:
    """deploy.start_group items: the plan's script on each of its hosts, in the order the plan first uses them.
    An apply that ends clean on every host marks the plan as ran; one that skipped drive tasks has not finished."""
    from . import deploy
    plan_id, digest = plan.get('id'), plan_hash(plan)
    plan = normalize(plan)
    hs, order = hosts(conn), []
    for t in plan['tasks']:
        h = find_host(hs, t['host'])
        name = h['name'] if h else t['host']
        if name not in order:
            order.append(name)
    text = script(conn, plan)
    args = (['--apply'] + (['--destructive'] if destructive else [])) if mode == 'apply' else []

    def mark(host):
        def hook(res):
            if 'destructive, skipped' in res['output']:
                return
            c = db.connect()
            try:
                deploy.mark_deployed(c, host, 'changes', str(plan_id), digest, {'name': plan['name'], 'hosts': order}, actor)
            finally:
                c.close()
        return hook
    return [{'host': h, 'script': text, 'args': args, 'kind': 'changes', 'ref': plan['name'], 'mode': mode,
             **({'on_ok': mark(h)} if mode == 'apply' and plan_id else {})} for h in order]


def script(conn: Conn, plan: dict) -> str:
    plan = normalize(plan)
    hs, chk = hosts(conn), check(conn, plan)
    q = shlex.quote
    calls, summary = [], []
    for i, (t, c) in enumerate(zip(plan['tasks'], chk['tasks']), 1):
        h = find_host(hs, t['host'])
        args = [('1' if t['params'][a] else '') if isinstance(t['params'][a], bool) else t['params'][a] for a in ARGS[t['type']]]
        if t['type'] in ('btrfs-send', 'zfs-send'):        # the receiving side: empty login when that is this host
            there = t['params']['dest_host']
            same = not there or (h and find_host(hs, there.split('@')[-1]) is h)
            login, port = ('', 22) if same else _login(hs, there)
            args += [login, str(port)]
        calls.append(f'run {i} {q(host_slug(h["name"] if h else t["host"]))} {t["type"]} {q(title(t))} ' + ' '.join(q(a) for a in args))
        summary.append(f'#   {i:>2}. [{t["host"]}] {title(t)}' + ('   (destructive)' if TYPES[t['type']].get('destructive') else ''))
    problems = [f'#   task {x["task"]}: {it["level"].upper()}: {it["text"]}' for x in chk['tasks'] for it in x['items']
                if it['level'] in ('crit', 'warn')]
    return (CHANGE_HEAD.format(name=one_line(plan['name']), slug=slug(plan['name']),
                               date=dt.datetime.now().strftime('%Y-%m-%d %H:%M'), tasks=comments(summary, '#   (no tasks)'),
                               problems=comments(problems, '#   none'))
            + f'PLAN={q(slug(plan["name"]))}\n' + CHANGE_BODY_1 + HELPERS + DEST_CMD + CHANGE_BODY_2 + REMOTE + CHANGE_BODY_3
            + '\n'.join(calls) + CHANGE_TAIL)


CHANGE_HEAD = r"""#!/usr/bin/env bash
# changes-{slug}.sh — StorageForge change plan "{name}", generated {date}.
#
# Tasks, in order:
{tasks}
#
# What StorageForge flagged from the index when this was generated:
{problems}
#
#   ./changes-{slug}.sh                       report: what is already so, what would change, what is blocked
#                                             (read-only; run it with sudo to see into folders your user can't read)
#   sudo ./changes-{slug}.sh --apply          make the changes, in order; stops at the first task that fails
#   sudo ./changes-{slug}.sh --apply --destructive   also partition, format, create pools and add devices to them
#   --task N     only task N            --host [user@]host   run on that machine instead
#
# Every task looks before it acts, so rerunning is safe. fstab is backed up before each edit and restored if
# findmnt --verify rejects the result. Nothing is deleted: trashed paths go to .storageforge-trash/<date>/ at
# the top of their filesystem.
set -euo pipefail

"""

CHANGE_BODY_1 = r"""
MODE=check; ONLY=; HOST=; DESTRUCTIVE=0; ARGS=("$@")
while (($#)); do
  case $1 in
    --check|--report) MODE=check ;; --apply) MODE=apply ;; --destructive) DESTRUCTIVE=1 ;;
    --task) ONLY=${2:?--task needs a number}; shift ;;
    --host) HOST=${2:?--host needs [user@]host}; shift ;;
    --forward-agent) FWD_AGENT=1 ;;
    -h|--help) sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1 (try --help)" >&2; exit 2 ;;
  esac
  shift
done
"""

CHANGE_BODY_2 = r"""
PROBLEMS=0; STOPPED=0; CUR_DESTRUCTIVE=0
host_slug() { local n=${1%%.*}; n=$(tr 'A-Z' 'a-z' <<<"$n" | tr -cd 'a-z0-9_-'); echo "${n:-unknown}"; }
"""

CHANGE_BODY_3 = r"""
ME=$(host_slug "$(uname -n)")
APPLY=0; [[ $MODE == apply ]] && APPLY=1
if ((APPLY)) && [[ $EUID -ne 0 ]]; then echo "--apply needs root: sudo $0 ${ARGS[*]}" >&2; exit 1; fi
STAMP=$(date +%Y%m%d-%H%M%S); TODAY=$(date +%F)
STATE=/var/lib/storageforge/changes/$PLAN
if ((APPLY)); then
  exec 9>"/run/lock/sf-changes-$PLAN.lock" 2>/dev/null || exec 9>"/tmp/sf-changes-$PLAN.lock"
  flock -n 9 || { echo "another run of this plan is in progress" >&2; exit 1; }
  mkdir -p /var/log/storageforge; LOG=/var/log/storageforge/changes-$PLAN-$STAMP.log
  exec > >(tee -a "$LOG") 2>&1; echo "log: $LOG"
fi

# act DESCRIPTION: report it (check), refuse it (destructive without --destructive), or announce it and go on
act() {
  if ((!APPLY)); then missing "would: $*"; return 1; fi
  if ((CUR_DESTRUCTIVE && !DESTRUCTIVE)); then missing "destructive, skipped: $* (rerun with --apply --destructive)"; return 1; fi
  doing "$*"
}
try() { "$@" || { conflict "failed: $*"; return 1; }; }
# later MSG: something a task needs is not there yet. --apply: a conflict. The report can't know whether an earlier
# task in this plan creates it, so it says so instead of failing
later() { if ((APPLY)); then conflict "$*"; else missing "after the tasks before it: $*"; fi; }
need() { command -v "$1" >/dev/null || { conflict "$1 is not installed (package ${2:-$1})"; return 1; }; }
esc() { local s=${1// /\\040}; printf '%s' "${s//$'\t'/\\011}"; }
fstab_line() { awk -v t="$(esc "$1")" '!/^[[:space:]]*#/ && $2 == t' /etc/fstab; }
fstab_backup() { FSTAB_BAK=/etc/fstab.storageforge-$STAMP; [[ -e $FSTAB_BAK ]] || cp -a /etc/fstab "$FSTAB_BAK"; }
fstab_verify() {
  if findmnt --verify --tab-file /etc/fstab >/dev/null 2>&1; then systemctl daemon-reload 2>/dev/null || true; return 0; fi
  cp -a "$FSTAB_BAK" /etc/fstab; conflict "findmnt --verify rejected the edited /etc/fstab: restored $FSTAB_BAK"; return 1
}
fs_top() { # path -> the top folder of its filesystem or btrfs subvolume (where a rename stays a rename)
  local d; d=$(cd "$(dirname "$1")" && pwd -P)
  while [[ $d != / && $(stat -c %d "$(dirname "$d")") == $(stat -c %d "$d") ]]; do d=$(dirname "$d"); done
  printf '%s' "$d"
}
devs_guard() { # wipe-allowed devices... -> 0 if each is free and, unless allowed, holds no filesystem
  local wipe=$1 d have; shift
  for d in "$@"; do
    dev_guard "$d" || return 1
    have=$(blkid -p -o value -s TYPE -- "$d" 2>/dev/null || true)
    [[ -z $have || $wipe == 1 ]] || { conflict "$d holds $have; the plan does not allow overwriting it"; return 1; }
  done
}
dev_guard() { # device -> 0 if nothing on it is mounted, swapped on, or part of RAID/LVM/LUKS
  [[ -b $1 ]] || { conflict "$1 is not a block device on $(uname -n)"; return 1; }
  local used; used=$(lsblk -nro MOUNTPOINT "$1" | grep . | paste -sd' ' -) || true
  [[ -z $used ]] || { conflict "$1 is in use: $used"; return 1; }
  if lsblk -nro TYPE "$1" | tail -n +2 | grep -E 'raid|lvm|crypt' >/dev/null; then conflict "$1 holds RAID, LVM or LUKS volumes"; return 1; fi
}
part_of() { if [[ $1 =~ [0-9]$ ]]; then printf '%sp%s' "$1" "$2"; else printf '%s%s' "$1" "$2"; fi; }
mkfs_dev() { # device fstype label
  case $2 in
    ext4) need mkfs.ext4 e2fsprogs && mkfs.ext4 -q -F ${3:+-L "$3"} "$1" ;;
    xfs) need mkfs.xfs xfsprogs && mkfs.xfs -q -f ${3:+-L "$3"} "$1" ;;
    btrfs) need mkfs.btrfs btrfs-progs && mkfs.btrfs -q -f ${3:+-L "$3"} "$1" ;;
    vfat) need mkfs.vfat dosfstools && mkfs.vfat ${3:+-n "$3"} "$1" >/dev/null ;;
    exfat) need mkfs.exfat exfatprogs && mkfs.exfat ${3:+-L "$3"} "$1" >/dev/null ;;
  esac
}
owner_mode() { # path owner group mode recursive
  local p=$1 o=$2 g=$3 m=$4 r=$5
  [[ -e $p ]] || return 0
  # chown and chmod follow a link at the path itself: it would hand its target (/etc/shadow, say) to the new owner
  [[ -L $p ]] && { conflict "$p is a symbolic link: give the folder it points to instead"; return 1; }
  if [[ -n $o || -n $g ]]; then
    [[ -z $o ]] || id -u -- "$o" >/dev/null 2>&1 || { conflict "there is no user $o here"; return 1; }
    [[ -z $g ]] || getent group "$g" >/dev/null || { conflict "there is no group $g here"; return 1; }
    # Only what was asked: an empty owner or group stays as each file has it (chown alice, chown :staff), never
    # the group or owner of the top folder spread over everything inside.
    local want=$o${g:+:$g} off= q=() depth=(-maxdepth 0)
    [[ -n $o ]] && q+=(! -user "$o")
    [[ -n $g ]] && { [[ -n $o ]] && q+=(-o); q+=(! -group "$g"); }
    [[ $r == 1 ]] && depth=()
    off=$(find "$p" ${depth[@]+"${depth[@]}"} \( "${q[@]}" \) -print -quit 2>/dev/null)
    if [[ -z $off ]]; then ok "owner $want"; elif act "chown ${r:+-R }$want $p"; then try chown ${r:+-R} -- "$want" "$p" && ok "owner $want"; fi
  fi
  if [[ -n $m ]]; then
    if (( 8#$(stat -c %a "$p") == 8#$m )); then ok "mode $m"; elif act "chmod $m $p"; then try chmod -- "$m" "$p" && ok "mode $m"; fi
  fi
}

t_dir() { local p=$1
  if [[ -d $p ]]; then ok "$p exists"
  elif [[ -e $p ]]; then conflict "$p exists and is not a folder"; return 0
  elif act "mkdir -p $p"; then try mkdir -p -- "$p" && ok "created $p"; fi
  owner_mode "$p" "$2" "$3" "$4" ''
}
t_rename() { local s=$1 d=$2
  if [[ ! -e $s && ( -e $d || -L $d ) ]]; then ok "already at $d"; return 0; fi
  [[ -e $s || -L $s ]] || { later "$s must exist"; return 0; }
  [[ -e $d || -L $d ]] && { conflict "$d already exists"; return 0; }
  mountpoint -q -- "$s" && { conflict "$s is a mount point"; return 0; }
  [[ -d $(dirname "$d") ]] || { later "$(dirname "$d") must exist"; return 0; }
  [[ $(stat -c %d "$(dirname "$s")") == $(stat -c %d "$(dirname "$d")") ]] ||
    { conflict "$d is on another filesystem or btrfs subvolume: mv would copy every byte; use a Moves step"; return 0; }
  act "mv $s -> $d" && try mv -T -- "$s" "$d" && ok "renamed"
}
t_trash() { local p=$1 top rel dest
  if [[ ! -e $p && ! -L $p ]]; then
    if [[ -n $(find "$(fs_top "$p" 2>/dev/null)/.storageforge-trash" -maxdepth 8 -name "${p##*/}" -print -quit 2>/dev/null) ]]; then
      ok "$p is already in the trash"
    else later "$p must exist"; fi
    return 0
  fi
  mountpoint -q -- "$p" && { conflict "$p is a mount point"; return 0; }
  top=$(fs_top "$p"); rel=$(cd "$(dirname "$p")" && pwd -P)/${p##*/}; rel=${rel#"$top"/}
  dest="$top/.storageforge-trash/$TODAY/$rel"
  [[ -e $dest ]] && dest="$dest.$STAMP"
  if act "mv $p -> $dest"; then
    mkdir -p "$(dirname "$dest")" && chmod 700 "$top/.storageforge-trash"
    try mv -T -- "$p" "$dest" && ok "in the trash: $dest"
  fi
}
t_symlink() { local l=$1 t=$2
  if [[ -L $l ]]; then
    if [[ $(readlink -- "$l") == "$t" ]]; then ok "$l -> $t"; else conflict "$l points to $(readlink -- "$l"), not $t"; fi; return 0
  fi
  [[ -e $l ]] && { conflict "$l exists and is not a link"; return 0; }
  [[ -e $t ]] || info "$t does not exist yet: the link dangles until it does"
  act "ln -s $t $l" && { mkdir -p -- "$(dirname "$l")"; try ln -s -- "$t" "$l" && ok "linked"; }
}
t_perms() { [[ -e $1 ]] || { later "$1 must exist"; return 0; }; owner_mode "$@"; }
t_subvolume() { local p=$1
  need btrfs btrfs-progs || return 0
  if btrfs subvolume show -- "$p" >/dev/null 2>&1; then ok "subvolume $p exists"
  elif [[ -e $p ]]; then conflict "$p exists and is not a subvolume"; return 0
  else
    local par; par=$(dirname "$p"); while [[ ! -d $par ]]; do par=$(dirname "$par"); done
    [[ $(stat -f -c %T "$par") == btrfs ]] || { conflict "$par is not on btrfs"; return 0; }
    act "btrfs subvolume create $p" && { mkdir -p -- "$(dirname "$p")"; try btrfs subvolume create -- "$p" >/dev/null && ok "created"; } || return 0
  fi
  if [[ $2 == 1 && -d $p ]]; then
    if lsattr -d -- "$p" 2>/dev/null | cut -d' ' -f1 | grep C >/dev/null; then ok "no copy-on-write"
    elif act "chattr +C $p"; then try chattr +C -- "$p" && ok "no copy-on-write (for new files)"; fi
  fi
}
t_snapshot() { local s=$1 d=$2
  need btrfs btrfs-progs || return 0
  if btrfs subvolume show -- "$d" >/dev/null 2>&1; then ok "snapshot $d exists"; return 0; fi
  [[ -e $d ]] && { conflict "$d exists"; return 0; }
  btrfs subvolume show -- "$s" >/dev/null 2>&1 || { later "$s must be a btrfs subvolume"; return 0; }
  act "btrfs subvolume snapshot ${3:+-r }$s $d" &&
    { mkdir -p -- "$(dirname "$d")"; try btrfs subvolume snapshot ${3:+-r} -- "$s" "$d" >/dev/null && ok "snapshot taken"; }
}
t_to_subvolume() { local p=$1 new old a b
  need btrfs btrfs-progs || return 0
  if btrfs subvolume show -- "$p" >/dev/null 2>&1; then ok "$p is a subvolume"; return 0; fi
  [[ -d $p ]] || { later "$p must be a folder"; return 0; }
  mountpoint -q -- "$p" && { conflict "$p is a mount point"; return 0; }
  [[ $(stat -f -c %T "$p") == btrfs ]] || { conflict "$p is not on btrfs"; return 0; }
  act "turn $p into a subvolume (reflink copy, swap, original to the trash)" || return 0
  new="$p.sf-subvol-$STAMP"; old="$p.sf-folder-$STAMP"
  try btrfs subvolume create -- "$new" >/dev/null || return 0
  chown --reference="$p" -- "$new"; chmod --reference="$p" -- "$new"
  try cp -a --reflink=always -- "$p/." "$new/" || { conflict "left $new for you to inspect; $p is untouched"; return 0; }
  a=$(find "$p" | wc -l); b=$(find "$new" | wc -l)
  [[ $a == "$b" ]] || { conflict "the copy has $b entries, the folder $a: left $new for you to inspect; $p is untouched"; return 0; }
  try mv -T -- "$p" "$old" && try mv -T -- "$new" "$p" || return 0
  ok "$p is now a subvolume"
  t_trash "$old"
}
t_btrfs_add() { local dev=$1 tgt=$2
  need btrfs btrfs-progs || return 0
  if btrfs filesystem show -- "$tgt" 2>/dev/null | grep -E " path $dev\$" >/dev/null; then ok "$dev is in the pool"; return 0; fi
  [[ $(stat -f -c %T "$tgt" 2>/dev/null) == btrfs ]] && mountpoint -q -- "$tgt" || { later "$tgt must be a mounted btrfs filesystem"; return 0; }
  dev_guard "$dev" || return 0
  local have; have=$(blkid -p -o value -s TYPE -- "$dev" 2>/dev/null || true)
  [[ -n $have && $3 != 1 ]] && { conflict "$dev holds $have; the plan doesn't allow overwriting it"; return 0; }
  act "btrfs device add $dev $tgt" && try btrfs device add ${3:+-f} -- "$dev" "$tgt" &&
    { ok "added"; info "existing data stays where it is until a balance spreads it"; }
}
t_btrfs_balance() { local tgt=$1 d=$2 m=$3 cd cm
  need btrfs btrfs-progs || return 0
  cd=$(btrfs filesystem df -- "$tgt" 2>/dev/null | awk -F'[ ,:]+' '/^Data/ {print tolower($2); exit}')
  cm=$(btrfs filesystem df -- "$tgt" 2>/dev/null | awk -F'[ ,:]+' '/^Metadata/ {print tolower($2); exit}')
  if [[ $cd == "$d" && $cm == "$m" ]]; then ok "$tgt is $d/$m"; return 0; fi
  if btrfs balance status -- "$tgt" 2>/dev/null | grep running >/dev/null; then ok "a balance is running on $tgt"; return 0; fi
  act "btrfs balance start --bg -dconvert=$d -mconvert=$m $tgt (now ${cd:-?}/${cm:-?})" &&
    try btrfs balance start --bg -dconvert="$d" -mconvert="$m" -- "$tgt" >/dev/null && ok "started: btrfs balance status $tgt"
}
t_scrub() { local tgt=$1
  need btrfs btrfs-progs || return 0
  if btrfs scrub status -- "$tgt" 2>/dev/null | grep -i 'running' >/dev/null; then ok "a scrub is running"; return 0; fi
  if [[ -e $STATE/scrub-${tgt//\//_} ]]; then ok "started $(cat "$STATE/scrub-${tgt//\//_}"): btrfs scrub status $tgt"; return 0; fi
  act "btrfs scrub start $tgt" && try btrfs scrub start -- "$tgt" >/dev/null &&
    { mkdir -p "$STATE"; date '+%F %T' >"$STATE/scrub-${tgt//\//_}"; ok "started: btrfs scrub status $tgt"; }
}
t_mount() { local src=$1 sv=$2 tgt=$3 fs=$4 opts=$5 line have
  [[ -n $sv ]] && opts="subvol=$sv${opts:+,$opts}"
  line="$(esc "$src") $(esc "$tgt") $fs ${opts:-defaults} 0 0"
  have=$(fstab_line "$tgt")
  if [[ -n $have ]]; then
    if [[ $(awk '{print $1, $3}' <<<"$have") == "$(esc "$src") $fs" ]]; then ok "fstab: $have"
    else conflict "fstab has another line for $tgt: $have"; return 0; fi
  elif act "add to /etc/fstab: $line"; then
    fstab_backup; mkdir -p -- "$tgt"; printf '%s\n' "$line" >>/etc/fstab; fstab_verify || return 0; ok "fstab line added"
  else return 0; fi
  if mountpoint -q -- "$tgt"; then ok "mounted"
  elif act "mount $tgt"; then try mount -- "$tgt" && ok "mounted"; fi
}
t_mount_options() { local tgt=$1 new=$2 have cur keep
  have=$(fstab_line "$tgt")
  [[ -n $have ]] || { later "/etc/fstab needs a line for $tgt"; return 0; }
  cur=$(awk '{print $4}' <<<"$have")
  keep=$(tr ',' '\n' <<<"$cur" | grep -E '^subvol(id)?=' | paste -sd, -) || true   # never lose the subvolume
  new=$(tr ',' '\n' <<<"$new" | grep -vE '^subvol(id)?=' | paste -sd, -)
  new=${keep:+$keep,}$new
  if [[ $cur == "$new" ]]; then ok "options $cur"; return 0; fi
  act "options of $tgt: $cur -> $new" || return 0
  fstab_backup
  awk -v t="$(esc "$tgt")" -v o="$new" 'BEGIN {OFS="\t"} !/^[[:space:]]*#/ && $2 == t {$4 = o} {print}' /etc/fstab >"/etc/fstab.sf-new"
  cat "/etc/fstab.sf-new" >/etc/fstab; rm -f "/etc/fstab.sf-new"
  fstab_verify || return 0
  ok "fstab updated"
  if mountpoint -q -- "$tgt"; then mount -o remount -- "$tgt" 2>/dev/null && ok "remounted" ||
    info "remount refused (some options need a full unmount): they apply on the next mount"; fi
}
t_unmount() { local tgt=$1 have inner
  have=$(fstab_line "$tgt")
  if ! mountpoint -q -- "$tgt" && [[ -z $have ]]; then ok "not mounted, no fstab line"; return 0; fi
  inner=$(findmnt -rn -o TARGET | awk -v t="$tgt/" 'index($0, t) == 1' | paste -sd' ' -) || true
  [[ -z $inner ]] || { conflict "mounted inside $tgt: $inner"; return 0; }
  if mountpoint -q -- "$tgt" && act "umount $tgt"; then try umount -- "$tgt" || return 0; ok "unmounted"; fi
  if [[ -n $have ]] && act "comment out the fstab line for $tgt"; then
    fstab_backup
    awk -v t="$(esc "$tgt")" -v tag="# storageforge-disabled $TODAY: " '!/^[[:space:]]*#/ && $2 == t {print tag $0; next} {print}' \
      /etc/fstab >"/etc/fstab.sf-new"; cat "/etc/fstab.sf-new" >/etc/fstab; rm -f "/etc/fstab.sf-new"
    fstab_verify && ok "fstab line commented out"
  fi
}
t_partition() { local disk=$1 fs=$2 label=$3 wipe=$4 n part
  need parted parted || return 0
  part=$(part_of "$disk" 1); n=$(lsblk -nro TYPE -- "$disk" 2>/dev/null | grep -c part || true)
  if ((n == 1)) && [[ -b $part ]] && [[ -z $fs || $(blkid -p -o value -s TYPE -- "$part" 2>/dev/null) == "$fs" ]]; then
    ok "$disk has one partition${fs:+ with $fs}"; return 0; fi
  dev_guard "$disk" || return 0
  ((n == 0)) || [[ $wipe == 1 ]] || { conflict "$disk has $n partition(s); the plan doesn't allow replacing them"; return 0; }
  act "new GPT on $disk with one partition${fs:+, formatted $fs}" || return 0
  try wipefs -aq -- "$disk" && try parted -s -- "$disk" mklabel gpt mkpart primary 1MiB 100% || return 0
  partprobe -- "$disk" 2>/dev/null || true; udevadm settle 2>/dev/null || true
  for _ in 1 2 3 4 5 6 7 8 9 10; do [[ -b $part ]] && break; sleep 0.5; done
  [[ -b $part ]] || { conflict "$part did not appear"; return 0; }
  ok "partitioned: $part"
  [[ -n $fs ]] && { mkfs_dev "$part" "$fs" "$label" && ok "formatted $part as $fs" || conflict "mkfs.$fs $part failed"; }
}
t_format() { local dev=$1 fs=$2 label=$3 wipe=$4 have
  have=$(blkid -p -o value -s TYPE -- "$dev" 2>/dev/null || true)
  if [[ $have == "$fs" && ( -z $label || $(blkid -p -o value -s LABEL -- "$dev" 2>/dev/null) == "$label" ) ]]; then ok "$dev is $fs"; return 0; fi
  dev_guard "$dev" || return 0
  [[ -z $have || $wipe == 1 ]] || { conflict "$dev holds $have; the plan doesn't allow destroying it"; return 0; }
  act "mkfs.$fs ${label:+-L $label }$dev${have:+ (destroys its $have)}" || return 0
  [[ -n $have ]] && { try wipefs -aq -- "$dev" || return 0; }
  mkfs_dev "$dev" "$fs" "$label" && ok "formatted" || conflict "mkfs.$fs $dev failed"
}
t_label() { local tgt=$1 label=$2 dev fs cur
  if [[ $tgt == /dev/* ]]; then dev=$tgt; fs=$(blkid -p -o value -s TYPE -- "$dev" 2>/dev/null || true)
  else mountpoint -q -- "$tgt" || { later "$tgt must be mounted"; return 0; }
    dev=$(findmnt -no SOURCE -- "$tgt" | sed 's/\[.*//'); fs=$(findmnt -no FSTYPE -- "$tgt"); fi
  cur=$(blkid -p -o value -s LABEL -- "$dev" 2>/dev/null || true)   # -p: probe, never the stale cache
  if [[ $cur == "$label" ]]; then ok "label $label"; return 0; fi
  act "label $dev ($fs) \"$label\" (was \"$cur\")" || return 0
  case $fs in
    ext2|ext3|ext4) try e2label "$dev" "$label" ;;
    btrfs) try btrfs filesystem label "$([[ $tgt == /dev/* ]] && echo "$dev" || echo "$tgt")" "$label" ;;
    xfs) try xfs_admin -L "$label" "$dev" ;;
    vfat) try fatlabel "$dev" "$label" ;;
    exfat) try exfatlabel "$dev" "$label" ;;
    *) conflict "labels on $fs are not handled"; return 0 ;;
  esac && ok "labelled"
}
t_btrfs_send() { local s=$1 par=$2 dir=$3 login=$4 port=$5 name=${1##*/} there ro
  need btrfs btrfs-progs || return 0
  if ! dest_cmd "$login" "$port" btrfs --version >/dev/null 2>&1 </dev/null; then later "cannot run btrfs on ${login:-this host} (SSH key, sudo, btrfs-progs)"; return 0; fi
  if there=$(dest_cmd "$login" "$port" btrfs subvolume show -- "$dir/$name" 2>/dev/null </dev/null); then
    if grep -qE 'Received UUID:[[:space:]]+[0-9a-f]' <<<"$there"; then ok "$dir/$name is already there"
    else conflict "$dir/$name is there but is not a finished copy (an interrupted send?): delete it with btrfs subvolume delete, then rerun"; fi
    return 0
  fi
  btrfs subvolume show -- "$s" >/dev/null 2>&1 || { later "$s must be a btrfs subvolume"; return 0; }
  ro=$(btrfs property get -ts -- "$s" ro 2>/dev/null || true)
  [[ $ro == ro=true ]] || { conflict "$s is not read-only: btrfs only sends read-only snapshots"; return 0; }
  if [[ -n $par ]]; then
    btrfs subvolume show -- "$par" >/dev/null 2>&1 || { later "$par must exist here"; return 0; }
    dest_cmd "$login" "$port" btrfs subvolume show -- "$dir/${par##*/}" >/dev/null 2>&1 </dev/null ||
      { conflict "$dir/${par##*/} is not on the other side: send $par there first"; return 0; }
  fi
  act "btrfs send ${par:+-p $par }$s | btrfs receive $dir on ${login:-this host}" || return 0
  dest_cmd "$login" "$port" mkdir -p -- "$dir" </dev/null || { conflict "cannot make $dir"; return 0; }
  if btrfs send ${par:+-p "$par"} -- "$s" | dest_cmd "$login" "$port" btrfs receive -- "$dir"; then ok "sent"
  else conflict "the send failed: delete a partial $dir/$name on the other side before you rerun"; fi
}
zfs_exists() { zfs list -H -o name -t "${2:-all}" -- "$1" >/dev/null 2>&1; }
t_zfs_pool() { local pool=$1 level=$2 devs=$3 mp=$4 wipe=$5 vdev=() d arr
  need zpool zfsutils-linux || return 0
  if zpool list -H -o name -- "$pool" >/dev/null 2>&1; then ok "pool $pool exists"; return 0; fi
  read -ra arr <<<"$devs"
  devs_guard "$wipe" "${arr[@]}" || return 0
  [[ $level == stripe ]] || vdev=("$level")
  act "zpool create $pool $level $devs${mp:+ (mounted at $mp)}" || return 0
  if [[ $wipe == 1 ]]; then for d in "${arr[@]}"; do try wipefs -aq -- "$d" || return 0; done; fi
  try zpool create -o ashift=12 ${wipe:+-f} ${mp:+-m "$mp"} -- "$pool" ${vdev[@]+"${vdev[@]}"} "${arr[@]}" && ok "created"
}
t_zfs_dataset() { local ds=$1 mp=$2 opts=$3 o k v have
  need zfs zfsutils-linux || return 0
  if ! zfs_exists "$ds" filesystem; then
    zfs_exists "${ds%%/*}" filesystem || { later "pool ${ds%%/*} must exist"; return 0; }
    act "zfs create -p $ds" && try zfs create -p -- "$ds" && ok "created" || return 0
  else ok "dataset $ds exists"; fi
  local props=() more=()
  [[ -n $mp ]] && props+=("mountpoint=$mp")
  IFS=, read -ra more <<<"$opts"
  for o in ${props[@]+"${props[@]}"} ${more[@]+"${more[@]}"}; do
    k=${o%%=*}; v=${o#*=}
    have=$(zfs get -H -o value "$k" -- "$ds" 2>/dev/null || true)
    if [[ $have == "$v" ]]; then ok "$k=$v"
    elif act "zfs set $k=$v $ds (now ${have:-unset})"; then try zfs set "$k=$v" -- "$ds" && ok "$k=$v"; fi
  done
}
t_zfs_snapshot() { local ds=$1 name=$2
  need zfs zfsutils-linux || return 0
  if zfs_exists "$ds@$name" snapshot; then ok "snapshot $ds@$name exists"; return 0; fi
  zfs_exists "$ds" filesystem || { later "dataset $ds must exist"; return 0; }
  act "zfs snapshot ${3:+-r }$ds@$name" && try zfs snapshot ${3:+-r} -- "$ds@$name" && ok "snapshot taken"
}
t_zfs_send() { local ds=$1 name=$2 base=$3 dest=$4 rec=$5 raw=$6 login=$7 port=$8 flags=()
  need zfs zfsutils-linux || return 0
  if ! dest_cmd "$login" "$port" zfs version >/dev/null 2>&1 </dev/null; then later "cannot run zfs on ${login:-this host} (SSH key, sudo, ZFS tools)"; return 0; fi
  if dest_cmd "$login" "$port" zfs list -H -o name -t snapshot -- "$dest@$name" >/dev/null 2>&1 </dev/null; then ok "$dest@$name is already there"; return 0; fi
  zfs_exists "$ds@$name" snapshot || { later "snapshot $ds@$name must exist"; return 0; }
  if [[ -n $base ]]; then
    zfs_exists "$ds@$base" snapshot || { later "snapshot $ds@$base must exist here"; return 0; }
    dest_cmd "$login" "$port" zfs list -H -o name -t snapshot -- "$dest@$base" >/dev/null 2>&1 </dev/null ||
      { conflict "$dest@$base is not on the other side: send it there first"; return 0; }
  elif dest_cmd "$login" "$port" zfs list -H -o name -- "$dest" >/dev/null 2>&1 </dev/null; then
    conflict "$dest already exists there and I never overwrite it: give an earlier snapshot both sides have"; return 0
  fi
  [[ -n $rec ]] && flags+=(-R)
  [[ -n $raw ]] && flags+=(-w)
  [[ -n $base ]] && flags+=(-i "@$base")
  act "zfs send ${flags[*]-} $ds@$name | zfs receive -u $dest on ${login:-this host}" || return 0
  if zfs send ${flags[@]+"${flags[@]}"} -- "$ds@$name" | dest_cmd "$login" "$port" zfs receive -u -- "$dest"; then ok "sent"
  else conflict "the send failed"; fi
}
t_zfs_scrub() { local pool=$1
  need zpool zfsutils-linux || return 0
  zpool list -H -o name -- "$pool" >/dev/null 2>&1 || { later "pool $pool must exist"; return 0; }
  if zpool status -- "$pool" | grep 'scrub in progress' >/dev/null; then ok "a scrub is running"; return 0; fi
  if [[ -e $STATE/zfs-scrub-$pool ]]; then ok "started $(cat "$STATE/zfs-scrub-$pool"): zpool status $pool"; return 0; fi
  act "zpool scrub $pool" && try zpool scrub -- "$pool" &&
    { mkdir -p "$STATE"; date '+%F %T' >"$STATE/zfs-scrub-$pool"; ok "started: zpool status $pool"; }
}
vg_exists() { vgs --noheadings -o vg_name -- "$1" >/dev/null 2>&1; }
lv_exists() { lvs --noheadings -o lv_name -- "$1/$2" >/dev/null 2>&1; }
t_lvm_vg() { local vg=$1 devs=$2 wipe=$3 d arr
  need vgcreate lvm2 || return 0
  if vg_exists "$vg"; then ok "volume group $vg exists"; return 0; fi
  read -ra arr <<<"$devs"
  devs_guard "$wipe" "${arr[@]}" || return 0
  act "vgcreate $vg $devs" || return 0
  if [[ $wipe == 1 ]]; then for d in "${arr[@]}"; do try wipefs -aq -- "$d" || return 0; done; fi
  try vgcreate -y -- "$vg" "${arr[@]}" >/dev/null && ok "created"
}
t_lvm_vg_extend() { local vg=$1 dev=$2 wipe=$3
  need vgextend lvm2 || return 0
  vg_exists "$vg" || { later "volume group $vg must exist"; return 0; }
  if [[ $(pvs --noheadings -o vg_name -- "$dev" 2>/dev/null | tr -d ' ') == "$vg" ]]; then ok "$dev is in $vg"; return 0; fi
  devs_guard "$wipe" "$dev" || return 0
  act "vgextend $vg $dev" || return 0
  [[ $wipe == 1 ]] && { try wipefs -aq -- "$dev" || return 0; }
  try vgextend -y -- "$vg" "$dev" >/dev/null && ok "added"
}
t_lvm_lv() { local vg=$1 lv=$2 size=$3 fs=$4 label=$5 dev=/dev/$1/$2 have
  need lvcreate lvm2 || return 0
  if lv_exists "$vg" "$lv"; then ok "volume $vg/$lv exists"
  else
    vg_exists "$vg" || { later "volume group $vg must exist"; return 0; }
    # -Wn: a new volume can land on old filesystem signatures; it is only formatted below if the plan asks
    act "lvcreate -L $size -n $lv $vg" && try lvcreate -y -Wn -L "$size" -n "$lv" -- "$vg" >/dev/null && ok "created" || return 0
    udevadm settle 2>/dev/null || true
  fi
  [[ -n $fs ]] || return 0
  have=$(blkid -p -o value -s TYPE -- "$dev" 2>/dev/null || true)
  if [[ $have == "$fs" ]]; then ok "$dev is $fs"
  elif [[ -n $have ]]; then conflict "$dev holds $have"
  elif act "mkfs.$fs $dev"; then mkfs_dev "$dev" "$fs" "$label" && ok "formatted" || conflict "mkfs.$fs $dev failed"; fi
}
t_lvm_extend() { local vg=$1 lv=$2 size=$3 now want
  need lvextend lvm2 || return 0
  lv_exists "$vg" "$lv" || { later "volume $vg/$lv must exist"; return 0; }
  now=$(lvs --noheadings --nosuffix --units b -o lv_size -- "$vg/$lv" | tr -d ' ')
  want=$(numfmt --from=iec "$size")
  if ((now >= want)); then ok "$vg/$lv is already $(human "$now")"; return 0; fi
  act "lvextend -r -L $size $vg/$lv (now $(human "$now"))" && try lvextend -r -L "$size" -- "$vg/$lv" >/dev/null && ok "grown"
}
t_lvm_snapshot() { local vg=$1 lv=$2 name=$3 size=$4
  need lvcreate lvm2 || return 0
  if lv_exists "$vg" "$name"; then ok "snapshot $vg/$name exists"; return 0; fi
  lv_exists "$vg" "$lv" || { later "volume $vg/$lv must exist"; return 0; }
  act "lvcreate -s ${size:+-L $size }-n $name $vg/$lv" && try lvcreate -y -s ${size:+-L "$size"} -n "$name" -- "$vg/$lv" >/dev/null && ok "snapshot taken"
}

run() { # n host type title args...
  local n=$1 host=$2 type=$3 desc=$4; shift 4
  [[ -n $ONLY && $ONLY != "$n" ]] && return 0
  section "$n. $desc"
  if [[ $host != "$ME" ]]; then skip "runs on $host: ./$(basename "$0") --host <user>@$host ${ARGS[*]}"; return 0; fi
  if ((STOPPED)); then info "skipped: an earlier task failed"; return 0; fi
  CUR_DESTRUCTIVE=0; case $type in partition|format|btrfs-add|zfs-pool|lvm-vg|lvm-vg-extend) CUR_DESTRUCTIVE=1 ;; esac
  local before=$PROBLEMS
  "t_${type//-/_}" "$@" '' '' '' '' '' || true      # padded: every task function can read its optional arguments
  if ((APPLY && PROBLEMS > before)); then STOPPED=1; fi
}

echo "${H}$PLAN${N0} · $MODE on $(uname -n)$( ((DESTRUCTIVE)) && echo ' · destructive tasks allowed')"
((APPLY)) || [[ $EUID -eq 0 ]] || info "(reporting as $(id -un): folders it can't read look missing; sudo shows everything)"
"""

CHANGE_TAIL = r"""
echo
if ((PROBLEMS)); then echo "${R}$PROBLEMS problem(s)${N0}$( ((STOPPED)) && echo ', stopped at the first one')"; exit 1; fi
echo "${G}done${N0}"
"""


# ── the Ansible playbook ────────────────────────────────────────────────
def _ansible_task(t: dict, c: Host | None) -> dict:
    p, k = t['params'], t['type']
    name = title(t)
    q = shlex.quote
    if k == 'dir':
        return {'name': name, 'ansible.builtin.file': {k2: v for k2, v in (('path', p['path']), ('state', 'directory'),
                ('owner', p['owner']), ('group', p['group']), ('mode', p['mode'])) if v}}
    if k == 'perms':
        if not (p['recursive'] and p['mode']):
            return {'name': name, 'ansible.builtin.file': {k2: v for k2, v in (('path', p['path']), ('owner', p['owner']),
                    ('group', p['group']), ('mode', p['mode']), ('recurse', p['recursive'] or None)) if v}}
        # recursive covers owner and group only (as in the script): the file module's recurse would give every file
        # inside the folder's mode too
        tasks = [{'name': f'{name}: mode', 'ansible.builtin.file': {'path': p['path'], 'mode': p['mode']}}]
        if p['owner'] or p['group']:
            tasks.insert(0, {'name': f'{name}: owner and group inside too', 'ansible.builtin.file': {k2: v for k2, v in (
                ('path', p['path']), ('owner', p['owner']), ('group', p['group']), ('recurse', True)) if v}})
        return tasks
    if k == 'symlink':
        return {'name': name, 'ansible.builtin.file': {'src': p['target'], 'dest': p['path'], 'state': 'link'}}
    if k == 'rename':
        return {'name': name, 'ansible.builtin.command': {'argv': ['mv', '-T', '--', p['path'], p['dest']],
                'creates': p['dest'], 'removes': p['path']}}
    if k == 'trash':
        return {'name': name, 'ansible.builtin.shell': {'cmd': (
            f'set -e; p={q(p["path"])}; d=$(cd "$(dirname "$p")" && pwd -P)\n'
            'while [ "$d" != / ] && [ "$(stat -c %d "$(dirname "$d")")" = "$(stat -c %d "$d")" ]; do d=$(dirname "$d"); done\n'
            'r=$(cd "$(dirname "$p")" && pwd -P)/$(basename "$p"); r=${r#"$d"/}\n'
            'dest="$d/.storageforge-trash/$(date +%F)/$r"; mkdir -p "$(dirname "$dest")"; chmod 700 "$d/.storageforge-trash"\n'
            'mv -T -- "$p" "$dest"\n'), 'removes': p['path']}}
    if k == 'subvolume':
        task = {'name': name, 'ansible.builtin.command': {'argv': ['btrfs', 'subvolume', 'create', p['path']], 'creates': p['path']}}
        return [task, {'name': f'No copy-on-write on {p["path"]}', 'ansible.builtin.command': {'argv': ['chattr', '+C', p['path']]},
                       'changed_when': False}] if p['nocow'] else task
    if k == 'snapshot':
        return {'name': name, 'ansible.builtin.command': {'argv': ['btrfs', 'subvolume', 'snapshot'] + (['-r'] if p['readonly'] else [])
                + [p['source'], p['dest']], 'creates': p['dest']}}
    if k == 'to-subvolume':
        return {'name': name, 'ansible.builtin.shell': {'executable': '/bin/bash', 'cmd': (
            f'set -euo pipefail; p={q(p["path"])}\n'
            'if btrfs subvolume show "$p" >/dev/null 2>&1; then echo unchanged; exit 0; fi\n'
            's=$(date +%Y%m%d-%H%M%S); new="$p.sf-subvol-$s"; old="$p.sf-folder-$s"\n'
            'btrfs subvolume create "$new" >/dev/null; chown --reference="$p" "$new"; chmod --reference="$p" "$new"\n'
            'cp -a --reflink=always "$p/." "$new/"\n'
            '[ "$(find "$p" | wc -l)" = "$(find "$new" | wc -l)" ] || { echo "copy incomplete: $new kept, $p untouched" >&2; exit 1; }\n'
            'mv -T "$p" "$old"; mv -T "$new" "$p"; echo "original folder kept at $old (move it to the trash when sure)"\n')},
            'register': 'sf_out', 'changed_when': "'unchanged' not in sf_out.stdout"}
    if k == 'mount':
        opts = ','.join(x for x in ([f'subvol={p["subvol"]}'] if p['subvol'] else []) + ([p['options']] if p['options'] else [])) or 'defaults'
        return {'name': name, 'ansible.posix.mount': {'src': p['source'], 'path': p['target'], 'fstype': p['fstype'],
                'opts': opts, 'state': 'mounted', 'backup': True}}
    if k == 'mount-options':
        m = (c.mounted.get(p['target']) if c else None) or {}
        src = (m.get('source') or '').split('[')[0]
        sv = re.search(r'\[/?([^\]]+)\]', m.get('source') or '')
        opts = ','.join(([f'subvol={sv.group(1)}'] if sv else []) + [o for o in p['options'].split(',') if not o.startswith('subvol')])
        return [{'name': name, 'ansible.posix.mount': {'src': src or 'CHECK-ME', 'path': p['target'], 'fstype': m.get('fstype') or 'auto',
                 'opts': opts, 'state': 'present', 'backup': True}, 'register': 'sf_mnt'},
                {'name': f'Remount {p["target"]}', 'ansible.builtin.command': {'argv': ['mount', '-o', 'remount', p['target']]},
                 'when': 'sf_mnt is changed'}]
    if k == 'unmount':
        return {'name': name, 'ansible.posix.mount': {'path': p['target'], 'state': 'absent', 'backup': True}}
    gate = {'tags': ['destructive'], 'when': 'storageforge_destructive | default(false) | bool'}
    if k == 'partition':
        tasks = [{'name': name, 'community.general.parted': {'device': p['disk'], 'label': 'gpt', 'number': 1, 'state': 'present',
                  'part_start': '1MiB', 'part_end': '100%'}, **gate}]
        if p['fstype']:
            part = p['disk'] + ('p1' if p['disk'][-1].isdigit() else '1')
            tasks.append({'name': f'Format {part} as {p["fstype"]}', 'community.general.filesystem': {k2: v for k2, v in (
                ('dev', part), ('fstype', p['fstype']), ('opts', f'-L {q(p["label"])}' if p['label'] and p['fstype'] != 'vfat'
                                                             else f'-n {q(p["label"])}' if p['label'] else None)) if v}, **gate})
        return tasks
    if k == 'format':
        return {'name': name, 'community.general.filesystem': {k2: v for k2, v in (
            ('dev', p['device']), ('fstype', p['fstype']), ('force', p['wipe'] or None),
            ('opts', (f'-n {q(p["label"])}' if p['fstype'] == 'vfat' else f'-L {q(p["label"])}') if p['label'] else None)) if v}, **gate}
    if k == 'btrfs-add':
        return {'name': name, 'ansible.builtin.command': {'argv': ['btrfs', 'device', 'add'] + (['-f'] if p['wipe'] else [])
                + [p['device'], p['target']]}, **gate}
    if k == 'btrfs-balance':
        return {'name': name, 'ansible.builtin.command': {'argv': ['btrfs', 'balance', 'start', '--bg', f'-dconvert={p["data"]}',
                f'-mconvert={p["metadata"]}', p['target']]}}
    if k == 'scrub':
        return {'name': name, 'ansible.builtin.command': {'argv': ['btrfs', 'scrub', 'start', p['target']]}}
    if k == 'label':
        return {'name': name, 'ansible.builtin.shell': {'cmd': (
            f't={q(p["target"])}; l={q(p["label"])}\n'
            'case $t in /dev/*) d=$t; fs=$(blkid -p -o value -s TYPE "$d") ;; *) d=$(findmnt -no SOURCE "$t" | sed "s/\\[.*//"); fs=$(findmnt -no FSTYPE "$t") ;; esac\n'
            '[ "$(blkid -p -o value -s LABEL "$d")" = "$l" ] && { echo unchanged; exit 0; }\n'
            'case $fs in ext*) e2label "$d" "$l" ;; btrfs) btrfs filesystem label "$t" "$l" ;; xfs) xfs_admin -L "$l" "$d" ;;\n'
            '  vfat) fatlabel "$d" "$l" ;; exfat) exfatlabel "$d" "$l" ;; *) echo "labels on $fs are not handled" >&2; exit 1 ;; esac\n')},
            'register': 'sf_out', 'changed_when': "'unchanged' not in sf_out.stdout"}
    return _ansible_storage(t, gate)


def _ansible_storage(t: dict, gate: dict) -> dict:
    """ZFS, LVM and send tasks, which have no module every install has: a shell step that looks first, like the script."""
    p, k = t['params'], t['type']
    q = shlex.quote

    def guarded(test: str, cmd: str, **extra) -> dict:
        return {'name': title(t), 'ansible.builtin.shell': {'executable': '/bin/bash', 'cmd': (
            f'set -euo pipefail\nif {test}; then echo unchanged; exit 0; fi\n{cmd}\n')},
            'register': 'sf_out', 'changed_when': "'unchanged' not in sf_out.stdout", **extra}

    def to(cmd: str) -> str:                 # on the receiving side
        host = p['dest_host']
        return cmd if not host else f'ssh -o BatchMode=yes -- {q(host)} {q(("sudo -n " if not host.startswith("root@") else "") + cmd)}'
    if k == 'btrfs-send':
        name = p['source'].rstrip('/').rsplit('/', 1)[-1]
        flag = f'-p {q(p["parent"])} ' if p['parent'] else ''
        recv = to(f'btrfs receive -- {q(p["dest"])}')
        return guarded(to(f'btrfs subvolume show -- {q(p["dest"] + "/" + name)}') + ' >/dev/null 2>&1',
                       f'btrfs send {flag}-- {q(p["source"])} | {recv}')
    if k == 'zfs-send':
        flags = ('-R ' if p['recursive'] else '') + ('-w ' if p['raw'] else '') + (f'-i {q("@" + p["base"])} ' if p['base'] else '')
        recv = to(f'zfs receive -u -- {q(p["dest"])}')
        return guarded(to(f'zfs list -H -t snapshot -- {q(p["dest"] + "@" + p["name"])}') + ' >/dev/null 2>&1',
                       f'zfs send {flags}-- {q(p["dataset"] + "@" + p["name"])} | {recv}')
    if k == 'zfs-pool':
        vdev = '' if p['level'] == 'stripe' else p['level'] + ' '
        force = '-f ' if p['wipe'] else ''
        mp = f'-m {q(p["mountpoint"])} ' if p['mountpoint'] else ''
        return guarded(f'zpool list -H -- {q(p["pool"])} >/dev/null 2>&1',
                       f'zpool create -o ashift=12 {force}{mp}-- {q(p["pool"])} {vdev}' + ' '.join(q(d) for d in p['devices'].split()), **gate)
    if k == 'zfs-dataset':
        props = ([f'mountpoint={p["mountpoint"]}'] if p['mountpoint'] else []) + [o for o in p['options'].split(',') if o]
        opts = ''.join(f'-o {q(o)} ' for o in props)
        return guarded(f'zfs list -H -- {q(p["dataset"])} >/dev/null 2>&1', f'zfs create -p {opts}-- {q(p["dataset"])}')
    if k == 'zfs-snapshot':
        snap = q(f'{p["dataset"]}@{p["name"]}')
        return guarded(f'zfs list -H -t snapshot -- {snap} >/dev/null 2>&1', f'zfs snapshot {"-r " if p["recursive"] else ""}-- {snap}')
    if k == 'zfs-scrub':
        return guarded(f'zpool status -- {q(p["pool"])} | grep "scrub in progress" >/dev/null', f'zpool scrub -- {q(p["pool"])}')
    if k == 'lvm-vg':
        return guarded(f'vgs -- {q(p["vg"])} >/dev/null 2>&1', f'vgcreate -y -- {q(p["vg"])} ' + ' '.join(q(d) for d in p['devices'].split()), **gate)
    if k == 'lvm-vg-extend':
        return guarded(f'[ "$(pvs --noheadings -o vg_name -- {q(p["device"])} 2>/dev/null | tr -d " ")" = {q(p["vg"])} ]',
                       f'vgextend -y -- {q(p["vg"])} {q(p["device"])}', **gate)
    lv = q(f'{p["vg"]}/{p["lv"]}')
    if k == 'lvm-lv':
        fmt = f'\nmkfs.{p["fstype"]} {q("/dev/" + p["vg"] + "/" + p["lv"])}' if p['fstype'] else ''
        return guarded(f'lvs -- {lv} >/dev/null 2>&1', f'lvcreate -y -Wn -L {q(p["size"])} -n {q(p["lv"])} -- {q(p["vg"])}{fmt}')
    if k == 'lvm-extend':
        return guarded(f'[ "$(lvs --noheadings --nosuffix --units b -o lv_size -- {lv} | tr -d " ")" -ge "$(numfmt --from=iec {q(p["size"])})" ]',
                       f'lvextend -r -L {q(p["size"])} -- {lv}')
    if k == 'lvm-snapshot':
        size = f'-L {q(p["size"])} ' if p['size'] else ''
        return guarded(f'lvs -- {q(p["vg"] + "/" + p["name"])} >/dev/null 2>&1', f'lvcreate -y -s {size}-n {q(p["name"])} -- {lv}')
    raise ValueError(k)


class _Literal(str):
    pass


def ansible(conn: Conn, plan: dict) -> str:
    import yaml

    class Dumper(yaml.SafeDumper):
        pass

    class _Unsafe(str):
        pass
    Dumper.add_representer(_Literal, lambda d, s: d.represent_scalar('tag:yaml.org,2002:str', s, style='|'))
    # Ansible renders Jinja2 in every module argument: a path holding {{ lookup('pipe', ...) }} would run a command on
    # the machine running the playbook. !unsafe keeps such a string literal (the playbook's own Jinja is in when:).
    Dumper.add_representer(_Unsafe, lambda d, s: d.represent_scalar('!unsafe', str(s), style='"'))

    def lit(x):
        if isinstance(x, dict):
            return {k: lit(v) for k, v in x.items()}
        if isinstance(x, list):
            return [lit(v) for v in x]
        if isinstance(x, str) and any(m in x for m in ('{{', '{%', '{#')):
            return _Unsafe(x)
        return _Literal(x) if isinstance(x, str) and '\n' in x else x

    plan = normalize(plan)
    hs = hosts(conn)
    plays, ctx = [], {}
    for t in plan['tasks']:
        h = find_host(hs, t['host'])
        name = h['name'] if h else t['host']
        c = ctx.setdefault(name, Host(conn, h)) if h else None
        made = _ansible_task(t, c)
        made = made if isinstance(made, list) else [made]
        if plays and plays[-1]['hosts'] == name:
            plays[-1]['tasks'] += made
        else:
            plays.append({'name': f'{plan["name"]} on {name}', 'hosts': name, 'become': True, 'gather_facts': False, 'tasks': made})
    inventory = comments((f'#   {h["name"]} ansible_host={h["ssh_host"]} ansible_user={h["ssh_user"] or "root"}'
                          for h in (find_host(hs, n) for n in dict.fromkeys(p['hosts'] for p in plays)) if h), '')
    head = (f'# StorageForge change plan "{one_line(plan["name"])}" as an Ansible playbook, generated {dt.datetime.now():%Y-%m-%d %H:%M}.\n'
            '# Needs the ansible.posix and community.general collections.\n'
            '#   ansible-playbook -i inventory.ini this.yml --check --diff        # look first\n'
            '#   ansible-playbook -i inventory.ini this.yml                       # apply (drive tasks skipped)\n'
            '#   ansible-playbook -i inventory.ini this.yml -e storageforge_destructive=true   # also partition/format/create pools/add devices\n'
            '# Unlike the Bash script, unmount removes the fstab line (a backup is kept) and trash has no "already done" check.\n'
            '# inventory.ini from the last scans:\n' + (inventory or '#   (no scanned hosts)') + '\n')
    return head + yaml.dump(lit(plays), Dumper=Dumper, sort_keys=False, default_flow_style=False, width=120, allow_unicode=True)
