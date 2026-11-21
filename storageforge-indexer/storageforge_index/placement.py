"""Where a workload's data goes, said before it is deployed (roadmap section 6, placement advice). From the index alone: the mount a path
sits on, the pool and disks under it, the ZFS properties set on purpose, and what snapshots, holds and copies reach it.

- A pool on a dataset tuned for its use: VM images want recordsize=64K on ZFS (qcow2 writes 64 KiB clusters) and no copy-on-write on
  btrfs; databases want a small recordsize (16K) on ZFS and no copy-on-write on btrfs.
- Databases off the bulk pool: a database on spinning disks or parity RAID (raidz, RAID 5 and 6) is slow at the small random writes it
  makes, and slows everything else on that pool down with it.
- Bind mounts on network filesystems: a database or a lock file on NFS or SMB fails in ways that are hard to see, and a lost
  connection stops the container.
- Data no hold or offsite copy reaches: nothing snapshots it, no retention hold covers it, and no backup takes it to another place.

Each piece of advice is a (level, text) pair as a plan check says it, and none of it stops a plan: placement is advice.
"""
from __future__ import annotations

import json
import re

from .db import Conn

NETFS = ('nfs', 'nfs4', 'cifs', 'smb3', 'smbfs', 'fuse.sshfs', 'glusterfs', 'fuse.glusterfs', 'ceph', 'fuse.ceph', 'fuse.rclone', '9p', 'davfs', 'fuse.s3fs')
DB_IMAGE = re.compile(r'(postgres|postgis|timescaledb|mysql|mariadb|percona|mongo|mongodb|redis|valkey|keydb|influxdb|clickhouse|elasticsearch|opensearch|cassandra|'
                      r'scylla|couchdb|couchbase|neo4j|questdb|cockroach|etcd|memgraph|surrealdb|yugabyte)([-_.][a-z0-9._-]*)?', re.I)
WANT_RS = {'vm': (65536, '64K', 'qcow2 writes 64 KiB clusters'), 'database': (16384, '16K', 'a database writes small pages')}
SIZES = {'K': 1024, 'M': 1024 ** 2}


def is_database(image: str | None) -> bool:
    """By the image's own name, the last part before its tag: postgres:16, docker.io/library/mariadb, ghcr.io/x/timescaledb-ha."""
    name = (image or '').split('@')[0].rsplit('/', 1)[-1].split(':')[0]
    return bool(DB_IMAGE.fullmatch(name))


def _bytes(v: str) -> int | None:
    m = re.fullmatch(r'(\d+)([KM]?)', (v or '').strip().upper())
    return int(m[1]) * SIZES.get(m[2], 1) if m else None


def _zfs_props(conn: Conn, host_id: int) -> dict:
    inv = conn.scalar('SELECT inventory_json FROM hosts WHERE host_id = :h', {'h': host_id})
    inv = (inv if isinstance(inv, dict) else json.loads(inv or '{}')) or {}
    out: dict = {}
    for line in str(inv.get('zfs_props') or '').splitlines():
        f = line.split('\t')
        if len(f) == 3:
            out.setdefault(f[0], {})[f[1]] = f[2]
    return out


def _recordsize(props: dict, dataset: str) -> tuple[int, str]:
    """The recordsize a dataset has: its own, or the nearest parent's set on purpose, or ZFS's default."""
    d = dataset
    while d:
        v = (props.get(d) or {}).get('recordsize')
        if v and _bytes(v):
            return _bytes(v), v
        d = d.rpartition('/')[0]
    return 131072, '128K (the default)'


def _pool_of(c, mount: dict) -> dict | None:
    """The pool under a mount, from what the scan read of the disks: a ZFS pool by name, an md array, a volume group or a btrfs pool by
    its mount, or the disk a plain partition is on."""
    node = c.node
    fs, src = mount.get('fstype') or '', (mount.get('source') or '').split('[')[0]
    pools = node.get('pools') or []
    if fs == 'zfs':
        return next((p for p in pools if p['name'] == src.split('/')[0]), None)
    dev = src.removeprefix('/dev/')
    for p in pools:
        if p.get('mount') == mount.get('target') or p['name'] == dev or p['name'] == src.removeprefix('/dev/mapper/'):
            return p
    for d in node.get('disks') or []:
        if any(part['dev'] == dev for part in d.get('parts') or []) or d['dev'] == dev:
            return {'name': d['dev'], 'type': 'disk', 'level': None, 'tier': d.get('tier'), 'media': d.get('media')}
    return None


def _bulk(pool: dict | None) -> str | None:
    """Why a pool is the bulk pool, or None."""
    if not pool:
        return None
    level = str(pool.get('level') or '').lower()
    if level.startswith('raidz') or level in ('raid5', 'raid6'):
        return f'{pool["name"]} is parity RAID ({level})'
    if pool.get('tier') == 'mass' or pool.get('media') == 'hdd':
        return f'{pool["name"]} is on spinning disks'
    return None


def _cover(conn: Conn, host: str, path: str, dataset: str | None) -> dict:
    """What reaches a path: snapshots, retention holds, backups, and whether a backup leaves the host."""
    from . import protection, security
    from .remote import is_under
    offsite = protection.offsite_hosts(conn)
    facts = []
    for fn in (protection._facts_from_jobs, protection._facts_from_tasks):
        try:
            facts += fn(conn, host, offsite)
        except Exception:        # a plan check never fails on what the protection matrix could not read
            pass
    try:
        facts += protection._facts_detected(conn, host)
    except Exception:
        pass

    def reaches(f):
        if f.get('path'):
            return is_under(path, f['path'])
        if f.get('dataset') and dataset:
            return dataset == f['dataset'] or dataset.startswith(f['dataset'] + '/')
        return False
    mine = [f for f in facts if reaches(f)]
    holds = [r for r in security.hold_rows(conn, host) if r['status'] != 'released' and dataset
             and (r.get('snapshot') or '').split('@')[0] in {dataset, *[dataset.rsplit('/', i)[0] for i in range(1, dataset.count('/') + 1)]}]
    return {'snapshots': [f['why'] for f in mine if (f.get('snapshots') or {}).get('enabled')],
            'offsite': [f['why'] for f in mine if (f.get('backup') or {}).get('offsite')],
            'backups': [f['why'] for f in mine if f.get('backup')], 'holds': len(holds)}


def advise(conn: Conn, c, h: dict, path: str, use: str = 'data', what: str = '') -> list[tuple[str, str]]:
    """use: 'vm' (VM images), 'database', or 'data'. what: how to name it in the text (a service, a pool)."""
    from .moves import mount_of
    out: list[tuple[str, str]] = []
    if not path or not path.startswith('/'):
        return out
    who = f'{what} ({path})' if what else path
    m = mount_of(h, path) or next((x for x in h['mounts'] if x['target'] == c.mount_at(path)[0]), None)
    if not m:
        return [('note', f'the index does not know what {path} sits on: scan {h["name"]} first for placement advice')]
    fs = m.get('fstype') or ''
    dataset = (m.get('source') or '').split('[')[0] if fs == 'zfs' else None
    if fs in NETFS:
        out.append(('warn', f'{who} is on a network filesystem ({fs} at {m["target"]}): '
                    + ('a database on it corrupts or stalls when the connection drops, and its locks are not reliable. Keep it on a local disk'
                       if use == 'database' else 'file locks on it are not reliable, and a lost connection stops what uses it')))
    if use in WANT_RS and fs == 'zfs' and dataset:
        want, label, why = WANT_RS[use]
        have, shown = _recordsize(_zfs_props(conn, h['id']), dataset)
        if have > want or have < want // 4:
            out.append(('note', f'{who} is on {dataset} with recordsize={shown}: {label} suits it better, as {why}. '
                                f'A dataset of its own with zfs create -o recordsize={label} is best: a changed recordsize applies to new files only'))
        else:
            out.append(('ok', f'{dataset} has recordsize={shown}, which suits it'))
    if use in WANT_RS and fs == 'btrfs':
        opts = (m.get('options') or '')
        if 'nodatacow' not in opts:
            out.append(('note', f'{who} is on btrfs with copy-on-write: {"VM images" if use == "vm" else "database files"} fragment badly that way. '
                                'Make its folder with chattr +C before the files are written (they lose checksums), or use a nodatacow subvolume'))
    if use == 'database':
        why = _bulk(_pool_of(c, m))
        if why:
            out.append(('warn', f'a database on the bulk pool: {who} is on {m["target"]}, and {why}. Small random writes are slow there and slow '
                                'the rest of the pool: keep databases on an SSD pool or dataset'))
    cov = _cover(conn, h['name'], path, dataset)
    if not cov['snapshots'] and not cov['holds'] and not cov['offsite']:
        out.append(('warn', f'no hold or offsite copy reaches {who}: nothing snapshots it, no retention hold covers it, and no backup takes it off {h["name"]}'))
    elif not cov['offsite']:
        what_has = cov['snapshots'][0] if cov['snapshots'] else f'{cov["holds"]} retention hold(s)'
        out.append(('note', f'{who} is snapshotted ({what_has}), but no copy of it leaves {h["name"]}'
                    + (f': {cov["backups"][0]} stays on site' if cov['backups'] else '')))
    else:
        out.append(('ok', f'{who} is copied off the host by {cov["offsite"][0]}'))
    return out


def _dedupe(say):
    seen = set()

    def once(level, text):
        if (level, text) not in seen:
            seen.add((level, text))
            say(level, text)
    return once


def say_for_stack(conn: Conn, c, h: dict, model: dict, where: str, say):
    """A compose stack: each bind mount by what the service is, and the named volumes under the engine's root."""
    from .runtimes import docker
    say = _dedupe(say)
    views = docker.listing(conn, h['name'])
    root = (views[0].get('root_dir') if views else None) or '/var/lib/docker'
    for sname, s in model['services'].items():
        use = 'database' if is_database(s.get('image')) else 'data'
        for b in s['binds']:
            src = b['source']
            if not src.startswith('/'):
                src = f'{where.rstrip("/")}/{src.lstrip("./")}' if src.startswith('./') else None
            if src:
                for level, text in advise(conn, c, h, src, use, sname):
                    say(level, text)
        if use == 'database' and not s['binds']:
            for level, text in advise(conn, c, h, root, 'database', f'{sname}, in a named volume'):
                say(level, text)


def say_for_vm(conn: Conn, c, h: dict, pool_path: str, say):
    for level, text in advise(conn, c, h, pool_path, 'vm', 'its disks'):
        say(level, text)


def for_host(conn: Conn, host: str, path: str, use: str = 'data') -> dict:
    """What the API answers for a deploy form: the advice for one path on one host."""
    from . import changes
    from .moves import find_host, hosts
    h = find_host(hosts(conn), host)
    if not h:
        raise LookupError(f'{host} has not been scanned')
    if use not in ('vm', 'database', 'data'):
        raise ValueError('use is vm, database or data')
    c = changes.Host(conn, h)
    return {'host': h['name'], 'path': path, 'use': use, 'advice': [{'level': lv, 'text': t} for lv, t in advise(conn, c, h, path, use)]}
