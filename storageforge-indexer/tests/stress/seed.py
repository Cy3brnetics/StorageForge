"""A large synthetic fleet for the stress runs, written through the scanner's own path (stage_insert and apply_diff), so the index looks as a
scan leaves it: hosts, mounts, a deep folder tree, files with sizes, ages and checksums that make duplicates and cold data, and host logs.

    python tests/stress/seed.py DB HOSTS FILES_PER_HOST
"""
import json
import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from storageforge_index import hostlogs, users  # noqa: E402
from storageforge_index.db import Database  # noqa: E402
from storageforge_index.stream import to_row  # noqa: E402

PW = 'stress-password-0123456789'
WORDS = ['photos', 'raw', 'backup', 'projects', 'music', 'video', 'docs', 'archive', 'home', 'srv', 'data', 'tmp', 'build', 'cache', 'mail']
EXTS = ['jpg', 'cr2', 'mp4', 'pdf', 'txt', 'flac', 'iso', 'tar.gz', 'py', 'log', 'db', 'docx']


def rows_for(host: int, n: int, rng: random.Random):
    now = int(time.time())
    for i in range(n):
        depth = rng.randint(1, 6)
        folder = '/' + '/'.join(rng.choice(WORDS) + str(rng.randint(0, 40)) for _ in range(depth))
        size = int(rng.paretovariate(1.2) * 4096)
        mtime = now - int(rng.expovariate(1 / (400 * 86400)))
        name = f'{rng.choice(WORDS)}_{i}.{rng.choice(EXTS)}'
        yield to_row([b'f', str(size).encode(), b'644', b'1000', b'1000', str(mtime).encode(), b'', f'{folder}/{name}'.encode()])


def seed(url: str, hosts: int, files: int, seed_value: int = 1):
    db = Database(url)
    conn = db.connect()
    db.migrate(conn)
    if not users.count(conn):
        users.create(conn, 'admin', PW, 'admin')
    rng = random.Random(seed_value)
    started = time.time()
    for h in range(hosts):
        name = f'host{h:03d}'
        inv = {'os': 'Debian GNU/Linux 13', 'df': '', 'collected_at': '2026-11-16T00:00:00+00:00'}
        hid = conn.scalar("INSERT INTO hosts (hostname, ssh_host, ssh_user, inventory_json, last_scanned_at) VALUES (:n, :n, 'scan', :i, :t) RETURNING host_id",
                          {'n': name, 'i': json.dumps(inv), 't': int(time.time())})
        mid = conn.scalar("INSERT INTO mounts (host_id, mount_point, filesystem_type, scan_state, total_bytes, used_bytes) "
                          "VALUES (:h, '/', 'ext4', 'indexed', :tot, :used) RETURNING mount_id", {'h': hid, 'tot': 8 << 40, 'used': 3 << 40})
        scan = db.begin_scan(conn, hid)
        job = 10_000 + h
        db.stage_create(conn, job)
        batch = []
        for row in rows_for(h, files, rng):
            batch.append(row)
            if len(batch) == 50_000:
                db.stage_insert(conn, job, batch)
                batch = []
        if batch:
            db.stage_insert(conn, job, batch)
        db.apply_diff(conn, scan, job, mid, '/', True, max_delete_ratio=1.0)
        db.stage_drop(conn, job)
        db.finish_scan(conn, scan, hid, {'entries': files, 'bytes': 0, 'added': files, 'modified': 0, 'deleted': 0, 'read_errors': 0}, 'ok', 1.0)
        # checksums for a share of the files, with collisions, so duplicates have something to find
        ids = [r[0] for r in conn.all('SELECT file_id FROM file_records f JOIN mounts m ON m.mount_id = f.mount_id WHERE m.host_id = :h AND f.file_id % 7 = 0', {'h': hid})]
        db.set_checksums(conn, [(f'{rng.randint(0, len(ids) // 3 or 1):064x}', i) for i in ids])
        now = time.time()
        lines = [{'key': f'{name}-{k}', 'at_us': int((now - k * 13) * 1e6), 'priority': rng.randint(0, 7), 'unit': rng.choice(['sshd.service', 'zed.service', 'cron.service', 'smbd.service']),
                  'ident': None, 'pid': None, 'message': f'line {k} ' + rng.choice(WORDS) * rng.randint(1, 20)} for k in range(2000)]
        hostlogs.store(conn, name, {'lines': lines, 'state': 'ok', 'cut': False}, now)
        print(f'{name}: {files:,} files ({time.time() - started:.0f} s)', flush=True)
    conn.close()


if __name__ == '__main__':
    seed(sys.argv[1], int(sys.argv[2]), int(sys.argv[3]))
