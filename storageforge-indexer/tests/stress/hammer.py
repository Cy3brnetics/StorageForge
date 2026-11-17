"""Stress a real StorageForge server until it breaks: `storageforge-index serve` on a seeded database (seed.py), in a temporary folder of its
own, then more and more clients at once on the routes that read the most. Each stage reports, per route, the answers by status, the slowest,
and what the server holds (memory, threads, open files). A stage that breaks a limit ends the run and says which.

    python tests/stress/hammer.py DB [--stages 8,32,64,128,256] [--seconds 20] [--postgres URL]

It is not part of the unit suite: it loads the machine on purpose. The server is the subject: it gets every core. The one guard is for the
machine: if it runs short of memory, the server is killed and that is the finding.
"""
import argparse
import collections
import http.client
import json
import os
import random
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PW = 'stress-password-0123456789'
# light routes must stay quick whatever else runs; a folder analysis is queued (one at a time) and must arrive, retries and all, in heavy_p99
# searches, duplicate lists and exports are admitted a few at a time (server.EXPENSIVE_ROUTES) and must arrive in queued_p99
LIMITS = {'errors': 0.05, 'light_p99': 2.0, 'queued_p99': 30.0, 'heavy_p99': 90.0, 'rss_gib': 6.0, 'machine_free_gib': 4.0}
HEAVY = {'filemap', 'filemap all', 'twin folders', 'cold folders'}
QUEUED = {'search', 'search one host', 'search under', 'dupes', 'dupes all', 'hostlogs export'}
PATTERNS = ['*photos*', '*.jpg', 'backup_*', '*raw*2*', 'docs_1.pdf', '*a*b*c*', '*[0-9][0-9][0-9].log', '*[!x]*.iso', '?????_*', 'music*']
WORDS = ['photos', 'raw', 'backup', 'projects', 'music', 'video', 'docs', 'archive', 'home', 'srv', 'data']


def free_port() -> int:
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def machine_free_gib() -> float:
    for line in open('/proc/meminfo'):
        if line.startswith('MemAvailable:'):
            return int(line.split()[1]) / 1048576
    return 99.0


def proc_stats(pid: int) -> dict:
    out = {'rss_gib': 0.0, 'threads': 0, 'fds': 0}
    try:
        for line in open(f'/proc/{pid}/status'):
            if line.startswith('VmRSS:'):
                out['rss_gib'] = int(line.split()[1]) / 1048576
            elif line.startswith('Threads:'):
                out['threads'] = int(line.split()[1])
        out['fds'] = len(os.listdir(f'/proc/{pid}/fd'))
    except OSError:
        pass
    return out


ONLY: set = set()                 # --only light | heavy: one kind of route, to tell which one slows the other


def routes(hosts: list[str]):
    """One request of the mix: (label, path)."""
    h = random.choice(hosts)
    q = urllib.parse.quote
    while True:
        label, path = _pick(h, q)
        if not ONLY or ('heavy' in ONLY) == (label in HEAVY):          # light here means anything but a folder analysis
            return label, path


def _pick(h, q):
    return random.choice([
        ('search', f'/api/search?q={q(random.choice(PATTERNS))}&limit=500'),
        ('search one host', f'/api/search?q={q(random.choice(PATTERNS))}&host={h}'),
        ('search under', f'/api/search?under={q("/" + random.choice(WORDS) + str(random.randint(0, 40)))}&limit=500'),
        ('dupes', f'/api/dupes?host={h}&min_size=1'),
        ('dupes all', '/api/dupes?min_size=1'),
        ('file-changes', f'/api/file-changes?host={h}'),
        ('cold folders', f'/api/folders/cold?host={h}&years=1&min_size=1'),
        ('twin folders', f'/api/folders/duplicates?host={h}&min_files=3&min_size=1'),
        ('capacity', f'/api/capacity?host={h}'),
        ('browse', f'/api/browse?host={h}&path=/{random.choice(WORDS)}{random.randint(0, 40)}'),
        ('folder listing', f'/api/fs/browse?host={h}&path=/{random.choice(WORDS)}{random.randint(0, 40)}&brief=1'),
        ('filemap', f'/api/filemap?host={h}&min_size=1&folders=1'),
        ('filemap all', '/api/filemap?folders=1&min_size=1'),
        ('hostlogs', f'/api/hostlogs?host={h}'),
        ('hostlogs counts', '/api/hostlogs/counts'),
        ('hostlogs export', '/api/hostlogs/export?format=csv'),
        ('hosts', '/api/hosts'),
        ('graph', f'/api/graph?host={h}'),
        ('map', '/api/map'),
        ('canvas', f'/api/canvas?host={h}'),
    ])


class Server:
    def __init__(self, db_url: str, profile: str = ''):
        self.tmp = Path(tempfile.mkdtemp(prefix='sfstress-'))
        self.port = free_port()
        self.base = f'127.0.0.1:{self.port}'
        env = {'PATH': f'{Path(sys.executable).parent}:{os.environ["PATH"]}', 'HOME': str(self.tmp), 'STORAGEFORGE_DATA_DIR': str(self.tmp / 'data'),
               'STORAGEFORGE_DB': db_url, 'STORAGEFORGE_SESSION_SECRET': 's' * 48, 'STORAGEFORGE_VAULT_SECRET': 'v' * 48, 'LANG': 'C.UTF-8'}
        self.log = open(self.tmp / 'server.log', 'w')
        # with --profile, py-spy starts the server as its child (a process may trace its own children without root) and writes where time went
        spy = [str(Path(sys.executable).parent / 'py-spy'), 'record', '-r', '40', '-f', 'raw', '-o', profile, '--'] if profile else []
        self.profiled = bool(profile)
        self.p = subprocess.Popen([*spy, str(Path(sys.executable).parent / 'storageforge-index'), '--db', db_url, 'serve', '--port', str(self.port)],
                                  env=env, stdout=self.log, stderr=subprocess.STDOUT, start_new_session=True)
        for _ in range(200):
            try:
                socket.create_connection(('127.0.0.1', self.port), 0.2).close()
                return
            except OSError:
                if self.p.poll() is not None:
                    raise SystemExit(f'the server did not start:\n{(self.tmp / "server.log").read_text()[-3000:]}')
                time.sleep(0.1)
        raise SystemExit('the server did not answer in 20 s')

    def login(self) -> str:
        c = http.client.HTTPConnection(self.base, timeout=30)
        c.request('POST', '/api/login', json.dumps({'username': 'admin', 'password': PW}),
                  {'Content-Type': 'application/json', 'Origin': f'http://{self.base}'})
        r = c.getresponse()
        body = r.read()
        if r.status != 200:
            raise SystemExit(f'login: {r.status} {body[:300]!r}')
        return '; '.join(v.split(';', 1)[0] for k, v in r.getheaders() if k.lower() == 'set-cookie')

    def stop(self):
        if self.profiled and self.p.poll() is None:      # Ctrl-C makes py-spy write its profile, then it ends the server
            os.kill(self.p.pid, signal.SIGINT)
            try:
                self.p.wait(30)
            except subprocess.TimeoutExpired:
                pass
        try:                                             # the whole group, always: py-spy leaves its child running when it stops
            os.killpg(self.p.pid, signal.SIGTERM)
            time.sleep(2)
            os.killpg(self.p.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            self.p.wait(10)
        except subprocess.TimeoutExpired:
            pass
        self.log.close()


def writer(url: str, every: float, files: int, stop: threading.Event, log: list):
    """Scans landing while people use the server: a new host of `files` files every `every` seconds, through the scanner's own path. Each one
    moves the latest scan id, which is what empties the folder analysis cache."""
    sys.path.insert(0, str(ROOT))
    sys.path.insert(0, str(Path(__file__).parent))
    import seed as seeder
    from storageforge_index.db import Database
    db = Database(url)
    n = 0
    while not stop.wait(every):
        n += 1
        started = time.time()
        try:
            conn = db.patient().connect()
            try:
                name = f'w{os.getpid()}-{n}'
                hid = conn.scalar(f"INSERT INTO hosts (hostname, ssh_host, inventory_json, last_scanned_at) VALUES (:n, :n, '{{}}', {db.ts(':t')}) RETURNING host_id",
                                  {'n': name, 't': int(time.time())})
                mid = conn.scalar("INSERT INTO mounts (host_id, mount_point, filesystem_type, scan_state) VALUES (:h, '/', 'ext4', 'indexed') RETURNING mount_id", {'h': hid})
                scan = db.begin_scan(conn, hid)
                job = 90_000 + n
                db.stage_create(conn, job)
                db.stage_insert(conn, job, list(seeder.rows_for(n, files, random.Random(n))))
                db.apply_diff(conn, scan, job, mid, '/', True)
                db.stage_drop(conn, job)
                db.finish_scan(conn, scan, hid, {'entries': files, 'bytes': 0, 'added': files, 'modified': 0, 'deleted': 0, 'read_errors': 0}, 'ok', 1.0)
                log.append(('ok', round(time.time() - started, 1)))
            finally:
                conn.close()
        except Exception as exc:                  # a scan that can't land is a finding too
            log.append((f'{type(exc).__name__}: {str(exc)[:120]}', round(time.time() - started, 1)))


def stage(server: Server, cookie: str, hosts: list[str], clients: int, seconds: float) -> dict:
    stop_at = time.time() + seconds
    results = collections.defaultdict(list)          # label -> [(status, seconds)]
    errors = collections.Counter()
    shed = collections.Counter()           # 503s with Retry-After: the server pushing back, which the client waited out
    lock = threading.Lock()

    def client():
        conn = None
        while time.time() < stop_at:
            label, path = routes(hosts)
            started = time.perf_counter()
            try:
                for attempt in range(41):            # as the page does (kernel.js): a 503 with Retry-After is waited out and asked again, 40 times
                    if conn is None:
                        conn = http.client.HTTPConnection(server.base, timeout=30)
                    conn.request('GET', path, headers={'Cookie': cookie})
                    r = conn.getresponse()
                    r.read()
                    status = r.status
                    if r.getheader('Connection', '').lower() == 'close':
                        conn.close()
                        conn = None
                    if status == 503 and r.getheader('Retry-After') and attempt < 40:
                        if time.time() >= stop_at:
                            status = 'cut off'           # still being waited out when the stage ended: not the server's failure
                            break
                        with lock:
                            shed[label] += 1
                        time.sleep(min(30, int(r.getheader('Retry-After'))))
                        continue
                    break
            except Exception as exc:
                status = type(exc).__name__
                if conn:
                    conn.close()
                conn = None
            took = time.perf_counter() - started
            with lock:
                results[label].append((status, took))
                if status != 'cut off' and not (isinstance(status, int) and status < 500):
                    errors[(label, status)] += 1
    peak = {'rss_gib': 0.0, 'threads': 0, 'fds': 0}
    machine_low = 99.0
    threads = [threading.Thread(target=client, daemon=True) for _ in range(clients)]
    for t in threads:
        t.start()
    while any(t.is_alive() for t in threads):
        s = proc_stats(server.p.pid)
        peak = {k: max(peak[k], s[k]) for k in peak}
        machine_low = min(machine_low, machine_free_gib())
        if machine_low < LIMITS['machine_free_gib'] or peak['rss_gib'] > LIMITS['rss_gib']:
            os.killpg(server.p.pid, signal.SIGKILL)          # the machine comes first: the server is what gives
            break
        if server.p.poll() is not None:
            break
        time.sleep(0.5)
    for t in threads:
        t.join(35)
    every = [x for v in results.values() for x in v]
    times = sorted(t for _, t in every)
    pct = lambda xs: sorted(xs)[int(len(xs) * 0.99) - 1] if xs else 0          # noqa: E731
    light_p99 = pct([t for k, v in results.items() if k not in HEAVY | QUEUED for s_, t in v if s_ != 'cut off'])
    queued_p99 = pct([t for k, v in results.items() if k in QUEUED for s_, t in v if s_ != 'cut off'])
    heavy_p99 = pct([t for k, v in results.items() if k in HEAVY for s_, t in v if s_ != 'cut off'])
    p99 = times[int(len(times) * 0.99) - 1] if times else 0
    bad = sum(errors.values())
    return {'clients': clients, 'requests': len(every), 'per_s': len(every) / seconds, 'errors': bad, 'error_rate': bad / max(1, len(every)),
            'p50': times[len(times) // 2] if times else 0, 'p99': p99, 'light_p99': light_p99, 'queued_p99': queued_p99, 'heavy_p99': heavy_p99, 'peak': peak, 'machine_low_gib': machine_low, 'server_died': server.p.poll() is not None,
            'by_route': {k: {'n': len(v), 'p99': sorted(t for _, t in v)[int(len(v) * 0.99) - 1] if v else 0,
                             'status': dict(collections.Counter(str(s) for s, _ in v))} for k, v in sorted(results.items())},
            'errors_by': {f'{k[0]}: {k[1]}': n for k, n in errors.most_common(12)}, 'shed': dict(shed)}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('db')
    ap.add_argument('--stages', default='8,32,64,128,256')
    ap.add_argument('--seconds', type=float, default=20)
    ap.add_argument('--out', default='')
    ap.add_argument('--only', choices=['light', 'heavy'], help='one kind of route only')
    ap.add_argument('--writer', type=float, default=0, help='land a scan of a new host every this many seconds during the stages')
    ap.add_argument('--writer-files', type=int, default=20000)
    ap.add_argument('--profile', default='', help='where py-spy writes the server\'s profile (raw, for flame graphs)')
    a = ap.parse_args(argv)
    url = a.db if '://' in a.db else a.db
    if a.only:
        ONLY.add(a.only)
    server = Server(url, a.profile)
    report = {'db': a.db, 'stages': [], 'broke': None, 'server_log': str(server.tmp / 'server.log')}
    try:
        cookie = server.login()
        c = http.client.HTTPConnection(server.base, timeout=30)
        c.request('GET', '/api/search/hosts', headers={'Cookie': cookie})
        hosts = json.loads(c.getresponse().read())['hosts']
        print(f'server pid {server.p.pid} on {server.base}, {len(hosts)} hosts; limits {LIMITS}', flush=True)
        # a server warms its file map once at start (serve(): filemap-warm): timed on its own, then the stages meet it as people do
        started = time.time()
        while time.time() - started < 600:
            c = http.client.HTTPConnection(server.base, timeout=60)
            c.request('GET', '/api/filemap?folders=1&min_size=1MiB', headers={'Cookie': cookie})
            r = c.getresponse()
            r.read()
            if r.status == 200:
                break
            time.sleep(1)
        report['cold_start_s'] = round(time.time() - started, 1)
        print(f'cold start (folder index and file map built): {report["cold_start_s"]} s, server {proc_stats(server.p.pid)["rss_gib"]:.2f} GiB', flush=True)
        scans, stop_writer = [], threading.Event()
        if a.writer:
            threading.Thread(target=writer, args=(url, a.writer, a.writer_files, stop_writer, scans), daemon=True).start()
        for clients in map(int, a.stages.split(',')):
            landed = len(scans)
            r = stage(server, cookie, hosts, clients, a.seconds)
            r['scans'] = scans[landed:]
            report['stages'].append(r)
            print(f'{clients:4} clients: {r["requests"]:6} requests ({r["per_s"]:.0f}/s), errors {r["error_rate"]:.1%}, p50 {r["p50"]:.2f}s, light p99 {r["light_p99"]:.2f}s, queued p99 {r["queued_p99"]:.1f}s, analyses p99 {r["heavy_p99"]:.1f}s, '
                  f'server {r["peak"]["rss_gib"]:.2f} GiB {r["peak"]["threads"]} threads {r["peak"]["fds"]} fds, machine low {r["machine_low_gib"]:.1f} GiB free', flush=True)
            for k, n in r['errors_by'].items():
                print(f'       {n:5}  {k}')
            if a.writer:
                ok = [t for what, t in r['scans'] if what == 'ok']
                bad = [what for what, _ in r['scans'] if what != 'ok']
                print(f'       scans landed during it: {len(ok)} ({", ".join(f"{t}s" for t in ok)})' + (f'; FAILED: {bad}' if bad else ''))
            if r['shed']:
                print(f'       pushed back (503, waited out): ' + ', '.join(f'{k} {n}' for k, n in sorted(r['shed'].items(), key=lambda x: -x[1])))
            failed_scans = [w for w, _ in r.get('scans', []) if w != 'ok']
            why = ('a scan could not land: ' + failed_scans[0] if failed_scans else 'the server died' if r['server_died'] else 'the machine ran short of memory' if r['machine_low_gib'] < LIMITS['machine_free_gib']
                   else 'the server passed its memory limit' if r['peak']['rss_gib'] > LIMITS['rss_gib'] else f'errors {r["error_rate"]:.1%}' if r['error_rate'] > LIMITS['errors']
                   else f'light routes p99 {r["light_p99"]:.1f} s' if r['light_p99'] > LIMITS['light_p99']
                   else f'queued routes p99 {r["queued_p99"]:.0f} s' if r['queued_p99'] > LIMITS['queued_p99']
                   else f'analyses p99 {r["heavy_p99"]:.0f} s' if r['heavy_p99'] > LIMITS['heavy_p99'] else None)
            if why:
                report['broke'] = {'clients': clients, 'why': why}
                print(f'BROKE at {clients} clients: {why}', flush=True)
                break
    finally:
        if a.writer:
            stop_writer.set()
        server.stop()
        log = (server.tmp / 'server.log').read_text(errors='replace')
        report['server_log_tail'] = log[-4000:]
        if a.out:
            Path(a.out).write_text(json.dumps(report, indent=1, default=str))
        shutil.copy(server.tmp / 'server.log', Path(a.out).with_suffix('.server.log')) if a.out else None
    return 1 if report['broke'] else 0


if __name__ == '__main__':
    sys.exit(main())
