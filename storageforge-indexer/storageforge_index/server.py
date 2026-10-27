"""HTTP API and graph UI on Flask, with Flask-Login sessions for local accounts. Meant to sit behind a TLS
reverse proxy or on loopback.

GET  /healthz                       liveness + readiness (no auth)
GET  /                              graph UI (static, no auth; every data call needs a session)
GET  /planner                       storage planner UI (static, no auth)
POST /api/login  {"username", "password"}   start a session (cookie)
POST /api/logout                    end it
GET  /api/me                        the signed-in user
GET  /api/hosts                     indexed hosts
GET  /api/graph[?host=]             nodes and edges
GET  /api/canvas[?host=]            Obsidian .canvas download
GET  /api/search?q=&host=&size_gt=&type=&under=&limit=
GET  /api/jobs                      recent scan jobs
GET  /api/audit[?limit=]            newest audit entries
GET  /api/audit/verify              hash-chain verification (unlocks the vault)
POST /api/scan  {"host": "…"}       queue a vault-backed scan
GET  /api/keys                      vault keys (public halves) and host bindings
POST /api/keys  {"name", "type"}     generate a key inside the vault
POST /api/keys/install  {"key", "host", "user", "port", "password", "bind"}
                                    ssh-copy-id the public key, then optionally bind it for scans
GET  /api/access?host=               per host: how scans read the disks, and folders they could not open
GET  /api/access/script?host=&remove=1   the read-only scan access setup (or removal) script, to run as root
POST /api/access/grant  {"host", "password", "admin_user", "remove"}   run that script once over SSH with sudo
GET  /api/folders/duplicates?host=&min_files=&min_size=   folders that are copies by name and structure
GET  /api/browse?host=&path=         subfolders of a path with their indexed sizes (for picking move sources)
GET  /api/moves                      saved move plans;  POST creates one from {"name", "steps": [...]}
GET|PUT|DELETE /api/moves/<id>       one plan
POST /api/moves/check                check a plan (saved or not) against the index: sizes, space, mounts, loops
GET  /api/moves/<id>/script          the Bash script that runs the plan (copy, verify, cutover, install)
GET  /api/folders/cold?host=&years=&min_size=   folders whose newest file is older than the cutoff
GET  /api/git?host=                  git repositories found by scans, with their copies and archive state
GET  /api/shares/check?host=         the NFS/SMB shares in a host's design, checked against the index
GET  /api/shares/script?host=        the script that deploys them on the server and mounts them on clients
GET  /api/changes/types              the task types of change plans, with their fields (the UI builds its forms from it)
GET  /api/changes                    saved change plans;  POST creates one from {"name", "tasks": [...]}
GET|PUT|DELETE /api/changes/<id>     one plan
POST /api/changes/check              check a plan against the index, task by task, in order
GET  /api/changes/<id>/script        the Bash script (report, --apply, --destructive)
GET  /api/changes/<id>/ansible       the same plan as an Ansible playbook
GET  /api/docker?host=               containers, compose stacks (running, stopped, stored), volumes, unused volumes
GET  /api/docker/usage?host=&path=   containers that use a folder (bind mounts and volume data)
GET  /api/backups                    backups on disk;  POST {"kind": "essentials"|"full"} makes one now
GET  /api/planner/hosts             scanned hosts and saved designs
GET  /api/planner/design?host=&source=saved|scan   a design: the saved one, or built from the latest scan
PUT  /api/planner/design            save a storageforge/v1 blueprint (overlaid on the graph and reports)
"""
from __future__ import annotations

import json
import os
import queue
import re
import secrets
import subprocess
import sys
import threading
import time
import traceback
from datetime import timedelta
from pathlib import Path

from flask import Flask, Response, g, jsonify, request, send_from_directory
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager, current_user, login_required, login_user, logout_user
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix

from . import __version__, access, blueprint, canvas, changes, docker, folders, gitrepos, graph, keyinstall, moves, shares, users
from .capacity import parse_size
from .db import Database, epoch
from .remote import RemoteError
from .runner import connect_address, scan_via_vault
from .scanner import ScanOptions
from .search import SearchQuery, run_search
from .vault import AuditLog, SecretBuffer, Vault, VaultError, fingerprint

STATIC = Path(__file__).with_name('static')
SECURITY_HEADERS = {
    # style-src-attr allows style="" attributes (the planner sizes bars and swatches inline); never <style> or scripts.
    'Content-Security-Policy': "default-src 'self'; img-src 'self' data:; style-src 'self'; style-src-attr 'unsafe-inline'; "
                               "script-src 'self'; "
                               "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'X-Frame-Options': 'DENY',
    'Cross-Origin-Opener-Policy': 'same-origin', 'Cache-Control': 'no-store',
}
MAX_BODY = 4096
# all: every request · changes (default): requests that change something, rate-limit hits and server errors · off
ACCESS_LOG = os.environ.get('STORAGEFORGE_ACCESS_LOG', 'changes').lower()
BACKUP_HOUR = int(os.environ.get('STORAGEFORGE_BACKUP_HOUR', '3'))          # local hour for the nightly backup and prune
BACKUP_KEEP = int(os.environ.get('STORAGEFORGE_BACKUP_KEEP', '14'))         # essentials backups kept
BACKUP_FULL = int(os.environ.get('STORAGEFORGE_BACKUP_FULL_KEEP', '0'))     # full backups kept nightly (0: on demand only)
SCHEDULE_TICK = 600               # the scheduler looks for due hosts this often (seconds)
MAX_BLUEPRINT = 2 << 20           # planner designs are the one large body we accept
# Failed sign-ins allowed before /api/login answers 429; successful ones are not counted.
LOGIN_LIMIT_PER_IP = '10 per minute; 50 per hour'
LOGIN_LIMIT_PER_USER = '5 per minute; 20 per hour'
INSTALL_LIMIT = '10 per minute'     # each attempt is one password try on the target
KEY_NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}')


def session_secret_from_env() -> str:
    s = os.environ.get('STORAGEFORGE_SESSION_SECRET')
    path = os.environ.get('STORAGEFORGE_SESSION_SECRET_FILE')
    if not s and path:
        s = Path(path).read_text().strip()
    if s and len(s) < 32:
        raise SystemExit('STORAGEFORGE_SESSION_SECRET must be at least 32 characters (openssl rand -base64 48)')
    if not s:
        print('warning: STORAGEFORGE_SESSION_SECRET is not set; sessions end when the server restarts', file=sys.stderr)
        s = secrets.token_urlsafe(48)
    return s


class App:
    def __init__(self, db: Database, scan_interval: int | None = None, parallel: int = 4):
        self.db, self.parallel = db, parallel
        self.audit_key = None
        conn = db.connect()
        try:   # keep only the audit MAC key in memory; the KEK is wiped right after unlock
            with Vault(db, conn).unlock() as v:
                self.audit_key = SecretBuffer(32)
                self.audit_key.buf[:32] = v.audit_key.view()
                self.audit_key.length = 32
        except VaultError as exc:
            print(f'warning: vault locked ({exc}); API audit entries use plain SHA-256 chaining', file=sys.stderr)
        finally:
            conn.close()
        self.queue: queue.Queue[int] = queue.Queue()
        self.worker = threading.Thread(target=self._work, name='scan-worker', daemon=True)
        self.worker.start()
        conn = db.connect()
        try:   # jobs interrupted by a restart are marked failed, not left "running" forever
            conn.execute("UPDATE scan_jobs SET status = 'failed', finished_at = :t, result_json = :r "
                         "WHERE status IN ('queued', 'running')",
                         {'t': int(time.time()), 'r': json.dumps({'error': 'interrupted by restart'})})
        finally:
            conn.close()
        if scan_interval:
            threading.Thread(target=self._schedule, args=(scan_interval,), name='scheduler', daemon=True).start()
        threading.Thread(target=self._nightly, name='nightly', daemon=True).start()

    @staticmethod
    def canonical(conn, host: str) -> str:
        """One name per machine: a binding's IP, an ssh alias and the hostname all queue as the indexed hostname, so
        the scheduler and "Scan now" can't start two scans of one host under different names."""
        row = conn.all("""SELECT hostname FROM hosts WHERE lower(hostname) = lower(:h) OR ip_address = :h OR ssh_host = :h
                          ORDER BY last_scanned_at DESC""", {'h': host})
        return row[0][0] if row else host

    def enqueue(self, host: str, actor: str) -> int:
        conn = self.db.connect()
        try:
            host = self.canonical(conn, host)
            busy = conn.scalar("SELECT job_id FROM scan_jobs WHERE host = :h AND status IN ('queued', 'running')", {'h': host})
            if busy:
                return busy
            jid = conn.scalar("INSERT INTO scan_jobs (host, requested_by, queued_at) VALUES (:h, :a, :t) RETURNING job_id",
                              {'h': host, 'a': actor, 't': int(time.time())})
        finally:
            conn.close()
        self.queue.put(jid)
        return jid

    def audit(self, conn, actor: str, action: str, outcome: str, host: str | None, detail: dict):
        AuditLog(self.db, conn, self.audit_key).append(actor, action, outcome, host, None, detail)

    def _work(self):
        while True:
            jid = self.queue.get()
            conn = self.db.connect()
            try:
                host, actor = conn.all('SELECT host, requested_by FROM scan_jobs WHERE job_id = :j', {'j': jid})[0]
                conn.execute("UPDATE scan_jobs SET status = 'running', started_at = :t WHERE job_id = :j",
                             {'t': int(time.time()), 'j': jid})
                try:
                    opts = ScanOptions(parallel=self.parallel, include_fstypes=[
                        x for x in os.environ.get('STORAGEFORGE_INCLUDE_FSTYPES', '').split(',') if x])
                    res = scan_via_vault(self.db, host, opts, actor=actor,
                                         log=lambda m: print(f'[job {jid}] {m}', file=sys.stderr, flush=True))
                    status, result = res['status'], res
                except Exception as exc:
                    status, result = 'failed', {'error': str(exc)}
                conn.execute('UPDATE scan_jobs SET status = :s, finished_at = :t, result_json = :r WHERE job_id = :j',
                             {'s': status, 't': int(time.time()), 'r': json.dumps(result, default=str), 'j': jid})
                self.db.prune(conn)                  # cheap deletes; keeps change history and denied lists bounded
            except Exception:
                traceback.print_exc()
            finally:
                conn.close()

    def due_hosts(self, interval: int, now: float | None = None) -> list[str]:
        """Bound hosts whose last scan job (of any outcome) is older than the interval. A restart therefore never
        triggers a burst of scans, and a host that keeps failing is retried once per interval, not every tick."""
        now = now or time.time()
        conn = self.db.connect()
        try:
            due = []
            for (pattern,) in conn.all("""SELECT DISTINCT host_pattern FROM key_bindings
                                          WHERE pattern_kind = 'host' AND allowed_actions LIKE :a""", {'a': '%scan%'}):
                name = self.canonical(conn, pattern)
                last = conn.scalar('SELECT max(queued_at) FROM scan_jobs WHERE host IN (:n, :p)', {'n': name, 'p': pattern})
                done = epoch(conn.scalar('SELECT last_scanned_at FROM hosts WHERE hostname = :n', {'n': name}))
                last = max(x for x in (last, done, 0) if x is not None) or None     # CLI scans count too
                if name not in due and (last is None or now - last >= interval * 0.95):
                    due.append(name)
            return due
        finally:
            conn.close()

    def nightly_once(self) -> dict:
        """Backups and retention. Runs at BACKUP_HOUR, and at start-up when the newest essentials backup is a day old."""
        from . import backup
        conn = self.db.connect()
        out = {}
        try:
            try:
                out['backup'] = backup.create(self.db, 'essentials', keep=BACKUP_KEEP)
                if BACKUP_FULL:
                    out['full'] = backup.create(self.db, 'full', keep=BACKUP_FULL)
                self.audit(conn, 'system', 'backup.create', 'ok', None, {k: v['path'] for k, v in out.items()})
            except (Exception, SystemExit) as exc:
                out['error'] = str(exc)
                self.audit(conn, 'system', 'backup.create', 'failed', None, {'error': str(exc)[:300]})
            out['pruned'] = self.db.prune(conn)
        finally:
            conn.close()
        print(f'nightly: {out}', file=sys.stderr, flush=True)
        return out

    def _nightly(self):
        from . import backup
        time.sleep(120)                          # let start-up and any first scan settle
        try:
            newest = backup.listing()
            if self.db.dialect == 'sqlite' and (not [b for b in newest if b['kind'] == 'essentials']
                                                or time.time() - newest[0]['created'] > 86400):
                self.nightly_once()
        except Exception:
            traceback.print_exc()
        while True:
            now = time.localtime()
            wait = ((BACKUP_HOUR - now.tm_hour) % 24) * 3600 - now.tm_min * 60 - now.tm_sec
            time.sleep(wait if wait > 0 else wait + 86400)
            try:
                if self.db.dialect == 'sqlite':
                    self.nightly_once()
                else:
                    conn = self.db.connect()
                    try:
                        self.db.prune(conn)
                    finally:
                        conn.close()
            except Exception:
                traceback.print_exc()

    def _schedule(self, interval: int):
        while True:
            try:
                for h in self.due_hosts(interval):
                    self.enqueue(h, 'scheduler')
            except Exception:
                traceback.print_exc()
            time.sleep(min(interval, SCHEDULE_TICK))


def create_app(core: App, session_secret: str, secure_cookies: bool = False, proxy_hops: int = 0) -> Flask:
    web = Flask(__name__, static_folder=None)
    if proxy_hops:   # trust X-Forwarded-For from this many proxies, so limits and audit see the real client
        web.wsgi_app = ProxyFix(web.wsgi_app, x_for=proxy_hops, x_proto=proxy_hops)
    web.config.update(
        SECRET_KEY=session_secret, MAX_CONTENT_LENGTH=MAX_BODY,
        SESSION_COOKIE_NAME='sf_session', SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Strict',
        SESSION_COOKIE_SECURE=secure_cookies, PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
    )
    db = core.db
    login = LoginManager(web)
    login.session_protection = 'strong'
    limiter = Limiter(get_remote_address, app=web, storage_uri='memory://', headers_enabled=True)

    def conn():
        if 'conn' not in g:
            g.conn = db.connect()
        return g.conn

    @web.teardown_appcontext
    def close_conn(_exc):
        c = g.pop('conn', None)
        if c is not None:
            c.close()

    @login.user_loader
    def load_user(session_id):
        return users.load(conn(), session_id)

    @login.unauthorized_handler
    def unauthorized():
        return jsonify(error='sign in required'), 401

    @web.before_request
    def body_limit():
        if request.path == '/api/planner/design' and request.method == 'PUT':
            request.max_content_length = MAX_BLUEPRINT

    @web.after_request
    def headers(resp: Response):
        for k, v in SECURITY_HEADERS.items():
            resp.headers.setdefault(k, v)
        resp.headers['Server'] = f'StorageForge/{__version__}'
        if ACCESS_LOG == 'all' or (ACCESS_LOG == 'changes' and (request.method not in ('GET', 'HEAD') or resp.status_code >= 500
                                                                  or resp.status_code == 429)):
            print(f'{request.remote_addr} {request.method} {request.path} {resp.status_code}', file=sys.stderr, flush=True)
        return resp

    @web.errorhandler(Exception)
    def on_error(exc):
        if isinstance(exc, HTTPException):
            return jsonify(error=exc.description), exc.code
        if isinstance(exc, (ValueError, VaultError)):
            return jsonify(error=str(exc)), 400
        traceback.print_exc()
        return jsonify(error=f'internal error: {type(exc).__name__}'), 500

    def actor() -> str:
        return f'web:{current_user.username}' if current_user.is_authenticated else f'web:{request.remote_addr}'

    def json_body() -> dict:
        # JSON only: a cross-site form cannot send application/json without a CORS preflight, which we never grant.
        body = request.get_json(silent=True) if request.is_json else None
        if not isinstance(body, dict):
            raise ValueError('expected a JSON object body')
        return body

    # static UI and health
    @web.get('/')
    @web.get('/index.html')
    def index():
        return static('index.html')

    @web.get('/planner')
    def planner():
        return static('planner.html')

    @web.get('/<any("app.js", "topology.js", "checks.js", "moves.js", "changes.js", "gitview.js", "dockerview.js", "style.css", "favicon.svg", "planner.js", "planner.css"):name>')
    def static(name):
        resp = send_from_directory(STATIC, name, max_age=0)
        resp.headers['Cache-Control'] = 'no-cache'
        return resp

    @web.get('/healthz')
    def healthz():
        checks = {}
        try:
            c = conn()
            c.scalar('SELECT 1')
            checks['database'] = 'ok'
            checks['vault'] = 'initialised' if c.scalar('SELECT count(*) FROM vault_meta') else 'not initialised'
            checks['users'] = users.count(c)
        except Exception as exc:
            checks['database'] = f'error: {type(exc).__name__}'
        checks['worker'] = 'ok' if core.worker.is_alive() else 'dead'
        healthy = checks.get('database') == 'ok' and checks['worker'] == 'ok'
        return jsonify(status='ok' if healthy else 'unhealthy', version=__version__, **checks), 200 if healthy else 503

    def login_username() -> str:
        body = request.get_json(silent=True) if request.is_json else None
        return 'user:' + (str(body.get('username', '')).lower()[:64] if isinstance(body, dict) else '')

    def failed(resp: Response) -> bool:
        return resp.status_code == 401

    # session
    @web.post('/api/login')
    @limiter.limit(LOGIN_LIMIT_PER_IP, deduct_when=failed, error_message='too many failed sign-ins; try again later')
    @limiter.limit(LOGIN_LIMIT_PER_USER, key_func=login_username, deduct_when=failed,
                   error_message='too many failed sign-ins for this account; try again later')
    def api_login():
        body = json_body()
        name, password = str(body.get('username', '')), str(body.get('password', ''))
        user = users.authenticate(conn(), name, password) if name and password else None
        core.audit(conn(), f'web:{request.remote_addr}', 'web.login', 'ok' if user else 'denied', None, {'username': name[:64]})
        if not user:
            return jsonify(error='wrong username or password'), 401
        login_user(user)
        return jsonify(username=user.username)

    @web.post('/api/logout')
    def api_logout():
        logout_user()
        return jsonify(ok=True)

    @web.get('/api/me')
    @login_required
    def api_me():
        return jsonify(username=current_user.username)

    # data
    @web.get('/api/hosts')
    @login_required
    def api_hosts():
        rows = conn().all("""SELECT h.hostname, h.ip_address, h.os_info, h.last_scanned_at,
                                    (SELECT count(*) FROM file_records f JOIN mounts m ON m.mount_id = f.mount_id
                                     WHERE m.host_id = h.host_id)
                             FROM hosts h ORDER BY h.hostname""")
        graph_hosts = [r[0] for r in conn().all("SELECT label FROM graph_nodes WHERE kind = 'Host' AND host IS NOT NULL ORDER BY label")]
        return jsonify(indexed=[dict(zip(('hostname', 'ip', 'os', 'last_scanned_at', 'entries'), r)) for r in rows],
                       graph=graph_hosts)

    @web.get('/api/graph')
    @login_required
    def api_graph():
        return Response(json.dumps(graph.load(conn(), request.args.get('host') or None), default=str),
                        mimetype='application/json')

    @web.get('/api/canvas')
    @login_required
    def api_canvas():
        host = request.args.get('host') or None
        name = f'storageforge-{host or "network"}.canvas'.replace('/', '_').replace('"', '')
        return Response(canvas.dumps(graph.load(conn(), host)), mimetype='application/json',
                        headers={'Content-Disposition': f'attachment; filename="{name}"'})

    @web.get('/api/search')
    @login_required
    def api_search():
        q = request.args
        sq = SearchQuery(pattern=q.get('q') or None, hosts=[q['host']] if q.get('host') else [],
                         size_gt=parse_size(q['size_gt']) if q.get('size_gt') else None,
                         ftype=q.get('type') if q.get('type') in ('f', 'd', 'l') else None,
                         under=q.get('under') or None, limit=min(int(q.get('limit') or 100), 500), sort='path')
        if not (sq.pattern or sq.size_gt or sq.under):
            raise ValueError('give q, size_gt or under')
        return Response(json.dumps({'results': run_search(db, conn(), sq)}, default=str), mimetype='application/json')

    @web.get('/api/jobs')
    @login_required
    def api_jobs():
        rows = conn().all("""SELECT job_id, host, requested_by, status, queued_at, started_at, finished_at, result_json
                             FROM scan_jobs ORDER BY job_id DESC LIMIT 50""")
        return jsonify(jobs=[dict(zip(('job_id', 'host', 'requested_by', 'status', 'queued_at', 'started_at',
                                       'finished_at'), r[:7])) | {'result': json.loads(r[7] or 'null')} for r in rows])

    @web.get('/api/audit')
    @login_required
    def api_audit():
        limit = min(int(request.args.get('limit') or 100), 1000)
        return Response(json.dumps({'entries': AuditLog(db, conn(), None).tail(limit)}, default=str),
                        mimetype='application/json')

    @web.get('/api/audit/verify')
    @login_required
    def api_audit_verify():
        with Vault(db, conn()).unlock() as v:
            ok, n, bad = AuditLog(db, conn(), v.audit_key).verify()
        return jsonify(valid=ok, entries_checked=n, first_bad_id=bad)

    @web.post('/api/scan')
    @login_required
    def api_scan():
        host = str(json_body().get('host', '')).strip()
        if not host or len(host) > 253 or any(c.isspace() for c in host):
            raise ValueError('body must be {"host": "<hostname or IP>"}')
        jid = core.enqueue(host, actor())
        core.audit(conn(), actor(), 'api.scan.request', 'info', host, {'job_id': jid})
        return jsonify(job_id=jid), 202

    # vault keys: generate, install with ssh-copy-id, bind
    @web.get('/api/keys')
    @login_required
    def api_keys():
        v = Vault(db, conn())
        keys = [k | {'public_key': v.public_key(k['name'])} for k in v.list_keys()]
        return jsonify(keys=keys, bindings=v.bindings())

    @web.post('/api/keys')
    @login_required
    def api_key_generate():
        body = json_body()
        name, kind = str(body.get('name', '')).strip(), str(body.get('type') or 'ed25519')
        if not KEY_NAME.fullmatch(name):
            raise ValueError('key name: letters, digits, . _ - only (max 64)')
        if kind not in ('ed25519', 'rsa'):
            raise ValueError('type must be ed25519 or rsa')
        if conn().scalar('SELECT 1 FROM ssh_keys WHERE name = :n', {'n': name}):
            raise ValueError(f'a key named {name!r} already exists')
        with Vault(db, conn()).unlock() as v:
            info = v.generate_key(name, kind)
        core.audit(conn(), actor(), 'vault.key.generate', 'ok', None,
                   {'name': name, 'type': info['type'], 'fingerprint': info['fingerprint']})
        return jsonify(info), 201

    @web.post('/api/keys/install')
    @login_required
    @limiter.limit(INSTALL_LIMIT, key_func=lambda: f'install:{current_user.get_id()}')
    def api_key_install():
        body = json_body()
        name, host, user = (str(body.get(k, '')).strip() for k in ('key', 'host', 'user'))
        password = str(body.get('password', ''))
        port = int(body.get('port') or 22)
        keyinstall.validate(host, user, port)
        public = Vault(db, conn()).public_key(name)
        detail = {'key': name, 'user': user, 'port': port}
        try:
            if keyinstall.key_login_works(db, conn(), name, host, user, port):   # already installed: no duplicate line
                res = {'host': host, 'user': user, 'port': port, 'keys_added': 0, 'verified': True}
            else:
                res = keyinstall.install_public_key(public, host, user, password, port)
                res['verified'] = keyinstall.key_login_works(db, conn(), name, host, user, port)
        except keyinstall.InstallError as exc:
            core.audit(conn(), actor(), 'ssh.copy-id', 'failed', host, detail | {'error': str(exc)})
            return jsonify(error=str(exc)), 502
        finally:
            del password
        core.audit(conn(), actor(), 'ssh.copy-id', 'ok' if res['verified'] else 'failed', host,
                   detail | {'fingerprint': fingerprint(public), 'keys_added': res['keys_added'], 'verified': res['verified']})
        if not res['verified']:
            return jsonify(error='ssh-copy-id finished, but logging in with the key still fails. Check that the host '
                                 'allows public key login and that ~/.ssh is not group- or world-writable.'), 502
        if body.get('bind'):
            v = Vault(db, conn())
            existing = next((b for b in v.bindings() if b['key'] == name and b['pattern'] == host and b['user'] == user), None)
            if existing:
                res['binding_id'] = existing['binding_id']
            else:
                actions = 'scan,checksum' if body.get('checksum') else 'scan'
                res['binding_id'] = v.bind(name, host, user, port, actions)
                core.audit(conn(), actor(), 'vault.bind', 'ok', host, detail | {'binding_id': res['binding_id'], 'actions': actions})
        return jsonify(res)

    # planner designs (storageforge/v1 blueprints)
    @web.get('/api/access')
    @login_required
    def api_access():
        return jsonify(hosts=access.status(conn(), request.args.get('host') or None))

    @web.get('/api/access/script')
    @login_required
    def api_access_script():
        host = request.args.get('host', '').strip()
        user = request.args.get('user', '').strip()
        if host and not user:
            with Vault(db, conn()).unlock() as v:
                user = v.resolve(connect_address(conn(), host), 'scan').user
        if not user:
            raise ValueError('give host (to use its scan user) or user')
        script = (access.remove_script if request.args.get('remove') else access.setup_script)(user)
        return jsonify(user=user, script=script, readonly_dir=access.READONLY_DIR, group=access.GROUP)

    @web.post('/api/access/grant')
    @login_required
    @limiter.limit(INSTALL_LIMIT, key_func=lambda: f'grant:{current_user.get_id()}')
    def api_access_grant():
        body = json_body()
        host, admin = str(body.get('host', '')).strip(), str(body.get('admin_user') or '').strip() or None
        password, remove = str(body.get('password', '')), bool(body.get('remove'))
        keyinstall.validate(host, admin or 'root', 22)
        action = 'access.revoke' if remove else 'access.grant'
        try:
            res = access.grant(db, conn(), host, password, admin, remove)
        except (RemoteError, subprocess.TimeoutExpired) as exc:
            msg = str(exc) if isinstance(exc, RemoteError) else 'timed out'
            core.audit(conn(), actor(), action, 'failed', host, {'via': admin, 'error': msg})
            return jsonify(error=msg), 502
        finally:
            del password
        core.audit(conn(), actor(), action, 'ok', host, {'user': res['user'], 'via': res['via']})
        return jsonify(res)

    @web.get('/api/browse')
    @login_required
    def api_browse():
        return jsonify(moves.browse(conn(), request.args.get('host', ''), request.args.get('path') or '/'))

    @web.get('/api/moves')
    @login_required
    def api_moves():
        return jsonify(plans=moves.list_plans(conn()))

    @web.post('/api/moves')
    @login_required
    def api_moves_create():
        pid = moves.save_plan(conn(), json_body(), actor())
        core.audit(conn(), actor(), 'moves.save', 'ok', None, {'plan': pid})
        return jsonify(moves.get_plan(conn(), pid)), 201

    @web.route('/api/moves/<int:plan_id>', methods=['GET', 'PUT', 'DELETE'])
    @login_required
    def api_move(plan_id):
        try:
            if request.method == 'PUT':
                moves.save_plan(conn(), json_body(), actor(), plan_id)
                core.audit(conn(), actor(), 'moves.save', 'ok', None, {'plan': plan_id})
            elif request.method == 'DELETE':
                moves.get_plan(conn(), plan_id)
                moves.delete_plan(conn(), plan_id)
                core.audit(conn(), actor(), 'moves.delete', 'ok', None, {'plan': plan_id})
                return jsonify(deleted=plan_id)
            return jsonify(moves.get_plan(conn(), plan_id))
        except LookupError as exc:
            return jsonify(error=str(exc)), 404

    @web.post('/api/moves/check')
    @login_required
    def api_moves_check():
        return jsonify(moves.check(conn(), moves.normalize(json_body())))

    @web.get('/api/moves/<int:plan_id>/script')
    @login_required
    def api_move_script(plan_id):
        try:
            plan = moves.get_plan(conn(), plan_id)
        except LookupError as exc:
            return jsonify(error=str(exc)), 404
        name = moves.slug(plan['name']) + '.sh'
        core.audit(conn(), actor(), 'moves.script', 'ok', None, {'plan': plan_id})
        return Response(moves.script(conn(), plan), mimetype='text/x-shellscript',
                        headers={'Content-Disposition': f'attachment; filename="{name}"'})

    @web.get('/api/git')
    @login_required
    def api_git():
        return jsonify(gitrepos.listing(conn(), request.args.get('host') or None, bool(request.args.get('all'))))

    @web.get('/api/shares/check')
    @login_required
    def api_shares_check():
        try:
            return jsonify(shares.check(conn(), request.args.get('host', '')))
        except LookupError as exc:
            return jsonify(error=str(exc)), 404

    @web.get('/api/shares/script')
    @login_required
    def api_shares_script():
        host = request.args.get('host', '')
        try:
            text = shares.script(conn(), host)
        except LookupError as exc:
            return jsonify(error=str(exc)), 404
        core.audit(conn(), actor(), 'shares.script', 'ok', host, {})
        return Response(text, mimetype='text/x-shellscript',
                        headers={'Content-Disposition': f'attachment; filename="shares-{moves.host_slug(host)}.sh"'})

    @web.get('/api/changes/types')
    @login_required
    def api_change_types():
        return jsonify(types=changes.TYPES)

    @web.get('/api/changes')
    @login_required
    def api_changes():
        return jsonify(plans=changes.list_plans(conn()))

    @web.post('/api/changes')
    @login_required
    def api_changes_create():
        pid = changes.save_plan(conn(), json_body(), actor())
        core.audit(conn(), actor(), 'changes.save', 'ok', None, {'plan': pid})
        return jsonify(changes.get_plan(conn(), pid)), 201

    @web.route('/api/changes/<int:plan_id>', methods=['GET', 'PUT', 'DELETE'])
    @login_required
    def api_change(plan_id):
        try:
            if request.method == 'PUT':
                changes.save_plan(conn(), json_body(), actor(), plan_id)
                core.audit(conn(), actor(), 'changes.save', 'ok', None, {'plan': plan_id})
            elif request.method == 'DELETE':
                changes.get_plan(conn(), plan_id)
                changes.delete_plan(conn(), plan_id)
                core.audit(conn(), actor(), 'changes.delete', 'ok', None, {'plan': plan_id})
                return jsonify(deleted=plan_id)
            return jsonify(changes.get_plan(conn(), plan_id))
        except LookupError as exc:
            return jsonify(error=str(exc)), 404

    @web.post('/api/changes/check')
    @login_required
    def api_changes_check():
        return jsonify(changes.check(conn(), changes.normalize(json_body())))

    @web.get('/api/changes/<int:plan_id>/<any("script", "ansible"):kind>')
    @login_required
    def api_change_out(plan_id, kind):
        try:
            plan = changes.get_plan(conn(), plan_id)
        except LookupError as exc:
            return jsonify(error=str(exc)), 404
        text = changes.script(conn(), plan) if kind == 'script' else changes.ansible(conn(), plan)
        name = f'changes-{moves.slug(plan["name"])}.' + ('sh' if kind == 'script' else 'yml')
        core.audit(conn(), actor(), f'changes.{kind}', 'ok', None, {'plan': plan_id})
        return Response(text, mimetype='text/x-shellscript' if kind == 'script' else 'application/yaml',
                        headers={'Content-Disposition': f'attachment; filename="{name}"'})

    @web.get('/api/docker')
    @login_required
    def api_docker():
        return jsonify(hosts=docker.listing(conn(), request.args.get('host') or None))

    @web.get('/api/docker/usage')
    @login_required
    def api_docker_usage():
        host, path = request.args.get('host') or None, request.args.get('path') or ''
        if path:
            if not host:
                raise ValueError('give host with path')
            return jsonify(usage=docker.users_of(conn(), host, path))
        return jsonify(usage=docker.usage(conn(), host))

    @web.get('/api/backups')
    @login_required
    def api_backups():
        from . import backup
        return jsonify(backups=backup.listing() if db.dialect == 'sqlite' else [], hour=BACKUP_HOUR, keep=BACKUP_KEEP,
                       full_keep=BACKUP_FULL)

    @web.post('/api/backups')
    @login_required
    @limiter.limit('6 per hour', key_func=lambda: f'backup:{current_user.get_id()}')
    def api_backup_now():
        from . import backup
        kind = 'full' if (json_body().get('kind') == 'full') else 'essentials'
        res = backup.create(db, kind, keep=BACKUP_KEEP if kind == 'essentials' else max(BACKUP_FULL, 2))
        core.audit(conn(), actor(), 'backup.create', 'ok', None, {'path': res['path'], 'bytes': res['bytes']})
        return jsonify(res)

    folder_cache: dict = {}

    @web.get('/api/folders/cold')
    @login_required
    def api_folders_cold():
        host = request.args.get('host') or None
        years = max(0.1, float(request.args.get('years') or 2))
        min_size = parse_size(request.args.get('min_size') or '1GiB')
        key = ('cold', host, years, min_size, conn().scalar('SELECT max(scan_id) FROM scans'))
        if key not in folder_cache:
            folder_cache.clear()
            folder_cache[key] = folders.cold_folders(conn(), host, years, min_size, limit=200)
        return jsonify(folder_cache[key])

    @web.get('/api/folders/duplicates')
    @login_required
    def api_folder_dupes():
        host = request.args.get('host') or None
        min_files = max(1, int(request.args.get('min_files') or 3))
        min_size = parse_size(request.args.get('min_size') or '1MiB')
        key = (host, min_files, min_size, conn().scalar('SELECT max(scan_id) FROM scans'))
        if key not in folder_cache:
            folder_cache.clear()
            folder_cache[key] = folders.duplicate_folders(conn(), host, min_files, min_size, limit=200)
        return jsonify(folder_cache[key])

    def scanned(host: str) -> bool:
        return bool(conn().scalar('SELECT 1 FROM hosts WHERE hostname = :h', {'h': host}))

    @web.get('/api/planner/hosts')
    @login_required
    def api_planner_hosts():
        hosts = {r[0]: {'host': r[0], 'scanned': True, 'last_scanned_at': r[1], 'saved': False, 'saved_at': None}
                 for r in conn().all('SELECT hostname, last_scanned_at FROM hosts ORDER BY hostname')}
        for name, at in conn().all('SELECT hostname, imported_at FROM blueprints ORDER BY hostname'):
            hosts.setdefault(name, {'host': name, 'scanned': False, 'last_scanned_at': None})
            hosts[name].update(saved=True, saved_at=at)
        return jsonify(hosts=sorted(hosts.values(), key=lambda h: h['host']))

    @web.get('/api/planner/design')
    @login_required
    def api_planner_design():
        host, source = request.args.get('host', '').strip(), request.args.get('source') or 'saved'
        if not host:
            raise ValueError('give host')
        saved = graph.stored_blueprint(conn(), host)
        saved_at = conn().scalar('SELECT imported_at FROM blueprints WHERE hostname = :h', {'h': host})
        if source == 'saved' and saved:
            return jsonify(host=host, source='saved', saved_at=saved_at, scanned=scanned(host), blueprint=saved)
        if not scanned(host):
            return jsonify(error=f'{host} has no saved design and has not been scanned'), 404
        bp = blueprint.merge_intent(blueprint.from_index(conn(), host), saved)
        return jsonify(host=host, source='scan', saved_at=saved_at, scanned=True, blueprint=bp)

    @web.put('/api/planner/design')
    @login_required
    def api_planner_save():
        bp = json_body()
        if bp.get('apiVersion') != 'storageforge/v1' or bp.get('kind') != 'StorageBlueprint':
            raise ValueError('expected a storageforge/v1 StorageBlueprint')
        host = str((bp.get('metadata') or {}).get('host') or '').strip()
        if not host or len(host) > 253 or any(c.isspace() for c in host):
            raise ValueError('metadata.host must be a hostname')
        graph.store_blueprint(conn(), bp)
        rebuilt = None
        if scanned(host):            # overlay the design on the scanned graph right away
            rebuilt = dict(zip(('nodes', 'edges'), graph.rebuild_host(db, conn(), host)))
        else:                        # a planned host: the design is the whole graph
            from .payloads import node_from_blueprint
            nodes, edges = graph.build(node_from_blueprint(bp))
            graph.save(db, conn(), host, nodes, edges)
            rebuilt = {'nodes': len(nodes), 'edges': len(edges)}
        core.audit(conn(), actor(), 'planner.save', 'ok', host,
                   {'devices': len(bp.get('devices') or []), 'pools': len(bp.get('pools') or []),
                    'protection': len(bp.get('protection') or []), 'graph': rebuilt})
        return jsonify(host=host, saved_at=int(time.time()), graph=rebuilt)

    return web


def serve(db: Database, host: str, port: int, scan_interval: int | None, parallel: int = 4):
    from waitress import serve as waitress_serve
    conn = db.connect()
    try:
        if not users.count(conn):
            print('warning: no web users yet; create one with: storageforge-index user add <name>', file=sys.stderr)
        stale = conn.all("SELECT scan_id FROM scans WHERE status = 'running'")   # killed by the last shutdown
        if stale:
            conn.execute(f"UPDATE scans SET status = 'failed', finished_at = {db.ts(':now')} WHERE status = 'running'",
                         {'now': int(time.time())})
            print(f'marked {len(stale)} interrupted scan(s) as failed', file=sys.stderr)
    finally:
        conn.close()
    secure = os.environ.get('STORAGEFORGE_COOKIE_SECURE', '0').lower() in ('1', 'true', 'yes')
    hops = int(os.environ.get('STORAGEFORGE_PROXY_HOPS', '0'))
    web = create_app(App(db, scan_interval, parallel), session_secret_from_env(), secure, hops)
    print(f'StorageForge {__version__} listening on http://{host}:{port}', file=sys.stderr, flush=True)
    waitress_serve(web, host=host, port=port, threads=8, ident=f'StorageForge/{__version__}', _quiet=True)
