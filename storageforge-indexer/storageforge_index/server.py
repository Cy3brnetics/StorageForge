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

from . import __version__, blueprint, canvas, graph, keyinstall, users
from .capacity import parse_size
from .db import Database
from .runner import scan_via_vault
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

    def enqueue(self, host: str, actor: str) -> int:
        conn = self.db.connect()
        try:
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
            except Exception:
                traceback.print_exc()
            finally:
                conn.close()

    def _schedule(self, interval: int):
        while True:
            try:
                conn = self.db.connect()
                try:
                    hosts = [r[0] for r in conn.all("""SELECT DISTINCT host_pattern FROM key_bindings
                                                       WHERE pattern_kind = 'host' AND allowed_actions LIKE :a""",
                                                    {'a': '%scan%'})]
                finally:
                    conn.close()
                for h in hosts:
                    self.enqueue(h, 'scheduler')
            except Exception:
                traceback.print_exc()
            time.sleep(interval)


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

    @web.get('/<any("app.js", "style.css", "favicon.svg", "planner.js", "planner.css"):name>')
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
    finally:
        conn.close()
    secure = os.environ.get('STORAGEFORGE_COOKIE_SECURE', '0').lower() in ('1', 'true', 'yes')
    hops = int(os.environ.get('STORAGEFORGE_PROXY_HOPS', '0'))
    web = create_app(App(db, scan_interval, parallel), session_secret_from_env(), secure, hops)
    print(f'StorageForge {__version__} listening on http://{host}:{port}', file=sys.stderr, flush=True)
    waitress_serve(web, host=host, port=port, threads=8, ident=f'StorageForge/{__version__}', _quiet=True)
