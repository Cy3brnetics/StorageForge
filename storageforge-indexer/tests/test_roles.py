"""Permissions, custom roles and invite links."""
import re
import sqlite3
import tempfile
import time
import unittest
from unittest import mock

from storageforge_index import deploy, permissions, preflight, scheduler, server, users
from storageforge_index.db import MIGRATIONS, Database

PW = 'a long enough password'


def old_required_role(method, path):
    """required_role as it was before permissions: the built-in roles must keep exactly this."""
    under = lambda roots: any(path == r or path.startswith(r + '/') for r in roots)   # noqa: E731
    if path in ('/api/login', '/api/logout', '/api/reauth', '/api/me', '/api/me/password'):
        return 'viewer'
    if under(('/api/users', '/api/deploy/settings', '/api/audit/verify')):
        return 'admin'
    if method in ('GET', 'HEAD'):
        return 'operator' if path.rsplit('/', 1)[-1] in ('script', 'ansible') or path in ('/api/git/status', '/api/git/history', '/api/git/commit') else 'viewer'
    if under(('/api/keys', '/api/bindings', '/api/hostkey', '/api/access/grant', '/api/deploy/access', '/api/backups', '/api/planner/example')) \
            or (method == 'DELETE' and re.fullmatch(r'/api/hosts/[^/]+', path)):
        return 'admin'
    return 'operator'


# Deliberately tighter than before: these handed runnable scripts, and a report token, to viewers.
TIGHTENED = ('/install-script', '/cron', '/api/hostconfigs/bundle')
NEW_ROUTES = ('/api/remote/nodes', '/api/jobs/state', '/dedupe', '/api/invites', '/api/roles', '/api/search/hosts', '/api/enroll', '/api/clamav', '/api/security', '/api/map/', '/api/devices', '/api/dsl/', '/api/fleet', '/api/netscan', '/api/traffic', '/api/hostlogs', '/api/scans/signing')


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Database(f'sqlite:///{self.tmp.name}/idx.db')
        self.conn = self.db.connect()
        self.addCleanup(self.conn.close)
        self.db.migrate(self.conn)
        users.create(self.conn, 'root', PW, 'admin')
        self.web = server.create_app(server.App(self.db), 's' * 48)

    def as_user(self, name, role=None):
        if role:
            users.create(self.conn, name, PW, role)
        c = self.web.test_client()
        self.assertEqual(c.post('/api/login', json={'username': name, 'password': PW}).status_code, 200)
        return c


class RouteRules(Base):
    def rules(self):
        for rule in self.web.url_map.iter_rules():
            for method in rule.methods - {'OPTIONS', 'HEAD'}:
                path = re.sub(r'<int:\w+>', '1', rule.rule)
                path = re.sub(r'<any\(([^)]*)\):\w+>', lambda m: m[1].split(',')[0].strip(' "'), path)
                yield method, re.sub(r'<[^>]+>', 'x', path)

    def test_every_route_is_listed(self):
        missing = [(m, p) for m, p in self.rules() if permissions.required(m, p) == permissions.EVERYTHING]
        self.assertEqual(missing, [], 'add a rule to permissions._RULES')

    def test_every_rule_names_a_real_permission(self):
        for _, _, perm in permissions._RULES:
            self.assertIn(perm, permissions.ALL)

    def test_built_in_roles_keep_their_access(self):
        rank = {'viewer': 0, 'operator': 1, 'admin': 2}
        paths = set(self.rules())
        for rule in self.web.url_map.iter_rules():      # each verb of the routes that take one
            m = re.search(r'<any\(([^)]*)\):\w+>', rule.rule)
            if m and rule.rule.startswith('/api/'):
                for verb in m[1].split(','):
                    paths.add(('POST' if 'POST' in rule.methods else 'GET',
                               re.sub(r'<[^>]+>', 'x', rule.rule.replace(m[0], verb.strip(' "')))))
        for method, path in sorted(paths):
            if not path.startswith('/api/') or any(path.endswith(t) or t in path for t in TIGHTENED + NEW_ROUTES):
                continue
            before = rank[old_required_role(method, path)]
            for role, level in rank.items():
                self.assertEqual(permissions.allows(permissions.BUILTIN[role][1], method, path), level >= before, (role, method, path))

    def test_tightened_routes_need_scripts(self):
        for path in ('/api/scheduler/schedules/1/install-script', '/api/scheduler/schedules/1/cron', '/api/hostconfigs/bundle'):
            self.assertEqual(permissions.required('GET', path), 'plans.scripts')
            self.assertFalse(permissions.allows(permissions.BUILTIN['viewer'][1], 'GET', path))

    def test_unlisted_routes_are_denied(self):
        self.assertEqual(permissions.required('POST', '/api/some-new-route'), permissions.EVERYTHING)
        self.assertFalse(permissions.allows(permissions.BUILTIN['operator'][1], 'POST', '/api/some-new-route'))
        self.assertTrue(permissions.allows(permissions.ALL, 'POST', '/api/some-new-route'))


class SearchOnly(Base):
    def test_only_search_answers(self):
        c = self.as_user('sam', 'search')
        self.assertEqual(c.get('/api/search?q=*').status_code, 200)
        self.assertEqual(c.get('/api/search/hosts').status_code, 200)
        self.assertEqual(c.get('/api/me').json['permissions'], ['search.files'])
        allowed = {'/api/search', '/api/search/hosts', *permissions.ANYONE}
        for rule in self.web.url_map.iter_rules():
            if not rule.rule.startswith('/api/') or rule.rule in allowed or rule.rule in ('/api/jobs/report', '/api/jobs/state', '/api/scheduler/report'):
                continue
            path = re.sub(r'<int:\w+>', '1', rule.rule)
            path = re.sub(r'<any\(([^)]*)\):\w+>', lambda m: m[1].split(',')[0].strip(' "'), path)
            path = re.sub(r'<[^>]+>', 'x', path)
            for method in rule.methods - {'OPTIONS', 'HEAD'}:
                self.assertEqual(c.open(path, method=method, json={}).status_code, 403, (method, path))

    def test_lands_on_the_search_page(self):
        c = self.as_user('sam', 'search')
        for page in ('/', '/planner'):
            r = c.get(page)
            self.assertEqual((r.status_code, r.headers['Location']), (302, '/search'))
        self.assertIn(b'id="sform"', c.get('/search').data)
        self.assertEqual(self.web.test_client().get('/search').status_code, 302)


class CustomRoles(Base):
    def test_a_custom_role_gets_what_it_lists(self):
        admin = self.as_user('root')
        r = admin.post('/api/roles', json={'name': 'scanner', 'description': 'runs scans', 'permissions': ['scans.view', 'hosts.view']})
        self.assertEqual(r.status_code, 200)
        self.assertIn('scanner', [x['name'] for x in r.json['roles']])
        c = self.as_user('scott', 'scanner')
        self.assertEqual(c.get('/api/jobs').status_code, 200)
        self.assertEqual(c.get('/api/keys').status_code, 403)
        admin.put('/api/roles/scanner', json={'permissions': ['hosts.view']})
        self.assertEqual(c.get('/api/jobs').status_code, 403)            # takes effect at once

    def test_built_in_roles_are_fixed(self):
        admin = self.as_user('root')
        for r in (admin.put('/api/roles/viewer', json={'permissions': []}), admin.delete('/api/roles/admin'),
                  admin.post('/api/roles', json={'name': 'operator', 'permissions': []})):
            self.assertEqual(r.status_code, 400)
        self.assertEqual(admin.post('/api/roles', json={'name': 'x', 'permissions': ['no.such']}).status_code, 400)

    def test_a_role_in_use_stays(self):
        admin = self.as_user('root')
        admin.post('/api/roles', json={'name': 'temp', 'permissions': []})
        users.create(self.conn, 'tess', PW, 'temp')
        self.assertIn('still have', admin.delete('/api/roles/temp').json['error'])
        users.remove(self.conn, 'tess')
        invite = admin.post('/api/invites', json={'role': 'temp'}).json
        self.assertIn('open invite', admin.delete('/api/roles/temp').json['error'])
        admin.delete(f'/api/invites/{invite["id"]}')
        self.assertEqual(admin.delete('/api/roles/temp').status_code, 200)

    def test_a_missing_role_allows_nothing(self):
        self.assertEqual(users.permissions_of(self.conn, 'gone'), frozenset())

    def test_nobody_hands_out_more_than_they_hold(self):
        admin = self.as_user('root')
        admin.post('/api/roles', json={'name': 'helpdesk', 'permissions': ['users.manage', 'roles.manage', 'hosts.view', 'search.files']})
        c = self.as_user('hal', 'helpdesk')
        for r in (c.post('/api/invites', json={'role': 'admin'}),
                  c.post('/api/users', json={'username': 'evil', 'password': PW, 'role': 'admin'}),
                  c.post('/api/roles', json={'name': 'mine', 'permissions': ['deploy.apply']}),
                  c.put('/api/users/hal', json={'role': 'admin'}),
                  c.put('/api/users/root', json={'disabled': True}),
                  c.post('/api/users/root/reset-link', json={}),
                  c.delete('/api/users/root')):
            self.assertEqual(r.status_code, 403, r.json)
        self.assertEqual(c.post('/api/invites', json={'role': 'search'}).status_code, 200)
        self.assertEqual(c.post('/api/roles', json={'name': 'lesser', 'permissions': ['hosts.view']}).status_code, 200)


class DeployLimits(Base):
    def test_mode_and_destructive_are_checked(self):
        admin = self.as_user('root')
        admin.post('/api/roles', json={'name': 'dry', 'permissions': ['deploy.report']})
        c = self.as_user('dana', 'dry')
        self.assertEqual(c.post('/api/deploy/start', json={'kind': 'jobs', 'ref': 'x', 'mode': 'apply'}).status_code, 403)
        self.assertEqual(c.post('/api/deploy/start', json={'kind': 'jobs', 'ref': 'x', 'destructive': True}).status_code, 403)
        self.assertNotEqual(c.post('/api/deploy/start', json={'kind': 'nope', 'ref': 'x', 'mode': 'report'}).status_code, 403)


class Invites(Base):
    def invite(self, role='viewer', **extra):
        return self.as_user('root').post('/api/invites', json={'role': role, **extra}).json

    def test_enroll_once(self):
        i = self.invite()
        anon = self.web.test_client()
        self.assertEqual(anon.post('/api/enroll/check', json={'token': i['token']}).json['role'], 'viewer')
        r = anon.post('/api/enroll', json={'token': i['token'], 'username': 'nina', 'password': PW, 'role': 'admin'})
        self.assertEqual((r.status_code, r.json['role']), (200, 'viewer'))      # the link decides the role
        self.assertEqual(self.as_user('nina').get('/api/me').json['role'], 'viewer')
        r = anon.post('/api/enroll', json={'token': i['token'], 'username': 'two', 'password': PW})
        self.assertEqual(r.status_code, 403)
        self.assertEqual(self.conn.scalar("SELECT count(*) FROM users WHERE username = 'two'"), 0)

    def test_a_refused_account_leaves_the_link_usable(self):
        i = self.invite()
        anon = self.web.test_client()
        self.assertEqual(anon.post('/api/enroll', json={'token': i['token'], 'username': 'nina', 'password': 'short'}).status_code, 400)
        self.assertEqual(anon.post('/api/enroll', json={'token': i['token'], 'username': 'ROOT', 'password': PW}).status_code, 400)
        self.assertEqual(anon.post('/api/enroll', json={'token': i['token'], 'username': 'nina', 'password': PW}).status_code, 200)

    def test_bad_expired_and_revoked_links(self):
        anon = self.web.test_client()
        self.assertEqual(anon.post('/api/enroll/check', json={'token': 'nope'}).status_code, 403)
        i = self.invite()
        self.conn.execute('UPDATE invites SET expires_at = :t WHERE invite_id = :i', {'t': int(time.time()) - 1, 'i': i['id']})
        self.assertEqual(anon.post('/api/enroll', json={'token': i['token'], 'username': 'late', 'password': PW}).status_code, 403)
        i = self.invite()
        self.as_user('root').delete(f'/api/invites/{i["id"]}')
        self.assertEqual(anon.post('/api/enroll', json={'token': i['token'], 'username': 'late', 'password': PW}).status_code, 403)

    def test_token_is_not_stored_or_listed(self):
        i = self.invite()
        admin = self.as_user('root')
        self.assertNotIn(i['token'], admin.get('/api/invites').text)
        self.assertEqual(self.conn.scalar('SELECT count(*) FROM invites WHERE token_hash = :t', {'t': i['token']}), 0)

    def test_guessing_tokens_is_limited(self):
        anon = self.web.test_client()
        codes = [anon.post('/api/enroll/check', json={'token': f'guess{n}'}).status_code for n in range(12)]
        self.assertIn(429, codes)

    def test_lifetime_is_bounded(self):
        admin = self.as_user('root')
        self.assertEqual(admin.post('/api/invites', json={'role': 'viewer', 'hours': 99999}).status_code, 400)
        self.assertEqual(admin.post('/api/invites', json={'role': 'nope'}).status_code, 400)


class ResetLinks(Base):
    def test_reset_sets_the_named_account_only(self):
        users.create(self.conn, 'vic', PW, 'viewer')
        vic = self.as_user('vic')
        link = self.as_user('root').post('/api/users/vic/reset-link', json={}).json
        anon = self.web.test_client()
        self.assertEqual(anon.post('/api/enroll/check', json={'token': link['token']}).json['reset_user'], 'vic')
        new = 'a different long password'
        r = anon.post('/api/enroll', json={'token': link['token'], 'username': 'root', 'password': new})
        self.assertEqual((r.status_code, r.json['username']), (200, 'vic'))
        self.assertEqual(vic.get('/api/me').status_code, 401)                 # every session ended
        self.assertIsNone(users.authenticate(self.conn, 'root', new))
        self.assertIsNotNone(users.authenticate(self.conn, 'vic', new))
        self.assertEqual(anon.post('/api/enroll', json={'token': link['token'], 'password': PW}).status_code, 403)

    def test_a_link_dies_when_the_role_changes(self):
        users.create(self.conn, 'vic', PW, 'viewer')
        link = self.as_user('root').post('/api/users/vic/reset-link', json={}).json
        users.set_role(self.conn, 'vic', 'admin')
        self.assertEqual(self.web.test_client().post('/api/enroll', json={'token': link['token'], 'password': 'x' * 16}).status_code, 403)


class Migration(unittest.TestCase):
    def test_upgrade_keeps_accounts_and_sessions(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Database(f'sqlite:///{tmp}/idx.db')
            conn = db.connect()
            for f in sorted((MIGRATIONS / 'sqlite').glob('*.sql')):
                if int(f.name.split('_')[0]) < 24:
                    conn.raw.executescript(f.read_text())
            now = int(time.time())
            conn.execute("INSERT INTO users (username, password_hash, created_at, role) VALUES ('old', 'h', :t, 'operator')", {'t': now})
            uid = conn.scalar("SELECT user_id FROM users WHERE username = 'old'")
            conn.execute("INSERT INTO web_sessions (sid_hash, user_id, created_at) VALUES ('s', :u, :t)", {'u': uid, 't': now})
            self.assertEqual(db.migrate(conn), ['024_roles_invites.sql', '025_invite_grants.sql', '026_job_state.sql', '027_key_origin.sql', '028_remote_nodes.sql', '029_schedule_pending_token.sql', '030_clamav.sql', '031_ransomware_defense.sql', '032_security_measured.sql', '033_host_network.sql', '034_map.sql', '035_map_more.sql', '036_security_more.sql', '037_device_credentials.sql', '038_network_devices.sql', '039_sentinel_permission.sql', '040_host_log_lines.sql', '041_scan_signing.sql'])
            self.assertEqual(db.migrate(conn), [], 'a migration that does not record itself runs again at every start')
            self.assertEqual(conn.scalar("SELECT role FROM users WHERE username = 'old'"), 'operator')
            self.assertEqual(conn.scalar('SELECT count(*) FROM web_sessions'), 1)
            users.set_role(conn, 'old', 'search')                             # the old CHECK is gone
            conn.execute("INSERT INTO roles (name, permissions, created_at, created_by) VALUES ('c', '[]', 1, 'x')")
            users.set_role(conn, 'old', 'c')
            with self.assertRaises(users.UserError):
                users.set_role(conn, 'old', 'nope')
            conn.close()
        self.assertTrue(sqlite3.sqlite_version_info >= (3, 35))



class PrivilegeChain(Base):
    """A planner or dry-run account must not reach root on a host through how a request is spelled."""
    def setUp(self):
        super().setUp()
        self.conn.execute("INSERT INTO hosts (hostname, ssh_host, ssh_user, ssh_port) VALUES ('h1', '10.9.9.9', 'root', 22)")
        self.started = []
        for target, attr, stub in ((deploy, 'start_group', lambda _db, items, _who, **_k: (self.started.extend(items), 'a' * 32)[1]),
                                   (deploy, 'ready', lambda *_a, **_k: True), (preflight, 'blockers', lambda *_a, **_k: [])):
            patcher = mock.patch.object(target, attr, stub)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.admin = self.as_user('root')
        self.task = self.admin.post('/api/tasks', json={'name': 'raw', 'host': 'h1', 'blocks': [{'type': 'command', 'params': {'cmd': 'id'}}]}).json['id']

    def with_perms(self, name, *perms):
        users.save_role(self.conn, name, '', list(perms), 'root', True)
        return self.as_user(name, name)

    def test_a_dry_run_cannot_run_for_real(self):
        c = self.with_perms('dry', 'deploy.report', 'deploy.view')
        self.assertEqual(c.post('/api/deploy/start', json={'kind': 'tasks', 'ref': self.task, 'mode': 'report', 'run': True}).status_code, 400)
        self.assertEqual(self.started, [])

    def test_remove_does_not_excuse_a_run(self):
        c = self.with_perms('applier', 'deploy.report', 'deploy.apply', 'deploy.view')
        self.assertEqual(c.post('/api/deploy/start', json={'kind': 'tasks', 'ref': self.task, 'mode': 'apply', 'remove': True, 'run': True}).status_code, 400)
        self.assertEqual(c.post('/api/deploy/start', json={'kind': 'tasks', 'ref': self.task, 'mode': 'apply', 'run': True}).status_code, 403)
        self.assertEqual(self.started, [])

    def test_the_command_check_sees_the_saved_type(self):
        c = self.with_perms('planner', 'plans.view', 'plans.edit')
        base = {'host': 'h1', 'cron_expr': '0 3 * * *', 'task_ref': 'id'}
        for i, spelled in enumerate(('command', 'Command', ' COMMAND ')):
            self.assertEqual((spelled, c.post('/api/scheduler/schedules', json={**base, 'name': f's{i}', 'task_type': spelled}).status_code), (spelled, 403))
        plain = self.admin.post('/api/tasks', json={'name': 'plain', 'host': 'h1', 'blocks': [{'type': 'require_mounted', 'params': {'path': '/'}}]}).json['id']
        sid = c.post('/api/scheduler/schedules', json={**base, 'name': 'ok', 'task_type': 'task', 'task_ref': str(plain)}).json['schedule']['schedule_id']
        self.assertEqual(c.put(f'/api/scheduler/schedules/{sid}', json={'task_type': 'COMMAND'}).status_code, 403)
        c2 = self.with_perms('pauser', 'plans.view', 'plans.edit', 'deploy.apply')
        unchanged = scheduler.schedule_hash(self.conn, scheduler.get_schedule(self.conn, sid))
        with mock.patch.object(scheduler, 'installed', lambda _c: {str(sid): [{'host': 'h1', 'hash': unchanged, 'at': 0, 'by': 'x'}]}):
            self.assertEqual(c2.put(f'/api/scheduler/schedules/{sid}', json={'task_ref': str(self.task)}).status_code, 200)    # planning it is allowed
            self.assertEqual(c2.post(f'/api/scheduler/schedules/{sid}/pause', json={'paused': True}).status_code, 403)         # pushing it is not
            self.assertEqual(self.started, [])
            c2.put(f'/api/scheduler/schedules/{sid}', json={'task_ref': str(plain)})
            self.assertEqual(c2.post(f'/api/scheduler/schedules/{sid}/pause', json={'paused': True}).status_code, 200)         # an unchanged one stops

    def test_env_is_for_commands_only(self):
        plain = self.admin.post('/api/tasks', json={'name': 'plain', 'host': 'h1', 'blocks': [{'type': 'require_mounted', 'params': {'path': '/'}}]}).json['id']
        r = self.admin.post('/api/scheduler/schedules', json={'name': 'e', 'host': 'h1', 'cron_expr': '0 3 * * *', 'task_type': 'task', 'task_ref': str(plain), 'config': {'env': {'RSYNC_RSH': 'x'}}})
        self.assertEqual(r.status_code, 400)

    def test_state_changes_come_from_this_origin(self):
        for headers in ({'Sec-Fetch-Site': 'same-site'}, {'Sec-Fetch-Site': 'cross-site'}, {'Origin': 'https://evil.example'}, {'Origin': 'null'}):
            self.assertEqual((headers, self.admin.post('/api/logout', headers=headers).status_code), (headers, 403))
        self.assertEqual(self.admin.get('/api/me', headers={'Sec-Fetch-Site': 'cross-site'}).status_code, 200)
        self.assertEqual(self.admin.post('/api/jobs/report', json={}).status_code, 401)     # no browser headers: judged by its token
        self.assertEqual(self.admin.post('/api/reauth', json={'password': PW}, headers={'Sec-Fetch-Site': 'same-origin'}).status_code, 200)
        self.assertEqual(self.admin.post('/api/reauth', json={'password': PW}, headers={'Origin': 'https://localhost:8443'}).status_code, 200)   # the proxy passes the Host without its port

    def test_plain_http_tells_ports_apart(self):
        """SF-42: browsers send no Sec-Fetch-Site over plain HTTP, and SameSite lets a page on another port send the cookie."""
        for origin, host in (('http://nas:3000', 'nas:8000'), ('http://nas', 'nas:8000'), ('https://nas:8000:x', 'nas:8000'), ('http://nas:bad', 'nas:8000')):
            self.assertEqual(self.admin.post('/api/logout', headers={'Origin': origin, 'Host': host}).status_code, 403, origin)
        for origin, host in (('http://nas:8000', 'nas:8000'), ('https://nas', 'nas:443'), ('http://nas', 'nas:80')):
            self.assertNotEqual(self.admin.post('/api/logout', headers={'Origin': origin, 'Host': host}).status_code, 403, origin)

if __name__ == '__main__':
    unittest.main()
