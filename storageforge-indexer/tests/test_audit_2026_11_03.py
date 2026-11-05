"""The 2026-11-03 audit: routes reaching around a permission, the runner's refusals, and the limits new routes need."""
import ast
import inspect
import json
import os
import re
import stat
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import test_security as T
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from storageforge_index import changes, clamav, deploy, mapdesign, permissions, preflight, secplus, secscripts as sx, security, server, tasks, users, webauthn
from storageforge_index.vault import Vault

PW = T.PW


class Accounts(T.Base):
    def as_role(self, name, role):
        users.create(self.conn, name, PW, role)
        self.login(name)

    def custom(self, name, perms):
        users.save_role(self.conn, 'r' + name, 'test', sorted(perms), 'admin1', True)
        self.as_role(name, 'r' + name)

    def key(self, who='admin1'):
        return webauthn.add_key(self.conn, who, {'credential_id': 'cred', 'public_key': 'x', 'sign_count': 0}, 'key')


class SecurityKeys(Accounts):
    """SF-44: a key guards its own removal and replacement."""

    def refused_for_a_touch(self, r):
        self.assertEqual((r.status_code, r.get_json().get('webauthn')), (403, True))

    def test_with_a_key_changing_keys_takes_a_touch(self):
        kid = self.key()
        self.refused_for_a_touch(self.client.delete(f'/api/security/webauthn/{kid}'))
        self.refused_for_a_touch(self.post('/api/security/webauthn/register/begin'))
        self.refused_for_a_touch(self.post('/api/security/webauthn/register/finish', clientDataJSON='x', attestationObject='x'))
        self.assertEqual(len(webauthn.keys_of(self.conn, 'admin1')), 1)

    def test_a_touch_lets_a_key_be_removed(self):
        kid = self.key()
        with self.client.session_transaction() as s:
            s['webauthn_at'] = time.time()
        self.assertEqual(self.client.delete(f'/api/security/webauthn/{kid}').status_code, 200)
        self.assertEqual(webauthn.keys_of(self.conn, 'admin1'), [])

    def test_a_first_key_needs_no_touch(self):
        self.assertEqual(self.post('/api/security/webauthn/register/begin').status_code, 200)

    def test_someone_elses_key_does_not_ask_me_for_a_touch(self):
        self.key('admin2')
        self.assertEqual(self.post('/api/security/webauthn/register/begin').status_code, 200)

    def test_a_lost_key_is_cleared_from_the_shell_and_audited(self):
        from storageforge_index import cli
        self.key()
        parser_args = ['--db', f'sqlite:///{self.tmp}/test.db', 'user', 'clear-keys', 'admin1']
        with mock.patch.object(cli.sys, 'argv', ['storageforge-index', *parser_args]), mock.patch('builtins.print'):
            self.assertEqual(cli.main(), 0)
        self.assertEqual(webauthn.keys_of(self.conn, 'admin1'), [])
        self.assertEqual(self.conn.scalar("SELECT count(*) FROM audit_log WHERE action = 'user.clear-keys'"), 1)


class SentinelPermission(Accounts):
    """SF-45: the sentinel has its own permission, and deploy options cannot reach around it."""

    def start(self, **body):
        seen = {}

        def capture(db, items, who, **kw):
            seen['items'] = items
            return 'a' * 32
        with mock.patch.object(deploy, 'start_group', capture), mock.patch.object(preflight, 'blockers', lambda *a, **k: []):
            r = self.post('/api/deploy/start', kind='security', ref='nas', **body)
        return r, seen

    def configure(self):
        self.login('admin1')
        r = self.post('/api/security/sentinel', host='nas', folders=[str(self.root / 'share')], armed=True)
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))

    def test_the_permission_is_high_risk_and_operators_do_not_hold_it(self):
        self.assertIn('security.sentinel', permissions.HIGH_RISK)
        self.assertNotIn('security.sentinel', permissions.BUILTIN['operator'][1])
        self.assertIn('security.sentinel', permissions.BUILTIN['admin'][1])

    def test_an_operator_cannot_touch_it_on_any_host(self):
        self.configure()
        self.as_role('opal', 'operator')
        self.assertEqual(self.post('/api/security/sentinel', host='nas', folders=['/srv']).status_code, 403)
        for options in ({'remove': True}, {'rearm': True}, {}):
            r, seen = self.start(mode='apply', **options)
            self.assertEqual(r.status_code, 403, options)
            self.assertEqual(seen, {}, 'nothing may have started')

    def test_a_dry_run_stays_with_deploy_report(self):
        self.configure()
        self.as_role('opal', 'operator')
        r, seen = self.start(mode='report')
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        self.assertEqual(seen['items'][0]['args'], [])

    def test_a_role_with_both_can_remove_it_and_with_one_cannot(self):
        self.configure()
        self.custom('both', {'deploy.report', 'deploy.apply', 'security.sentinel'})
        r, seen = self.start(mode='apply', remove=True)
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        self.assertEqual(seen['items'][0]['args'], ['--uninstall'])
        self.custom('onlyapply', {'deploy.report', 'deploy.apply'})
        self.assertEqual(self.start(mode='apply', remove=True)[0].status_code, 403)
        self.custom('onlysentinel', {'deploy.report', 'security.sentinel'})
        self.assertEqual(self.start(mode='apply', remove=True)[0].status_code, 403)

    def test_a_retry_takes_it_too(self):
        self.configure()
        r, _ = self.start(mode='apply', remove=True)
        self.assertEqual(r.status_code, 200)
        from storageforge_index import engine
        g = {'kind': 'security', 'ref': 'nas', 'mode': 'apply', 'options': {'remove': True}, 'title': 't'}
        self.as_role('opal', 'operator')
        with mock.patch.object(engine, 'get', lambda *_: g):
            self.assertEqual(self.post(f'/api/deploy/groups/{"a" * 32}/retry').status_code, 403)

    def test_emergency_alone_no_longer_sets_it(self):
        self.custom('em', {'security.emergency'})
        self.assertEqual(self.post('/api/security/sentinel', host='nas', folders=['/srv']).status_code, 403)

    def test_custom_roles_that_could_set_it_keep_that(self):
        path = Path(server.__file__).parent / 'migrations/sqlite/039_sentinel_permission.sql'
        self.assertIn('security.sentinel', (path.parent.parent / 'postgres' / path.name).read_text(), 'both databases')
        for name, perms in (('a', ['deploy.apply', 'security.emergency']), ('b', ['deploy.apply']), ('c', ['security.emergency', 'security.sentinel'])):
            self.conn.execute("INSERT INTO roles (name, description, permissions, created_at, created_by) VALUES (:n, :d, :p, 1, 'test')", {'n': name, 'd': 'x', 'p': json.dumps(perms)})
        statement = '\n'.join(x for x in Path(path).read_text().splitlines() if not x.startswith('--')).split(';')[0]
        self.conn.execute(statement)
        got = {r[0]: json.loads(r[1]) for r in self.conn.all("SELECT name, permissions FROM roles WHERE name IN ('a', 'b', 'c')")}
        self.assertIn('security.sentinel', got['a'])
        self.assertNotIn('security.sentinel', got['b'])
        self.assertEqual(got['c'].count('security.sentinel'), 1)


class HoldsByPolicy(Accounts):
    """SF-46: every way to a hold takes the permission a hold takes."""

    def test_an_operator_cannot_make_or_apply_a_policy(self):
        pid = secplus.save_policy(self.conn, {'host': 'nas', 'pattern': 'tank/*', 'legal': True}, 'admin1')['id']
        self.as_role('opal', 'operator')
        self.assertEqual(self.post('/api/security/worm/policies', host='nas', pattern='tank/*', legal=True, auto=True).status_code, 403)
        self.assertEqual(self.client.delete(f'/api/security/worm/policies/{pid}').status_code, 403)
        self.assertEqual(self.post('/api/security/worm/policies/apply', host='nas', mode='apply').status_code, 403)
        self.assertEqual(self.conn.scalar('SELECT count(*) FROM security_retention_holds'), 0)

    def test_an_operator_can_still_see_what_it_would_do(self):
        self.as_role('opal', 'operator')
        for mode in ('preview', 'report'):
            self.assertEqual(self.post('/api/security/worm/policies/apply', host='nas', mode=mode).status_code, 200, mode)

    def test_a_mode_that_is_not_real_does_not_slip_past(self):
        self.as_role('opal', 'operator')
        self.assertEqual(self.post('/api/security/worm/policies/apply', host='nas', mode='APPLY').status_code, 400)

    def test_emergency_can(self):
        self.custom('em', {'security.emergency', 'security.manage', 'security.view'})
        self.assertEqual(self.post('/api/security/worm/policies', host='nas', pattern='tank/*', days=7).status_code, 200)
        self.assertEqual(self.post('/api/security/worm/policies/apply', host='nas', mode='apply').status_code, 200)


class Evidence(Accounts):
    """SF-47: signing takes more than reading, and is never a GET."""

    def signed(self):
        key = ed25519.Ed25519PrivateKey.generate()
        unlock = mock.patch.object(Vault, 'unlock')
        return unlock, mock.patch.object(deploy, '_signer', return_value=key)

    def test_a_viewer_cannot_and_a_get_does_nothing(self):
        before = self.conn.scalar("SELECT count(*) FROM audit_log WHERE action = 'security.evidence'")
        self.as_role('vera', 'viewer')
        u, s = self.signed()
        with u as unlock, s:
            self.assertEqual(self.post('/api/security/evidence', host='nas').status_code, 403)
            self.assertEqual(self.client.get('/api/security/evidence').status_code, 405)
        unlock.assert_not_called()
        self.assertEqual(self.conn.scalar("SELECT count(*) FROM audit_log WHERE action = 'security.evidence'"), before)

    def test_it_takes_both_permissions(self):
        self.custom('onlyverify', {'audit.verify'})
        u, s = self.signed()
        with u, s:
            self.assertEqual(self.post('/api/security/evidence', host='nas').status_code, 403)
        self.custom('both', {'audit.verify', 'audit.view'})
        with u, s:
            r = self.post('/api/security/evidence', host='nas', **{'from': 5})
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        self.assertEqual(json.loads(r.get_json()['document'])['from'], 5)

    def test_past_the_limit_it_does_not_unlock_the_vault(self):
        u, s = self.signed()
        with u as unlock, s:
            codes = [self.post('/api/security/evidence', host='nas').status_code for _ in range(12)]
        self.assertEqual(codes, [200] * 10 + [429] * 2)
        self.assertEqual(unlock.call_count, 10)


class EveryWayToAHold(Accounts):
    """SF-46, as a walk: from what makes a hold back to the routes, so a new route, policy or playbook is found without anyone listing it."""
    ENDS = {('security', 'apply_hold'), ('secplus', 'freeze'), ('security', 'brake')}     # the three things that sign a script holding snapshots on a host
    # Code that runs later, on what a route saved: a call graph cannot see these, so each is named with what it reads
    FEEDS = {('secplus', 'tick'): {('secplus', 'save_policy')}, ('secplus', 'run_actions'): {('secplus', 'save_playbook')}}

    def setUp(self):
        super().setUp()
        self.ran = []
        run = mock.patch.object(deploy, 'run', lambda db, host, script, *a, **k: self.ran.append(host) or {'run_id': 1, 'group_id': 'g', 'host': host, 'status': 'failed', 'exit_code': 1, 'output': 'not run: test'})
        run.start()     # nothing in this class may run a script on the machine under the tests
        self.addCleanup(run.stop)

    @staticmethod
    def graph():
        """{(module, function): what it uses}. A name in its own module, module.name through an import, and anything else by its last word."""
        out = {}
        for path in Path(server.__file__).parent.rglob('*.py'):
            tree, mod = ast.parse(path.read_text()), path.stem
            modules = {a.asname or a.name.split('.')[-1] for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom)) for a in n.names}

            def uses(fn):
                stack, found = list(fn.body), set()
                while stack:
                    n = stack.pop()
                    if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):      # its own entry: it runs if someone uses its name
                        continue
                    if isinstance(n, ast.Attribute):
                        base = n.value.id if isinstance(n.value, ast.Name) else None
                        found.add((base if base in modules else None, n.attr))
                    elif isinstance(n, ast.Name):
                        found.add((mod, n.id))
                    stack.extend(ast.iter_child_nodes(n))
                return found
            for fn in ast.walk(tree):
                if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    out.setdefault((mod, fn.name), set()).update(uses(fn))
        return out

    def leading_to(self, ends):
        graph, reached = self.graph(), set(ends)

        def hits(u):
            return u in reached or (u[0] is None and not u[1].startswith('__') and any(r[1] == u[1] for r in reached))
        while True:
            more = {f for f, used in graph.items() if f not in reached and any(hits(u) for u in used)}
            more |= {w for f, writers in self.FEEDS.items() if f in reached for w in writers} - reached
            if not more:
                return reached
            reached |= more

    def routes(self, ends=None):
        """(method, rule, view function) of each route whose view reaches a hold, from the URL map."""
        reached = self.leading_to(ends or self.ENDS)
        for rule in self.web.url_map.iter_rules():
            view = self.web.view_functions[rule.endpoint]
            if (view.__module__.rsplit('.', 1)[-1], view.__name__) in reached:
                for method in rule.methods - {'HEAD', 'OPTIONS'}:
                    yield method, rule.rule, view

    @staticmethod
    def url(rule):
        return re.sub(r'<[^>]+>', 'x', re.sub(r'<int:\w+>', '1', rule))

    def takes_it(self, method, rule, view):
        need = permissions.required(method, self.url(rule))
        return need == 'security.emergency' or "need('security.emergency')" in inspect.getsource(inspect.unwrap(view))

    def test_the_walk_finds_the_ways_there_are(self):
        """If this goes wrong the walk is blind, and the tests below pass by finding nothing."""
        found = {(m, r) for m, r, _ in self.routes()}
        for way in (('POST', '/api/security/worm/hold'), ('POST', '/api/security/worm/policies/apply'), ('POST', '/api/security/worm/policies'),
                    ('POST', '/api/security/worm/freeze'), ('POST', '/api/security/incident/brake'), ('POST', '/api/security/playbooks'),
                    ('POST', '/api/security/playbooks/runs/<int:run_id>')):
            self.assertIn(way, found)

    def test_every_route_ending_in_a_hold_takes_security_emergency(self):
        for method, rule, view in self.routes():
            with self.subTest(route=f'{method} {rule}'):
                self.assertTrue(self.takes_it(method, rule, view), f'{rule} takes {permissions.required(method, self.url(rule))}')

    def test_without_the_permission_no_route_gets_to_a_hold(self):
        """Everything else in the catalogue, and still nothing: each route is called as it would be to make a hold."""
        self.custom('allbut', permissions.ALL - {'security.emergency'})
        body = {'mode': 'apply', 'host': 'nas', 'snapshot': 'tank/shares@s1', 'retention_days': 1, 'legal_hold': True, 'target': 'tank/shares', 'pattern': 'tank/*',
                'legal': True, 'auto': True, 'actions': ['snapshot'], 'trigger': 'canary_tripped', 'name': 'p', 'confirm': True, 'path': '/srv/x', 'reason': 'test'}
        with mock.patch.object(security, 'apply_hold', side_effect=AssertionError('apply_hold was reached')) as held:
            for method, rule, _ in self.routes():
                with self.subTest(route=f'{method} {rule}'):
                    r = self.client.open(self.url(rule), method=method, json=body)
                    self.assertEqual(r.status_code, 403, r.get_data(as_text=True))
        self.assertEqual((held.call_count, self.ran, self.conn.scalar('SELECT count(*) FROM security_retention_holds')), (0, [], 0))

    def test_with_it_none_is_refused_for_want_of_a_permission(self):
        """Applying policies also takes what its route takes for a preview, security.manage: it asks for more than a hold does, never less."""
        body = {'mode': 'apply', 'host': 'nas', 'snapshot': 'tank/shares@s1', 'retention_days': 1, 'pattern': 'tank/*', 'days': 1, 'target': 'tank/shares', 'name': 'p',
                'trigger': 'canary_tripped', 'actions': ['notify'], 'path': '/srv/x', 'reason': 'test'}
        for i, (method, rule, _) in enumerate(self.routes()):
            with self.subTest(route=f'{method} {rule}'):
                self.custom(f'em{i}', {'security.emergency', permissions.required(method, self.url(rule))})
                r = self.client.open(self.url(rule), method=method, json=body)
                self.assertNotEqual(r.status_code, 403, r.get_data(as_text=True))

    def test_the_check_can_fail(self):
        """Measuring a host takes security.manage: walked from there, the same check has to say so."""
        found = [(m, r) for m, r, v in self.routes({('security', 'measure')}) if not self.takes_it(m, r, v)]
        self.assertIn(('POST', '/api/security/measure'), found)


class SecondHops(Accounts):
    """SF-48: the signature stops at the first host, and the record says who else was involved."""

    def test_plans_and_tasks_name_their_receivers(self):
        self.assertEqual(changes.second_hops({'name': 'p', 'tasks': [{'type': 'zfs-send', 'host': 'nas', 'params': {'dataset': 'tank/a', 'name': 's', 'dest_host': 'root@10.0.0.9', 'dest': 'b/a'}},
                                                                    {'type': 'dir', 'host': 'nas', 'params': {'path': '/srv'}}]}), ['root@10.0.0.9'])
        task = {'name': 't', 'host': 'nas', 'blocks': [{'type': 'if', 'params': {'kind': 'exists', 'path': '/x'}, 'then': [{'type': 'zfs_send', 'params': {'dataset': 'tank/a', 'prefix': 'd', 'dst_host': 'backup', 'dst': 'b/a', 'keep': 3}}]}]}
        with mock.patch.object(tasks, 'normalize', lambda t: t):
            self.assertEqual(tasks.second_hops(task), ['backup'])

    def test_the_audit_row_says_so(self):
        plan = changes.save_plan(self.conn, {'name': 'send', 'tasks': [{'type': 'zfs-send', 'host': 'nas', 'params': {'dataset': 'tank/a', 'name': 's', 'dest_host': 'root@10.0.0.9', 'dest': 'b/a'}}]}, 'admin1', None)
        with mock.patch.object(deploy, 'start_group', lambda *a, **k: 'a' * 32), mock.patch.object(preflight, 'blockers', lambda *a, **k: []):
            r = self.post('/api/deploy/start', kind='changes', ref=plan, mode='report')
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        detail = self.conn.scalar("SELECT detail_json FROM audit_log WHERE action = 'deploy.start' ORDER BY audit_id DESC LIMIT 1")
        self.assertIn('root@10.0.0.9', detail)
        self.assertIn('second_hops', detail)


class FalcoKey(unittest.TestCase):
    """SF-49: the script's signature says nothing about what a download returns."""

    def fetch(self, listing):
        with tempfile.TemporaryDirectory() as d:
            bin_ = Path(d)
            for name, body in (('curl', '#!/bin/bash\nwhile (($#)); do [[ $1 == -o ]] && { echo key >"$2"; }; shift; done\n'), ('gpg', f'#!/bin/bash\ncat <<EOF\n{listing}\nEOF\n')):
                (bin_ / name).write_text(body)
                (bin_ / name).chmod(stat.S_IRWXU)
            script = sx.head() + secplus.FALCO_KEY_FETCH + 'echo KEY-OK\n'
            return subprocess.run(['bash', '-c', script], capture_output=True, text=True, env={**os.environ, 'PATH': f'{d}:{os.environ["PATH"]}'}, timeout=30)

    def test_only_that_key_gets_through(self):
        pin = secplus.FALCO_KEY_FINGERPRINT
        good = f'pub:-:4096:1:X:1:::-:::scSC:\nfpr:::::::::{pin}:\nsub:-:4096:1:Y:1:::::e:\nfpr:::::::::{"A" * 40}:'
        self.assertIn('KEY-OK', self.fetch(good).stdout)
        for name, listing in (('another key', f'pub:-:4096:1:X:1:::-:::scSC:\nfpr:::::::::{"B" * 40}:'),
                              ('the revoked one', 'pub:-:4096:1:X:1:::-:::scSC:\nfpr:::::::::2005399002D5E8FF59F28CE64021833E14CB7A8D:'),
                              ('a second key beside it', f'pub:-:4096:1:X:1:::-:::scSC:\nfpr:::::::::{pin}:\npub:-:4096:1:Z:1:::-:::scSC:\nfpr:::::::::{"C" * 40}:'),
                              ('nothing', '')):
            r = self.fetch(listing)
            self.assertNotIn('KEY-OK', r.stdout, name)
            self.assertNotEqual(r.returncode, 0, name)

    def test_nothing_else_is_taken_on_trust(self):
        script = secplus.falco_script('- rule: a\n')
        for bad in ('--gpg-auto-import-keys', 'rpm --import https', '| gpg --dearmor', 'falcosecurity-rpm.repo', 'gpgkey='):
            self.assertNotIn(bad, script, bad)
        self.assertIn('gpgcheck=1', script)
        self.assertIn(secplus.FALCO_KEY_FINGERPRINT, script)
        self.assertEqual(subprocess.run(['bash', '-n'], input=script, text=True, capture_output=True).returncode, 0)


class MapViews(Accounts):
    """SF-50 and SF-51."""

    def test_a_view_is_its_owners(self):
        self.as_role('opal', 'operator')
        self.assertEqual(self.post('/api/map/views', name='mine', positions={'a': 1}).status_code, 200)
        vid = self.client.get('/api/map/views').get_json()['views'][0]['id']
        self.as_role('otto', 'operator')
        self.assertEqual(self.client.get('/api/map/views').get_json()['views'], [])
        self.assertEqual(self.post('/api/map/views', name='mine', positions={'a': 666}).status_code, 409)
        self.assertEqual(self.client.delete(f'/api/map/views/{vid}').status_code, 403)
        self.assertEqual(self.client.delete('/api/map/views/99999').status_code, 404)
        self.assertEqual(self.conn.all('SELECT owner, body_json FROM map_views')[0][0], 'web:opal')
        self.assertIn('"a": 1', self.conn.scalar('SELECT body_json FROM map_views'))

    def test_a_shared_view_is_seen_by_all_and_changed_by_one(self):
        self.as_role('opal', 'operator')
        self.post('/api/map/views', name='team', positions={}, shared=True)
        self.as_role('otto', 'operator')
        got = self.client.get('/api/map/views').get_json()['views']
        self.assertEqual([(v['name'], v['mine']) for v in got], [('team', False)])
        self.assertEqual(self.client.delete(f'/api/map/views/{got[0]["id"]}').status_code, 403)
        self.as_role('vera', 'viewer')
        self.assertEqual([v['name'] for v in self.client.get('/api/map/views').get_json()['views']], ['team'])

    def test_comparing_a_design_changes_nothing(self):
        did = mapdesign.save_design(self.conn, {'name': 'd', 'doc': {'hosts': []}}, 'admin1')['id']
        before = self.conn.all('SELECT * FROM map_designs WHERE id = :i', {'i': did})
        r = self.client.get(f'/api/map/designs/{did}/compare')
        self.assertEqual(r.status_code, 200)
        self.assertIn('compared_at', r.get_json(), 'it still says when, for whoever is reading')
        self.assertEqual(self.conn.all('SELECT * FROM map_designs WHERE id = :i', {'i': did}), before)


class BodyLimits(T.Base):
    """PF-31: a limit and the validator behind it go together. In both directions, as PF-28 taught."""

    # They check the token before they read the body, so a stranger cannot make them read this much: their own tests send a real one.
    TOKEN_FIRST = {'/api/scheduler/report', '/api/jobs/report'}

    def size(self, method, path, n):
        pad = 'x' * max(0, n - len(json.dumps({'p': ''})))
        return self.client.open(path, method=method, data=json.dumps({'p': pad}), content_type='application/json',
                                headers={'Authorization': 'Bearer tok'}).status_code

    def test_every_listed_route_takes_up_to_its_limit_and_no_more(self):
        import hashlib
        from storageforge_index import alerts
        alerts.set_setting(self.conn, security.host_key('nas'), {'host': 'nas', 'token_sha': hashlib.sha256(b'tok').hexdigest()}, 't')
        for (method, path), limit in server.BODY_LIMITS.items():
            if not any(path == r.rule and method in r.methods for r in self.web.url_map.iter_rules()):
                self.fail(f'{method} {path} is not a route')
            if path in self.TOKEN_FIRST:
                self.assertEqual(self.size(method, path, limit + 1), 401, path)
                continue
            self.assertNotEqual(self.size(method, path, limit), 413, path)
            self.assertEqual(self.size(method, path, limit + 1), 413, path)

    def test_a_route_not_listed_keeps_the_small_limit(self):
        self.assertEqual(self.size('POST', '/api/map/annotations', server.MAX_BODY + 1), 413)

    def test_what_the_validators_accept_fits(self):
        self.assertEqual(self.post('/api/map/views', name='big', positions={'a': 'x' * 150_000}).status_code, 200)
        self.assertEqual(self.post('/api/map/views', name='toobig', positions={'a': 'x' * 250_000}).status_code, 400)
        self.assertEqual(self.post('/api/security/behavior/yara/rules', name='r', body='rule a { condition: true } //' + 'x' * 150_000).status_code, 200)

    def test_a_sentinel_can_report_a_long_path(self):
        import base64
        import hashlib
        from storageforge_index import alerts
        alerts.set_setting(self.conn, security.host_key('nas'), {'host': 'nas', 'token_sha': hashlib.sha256(b'tok').hexdigest()}, 't')
        line = T.event_line(summary='s', detail='path_b64=' + base64.b64encode(b'/srv/' + b'd' * 4000).decode())
        r = self.client.post('/api/security/report', json={'lines': [line]}, headers={'Authorization': 'Bearer tok'})
        self.assertEqual((r.status_code, r.get_json()['new']), (200, 1))


class MalwarePreview(T.Base):
    """PF-32."""

    def test_a_quarantined_file_gets_a_plain_answer(self):
        self.conn.execute("""INSERT INTO clamav_detections (host, path_b64, path, signature, state, ignored, first_seen, last_seen, quarantine_id)
                             VALUES ('nas', 'L3NydC94', '/srv/x', 'S', 'quarantined', 0, 1, 1, :q)""", {'q': 'a' * 32})
        did = self.conn.scalar('SELECT max(detection_id) FROM clamav_detections')
        self.calls.clear()
        r = self.post('/api/security/malware/preview', id=did)
        self.assertEqual(r.status_code, 400)
        self.assertIn('quarantine', r.get_json()['error'])
        self.assertEqual(self.calls, [], 'nothing runs on the host')
        self.assertTrue(clamav.get_detection(self.conn, did))


class SecurityGenerators(T.Base):
    """EQ-07: what test_no_generator_lets_a_value_run_as_code does for the plans, for the scripts of the Security panel."""
    MARK = 'XPWNX'

    def runnable(self, script):
        t = re.sub(r"<<-?'(\w+)'\n.*?\n\1\n", '', script, flags=re.S)
        t = re.sub(r"'[^']*'", "''", t)
        return [x for x in t.splitlines() if self.MARK in x and not x.lstrip().startswith('#')]

    def scripts(self):
        c = f'$(touch${{IFS}}/tmp/{self.MARK})`id`"q;x'
        p = '/srv/' + c
        yield 'measure', sx.measure_script([p], [p], [p], [p])
        yield 'hold', sx.hold_script(p, 'sf-x')
        yield 'release', sx.release_script(p, 'sf-x')
        yield 'relabel', sx.relabel_script(p, 'samba_share_t')
        yield 'boolean', sx.boolean_script(c, c)
        yield 'aide', sx.tool_script('aide-init', [p])
        yield 'cleanroom', sx.cleanroom_script(p, p)
        yield 'install', sx.install_script(decoys=[p], armed=True, actions=sx.BRAKE_ACTIONS, minutes=1, report_url='', token='', vips=[])
        yield 'falco', secplus.falco_script(f'- rule: {c}\n')

    def test_a_value_stays_data(self):
        out = dict(self.scripts())
        self.assertEqual({k: self.runnable(v) for k, v in out.items() if self.runnable(v)}, {})
        for name, script in out.items():
            self.assertEqual(subprocess.run(['bash', '-n'], input=script, text=True, capture_output=True).returncode, 0, name)

    def test_the_scripts_the_routes_build_themselves(self):
        self.calls.clear()
        c = f'$(touch${{IFS}}/tmp/{self.MARK})`id`"q;x'
        self.post('/api/security/worm/freeze', host='nas', target='/srv/' + c, mode='report')
        self.post('/api/security/worm/preview', host='nas', snapshot='/srv/' + c, live='/srv/' + c)
        self.assertEqual(len(self.calls), 2)
        for call in self.calls:
            self.assertEqual(self.runnable(call['script']), [], call['ref'])

    def test_the_check_can_fail(self):
        self.assertTrue(self.runnable(f'SNAP=$(touch /tmp/{self.MARK})\n'))


class ForgedRequests(unittest.TestCase):
    """EQ-07: every way the runner refuses, with a real runner and a file showing whether the script ran."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(__import__('shutil').rmtree, self.d, True)
        self.key, self.other = ed25519.Ed25519PrivateKey.generate(), ed25519.Ed25519PrivateKey.generate()
        pub = self.key.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
        (self.d / 'etc').mkdir()
        (self.d / 'etc/allowed_signers').write_text(f'storageforge namespaces="storageforge-deploy" {pub}\n')
        (self.d / 'mid').write_text('a' * 32 + '\n')
        (self.d / 'run').write_text(deploy.RUNNER_SCRIPT)
        self.env = {**os.environ, 'STORAGEFORGE_RUN_ETC': str(self.d / 'etc'), 'STORAGEFORGE_RUN_STATE': str(self.d / 's'), 'STORAGEFORGE_RUN_LOG': str(self.d / 'l'), 'STORAGEFORGE_RUN_MACHINE_ID': str(self.d / 'mid')}
        self.mark = self.d / 'RAN'
        self.script = f'touch {self.mark}\n'
        self.me = os.uname().nodename

    def go(self, req):
        self.mark.unlink(missing_ok=True)
        p = subprocess.run(['bash', str(self.d / 'run')], input=req, capture_output=True, env=self.env, timeout=30)
        return p.returncode, self.mark.exists(), p.stderr.decode()

    def refused(self, req, says):
        rc, ran, err = self.go(req)
        self.assertEqual((rc, ran), (deploy.REFUSED, False), err)
        self.assertIn(says, err)

    def test_control_a_signed_request_runs(self):
        self.assertEqual(self.go(deploy.request(self.key, self.me, self.script))[:2], (0, True))

    def test_not_a_request(self):
        self.refused(b'', 'no request')
        self.refused(self.script.encode(), 'not a StorageForge request')

    def test_another_key(self):
        self.refused(deploy.request(self.other, self.me, self.script), 'does not verify')

    def test_altered_after_signing(self):
        self.refused(deploy.request(self.key, self.me, 'true # ' + 'x' * len(self.script)).replace(b'true # ' + b'x' * len(self.script), (self.script + '#' * 7).encode()), 'does not verify')
        self.refused(deploy.request(self.key, self.me, self.script).replace(b'args: \n', b'args: x\n'), 'does not verify')

    def test_another_host(self):
        self.refused(deploy.request(self.key, 'otherhost', self.script), 'signed for otherhost')

    def test_another_namespace(self):
        good = deploy.request(self.key, self.me, self.script)
        _, plen, slen, rest = good.split(b'\n', 3)
        payload = rest[:int(plen)]
        sig = deploy.sshsig(self.key, payload, namespace='storageforge-evidence').encode()
        self.refused(b'STORAGEFORGE-RUN 1\n%d\n%d\n' % (len(payload), len(sig)) + payload + sig, 'does not verify')

    def test_too_old_and_too_far_ahead(self):
        self.refused(deploy.request(self.key, self.me, self.script, now=time.time() - 660), 'too old')
        self.refused(deploy.request(self.key, self.me, self.script, now=time.time() + 660), 'too old')

    def test_replayed(self):
        req = deploy.request(self.key, self.me, self.script)
        self.assertEqual(self.go(req)[:2], (0, True))
        self.refused(req, 'already used')


if __name__ == '__main__':
    unittest.main()
