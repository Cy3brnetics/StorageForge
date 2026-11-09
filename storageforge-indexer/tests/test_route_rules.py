"""Every route's rules in one table, so a new one has to say what it is (EQ-04). Walks the URL map, as test_every_route_is_listed
does for permissions. Docs: concepts rules 13 and 14."""
import inspect
import re
import subprocess
import tempfile
import threading
import unittest
from unittest import mock

from flask_login import login_required

from storageforge_index import deploy, server, users
from storageforge_index.db import Database

PW = 'a long enough password'

# Changes something, runs on a host or touches accounts and keys: asks for a password typed in the last 5 minutes.
FRESH_PASSWORD = {
    ('POST', '/api/console/sessions'),          # a shell on a host: the password again for each session
    ('PUT', '/api/console/settings'),           # whether every session is recorded in full
    ('PUT', '/api/scans/signing'),                # whether unsigned scans are refused
    ('DELETE', '/api/scans/signing/<path:addr>'),  # forgetting a pinned key lets the next signer take its place
    ('POST', '/api/devices'),
    ('DELETE', '/api/devices/<name>'),
    ('POST', '/api/devices/credentials'),
    ('DELETE', '/api/devices/credentials/<name>'),
    ('POST', '/api/devices/<name>/hostkey'),
    ('POST', '/api/devices/changes/<int:change_id>/apply'),
    ('POST', '/api/devices/changes/<int:change_id>/confirm'),
    ('POST', '/api/netscan/settings'),
    ('POST', '/api/traffic/settings'),
    ('POST', '/api/remote/nodes'),
    ('POST', '/api/remote/nodes/<int:node_id>/adopt'),
    ('DELETE', '/api/remote/nodes/<int:node_id>'),
    ('POST', '/api/access/grant'),
    ('PUT', '/api/backups/target'),
    ('DELETE', '/api/bindings/<int:binding_id>'),
    ('POST', '/api/deploy/access'),
    ('POST', '/api/deploy/adopt'),
    ('POST', '/api/deploy/groups/<gid>/retry'),
    ('POST', '/api/deploy/jobs/<jid>/<any("run", "dryrun", "verify", "pause", "resume", "cutover", "log", "snapshots", "dedupe"):verb>'),
    ('POST', '/api/deploy/jobs/<jid>/restore'),
    ('POST', '/api/deploy/jobs/<jid>/retention'),
    ('POST', '/api/deploy/jobs/<jid>/forget'),
    ('POST', '/api/deploy/snapjobs/probe'),
    ('POST', '/api/deploy/snapjobs/import'),
    ('POST', '/api/deploy/snapjobs/snapper'),
    ('PUT', '/api/deploy/settings'),
    ('POST', '/api/deploy/start'),
    ('POST', '/api/git/sync'),
    ('POST', '/api/clamav/hosts/<host>/config'),
    ('POST', '/api/clamav/detections/<int:did>/quarantine'),
    ('POST', '/api/clamav/detections/<int:did>/restore'),
    ('POST', '/api/clamav/detections/<int:did>/ignore'),
    ('POST', '/api/hostkey/confirm'),
    ('DELETE', '/api/hosts/<name>'),
    ('POST', '/api/invites'),
    ('DELETE', '/api/invites/<int:invite_id>'),
    ('DELETE', '/api/keys/<name>'),
    ('POST', '/api/keys/install'),
    ('PUT', '/api/me'),
    ('POST', '/api/roles'),
    ('DELETE', '/api/roles/<name>'),
    ('PUT', '/api/roles/<name>'),
    ('POST', '/api/scheduler/schedules'),
    ('DELETE', '/api/scheduler/schedules/<int:schedule_id>'),
    ('PUT', '/api/scheduler/schedules/<int:schedule_id>'),
    ('POST', '/api/scheduler/schedules/<int:schedule_id>/pause'),
    ('POST', '/api/scheduler/schedules/<int:schedule_id>/run'),
    ('POST', '/api/scheduler/schedules/<int:schedule_id>/token'),
    ('POST', '/api/users'),
    ('DELETE', '/api/users/<name>'),
    ('PUT', '/api/users/<name>'),
    ('POST', '/api/users/<name>/reset-link'),
    ('POST', '/api/security/events/<int:event_id>/ack'),
    ('POST', '/api/security/measure'),
    ('POST', '/api/security/webauthn/register/begin'),
    ('POST', '/api/security/webauthn/register/finish'),
    ('POST', '/api/security/waivers'),
    ('POST', '/api/security/profiles'),
    ('POST', '/api/security/integrity/aide/watch'),
    ('POST', '/api/security/worm/policies'),
    ('POST', '/api/security/worm/policies/apply'),
    ('POST', '/api/security/worm/freeze'),
    ('POST', '/api/security/worm/preview'),
    ('POST', '/api/security/mac/identity/deploy'),
    ('POST', '/api/security/mac/noise'),
    ('POST', '/api/security/mac/context'),
    ('POST', '/api/security/firewall/tiers'),
    ('POST', '/api/security/behavior/thresholds'),
    ('POST', '/api/security/behavior/filters'),
    ('POST', '/api/security/behavior/falco'),
    ('POST', '/api/security/behavior/yara'),
    ('POST', '/api/security/behavior/yara/rules'),
    ('POST', '/api/security/malware/preview'),
    ('POST', '/api/security/playbooks'),
    ('POST', '/api/security/packages/check'),
    ('POST', '/api/security/packages/bundle'),
    ('POST', '/api/security/incident/clean-room/sweep'),
    ('DELETE', '/api/security/webauthn/<int:key_id>'),
    ('DELETE', '/api/security/waivers/<int:waiver_id>'),
    ('DELETE', '/api/security/profiles/<int:profile_id>'),
    ('DELETE', '/api/security/worm/policies/<int:policy_id>'),
    ('DELETE', '/api/security/behavior/yara/rules/<int:rule_id>'),
    ('DELETE', '/api/security/playbooks/<int:playbook_id>'),
    ('POST', '/api/security/playbooks/runs/<int:run_id>'),
    ('POST', '/api/infra/measure'),
    ('POST', '/api/infra/settings'),
    ('POST', '/api/map/placeholders/<path:node_id>/promote'),
    ('POST', '/api/map/manual'),
    ('DELETE', '/api/map/manual/<int:manual_id>'),
    ('POST', '/api/security/worm/hold'),
    ('POST', '/api/security/worm/release'),
    ('POST', '/api/security/worm/quorum/approve'),
    ('POST', '/api/security/worm/abort'),
    ('POST', '/api/security/worm/break-glass'),
    ('POST', '/api/security/worm/break-glass/key'),
    ('POST', '/api/security/worm/cool-off'),
    ('POST', '/api/security/worm/clock/clear'),
    ('POST', '/api/security/sentinel'),
    ('POST', '/api/security/canaries/test'),
    ('POST', '/api/security/mac/remediate'),
    ('POST', '/api/security/firewall/quarantine'),
    ('DELETE', '/api/security/firewall/quarantine/<path:ip>'),
    ('POST', '/api/security/firewall/vip'),
    ('POST', '/api/security/firewall/airgap'),
    ('POST', '/api/security/behavior/entropy'),
    ('POST', '/api/security/behavior/diff-scan'),
    ('POST', '/api/security/integrity/run'),
    ('POST', '/api/security/compliance/init'),
    ('POST', '/api/security/incident/brake'),
    ('POST', '/api/security/incident/clean-room'),
}
# No fresh password: plans that only sit in the database, reads over SSH or signed read-only probes, or the sign-in routes themselves.
NO_FRESH_PASSWORD = {
    ('POST', '/api/devices/<name>/read'),        # reads, as a scan does, through the account bound for reading
    ('POST', '/api/devices/<name>/report'),      # saves what an apply would do. The apply asks
    ('POST', '/api/dsl/compile'),
    ('POST', '/api/dsl/whatif'),
    ('POST', '/api/dsl/stage'),                  # a plan in the database, as /api/map/stage is
    ('POST', '/api/netscan/run'),                # only of ranges someone named behind a fresh password
    ('POST', '/api/security/evidence'),
    ('POST', '/api/security/webauthn/assert/begin'),
    ('POST', '/api/security/webauthn/assert/finish'),
    ('POST', '/api/security/compliance/reconverge'),
    ('POST', '/api/security/integrity/stage'),
    ('POST', '/api/security/worm/preview/stage'),
    ('POST', '/api/security/mac/context/stage'),
    ('POST', '/api/security/firewall/shares/stage'),
    ('POST', '/api/security/dash'),
    ('DELETE', '/api/security/dash/<int:dash_id>'),
    ('POST', '/api/map/views'),
    ('DELETE', '/api/map/views/<int:view_id>'),
    ('POST', '/api/map/whatif'),
    ('POST', '/api/map/stage'),
    ('POST', '/api/map/annotations'),
    ('DELETE', '/api/map/annotations/<int:note_id>'),
    ('POST', '/api/map/designs'),
    ('DELETE', '/api/map/designs/<int:design_id>'),
    ('POST', '/api/map/designs/<int:design_id>/stage'),
    ('POST', '/api/clamav/hosts/<host>/collect'),
    ('POST', '/api/backups'),
    ('POST', '/api/changes'),
    ('DELETE', '/api/changes/<int:plan_id>'),
    ('PUT', '/api/changes/<int:plan_id>'),
    ('POST', '/api/changes/<int:plan_id>/ran'),
    ('POST', '/api/changes/check'),
    ('POST', '/api/clone/preview'),                # reads the index only
    ('POST', '/api/clone'),                        # saves plans, as /api/changes does: running them is what asks
    ('POST', '/api/vm/copy/preview'),              # reads the index only
    ('POST', '/api/vm/copy'),                      # saves a plan, as /api/changes does: deploying it is what asks
    ('POST', '/api/console/sessions/<sid>/input'),    # typing into a session already opened with the password
    ('POST', '/api/console/sessions/<sid>/resize'),
    ('DELETE', '/api/console/sessions/<sid>'),        # closing a session of your own
    ('PUT', '/api/vm/specs/<name>'),               # a VM spec only fills a step's empty fields when a plan is saved: nothing runs
    ('DELETE', '/api/vm/specs/<name>'),
    ('POST', '/api/deploy/check'),
    ('POST', '/api/deploy/groups/<gid>/cancel'),
    ('POST', '/api/deploy/jobs/<jid>/browse'),
    ('POST', '/api/deploy/settings/test'),
    ('POST', '/api/deploy/setup-script'),
    ('POST', '/api/enroll'),
    ('POST', '/api/enroll/check'),
    ('PUT', '/api/files/ignore'),
    ('POST', '/api/git/commit'),
    ('POST', '/api/git/history'),
    ('PUT', '/api/git/ignore'),
    ('POST', '/api/git/status'),
    ('POST', '/api/git/survey'),
    ('PUT', '/api/hosts/<name>/schedule'),
    ('POST', '/api/jobs/report'),
    ('POST', '/api/jobs/state'),
    ('POST', '/api/keys'),
    ('POST', '/api/login'),
    ('POST', '/api/logout'),
    ('POST', '/api/me/password'),
    ('POST', '/api/moves'),
    ('DELETE', '/api/moves/<int:plan_id>'),
    ('PUT', '/api/moves/<int:plan_id>'),
    ('POST', '/api/moves/<int:plan_id>/copy'),
    ('POST', '/api/moves/check'),
    ('POST', '/api/planner/changes'),
    ('PUT', '/api/planner/design'),
    ('PUT', '/api/planner/example'),
    ('PUT', '/api/planner/offsite'),
    ('POST', '/api/planner/versions'),           # a copy of a design in the database, as PUT /api/planner/design is one of the saved design
    ('POST', '/api/planner/versions/compare'),
    ('POST', '/api/planner/versions/restore'),   # what a Save design does, and the design it replaces is kept first
    ('DELETE', '/api/planner/versions/<int:vid>'),
    ('POST', '/api/reauth'),
    ('POST', '/api/scan'),
    ('POST', '/api/scan/all'),
    ('POST', '/api/scheduler/report'),
    ('POST', '/api/scheduler/schedules/<int:schedule_id>/verify'),
    ('DELETE', '/api/shares'),
    ('POST', '/api/shares'),
    ('POST', '/api/shares/validate'),
    ('POST', '/api/tasks'),
    ('DELETE', '/api/tasks/<int:task_id>'),
    ('PUT', '/api/tasks/<int:task_id>'),
    ('POST', '/api/tasks/check'),
    ('POST', '/api/tasks/script'),
    ('POST', '/api/security/report'),
}
# Writes no audit row in its own view, and why that is fine. Anything else must call audit() or git_call().
AUDITED_ELSEWHERE = {
    'api_console_input': 'the session is: console.open and console.close, and every keystroke in the recording when it is on',
    'api_console_resize': 'part of the session, and of its recording',
    'api_console_close': 'console.close, written as the session ends',
    'api_deploy_access': 'deploy.enroll writes deploy.setup',
    'api_deploy_adopt': 'deploy.adopt goes through deploy.run',
    'api_deploy_check': 'a signed probe: deploy.run writes the row',
    'api_deploy_job_action': 'jobs.action goes through deploy.run',
    'api_deploy_job_browse': 'jobs.browse goes through deploy.run',
    'api_deploy_job_restore': 'jobs.restore goes through deploy.run',
    'api_roles': 'save_role writes role.add',
    'api_remote_nodes': 'remotes.add writes remote.add',
    'api_remote_adopt': 'deploy.adopt goes through deploy.run',
    'api_remote_revoke': 'remotes.revoke writes remote.revoke',
}
NOT_AUDITED = {
    'api_dsl_compile': 'reads only: text in, text out',
    'api_dsl_whatif': 'reads only: rules against a copy of the facts',
    'api_map_whatif': 'reads only: a draft plan against a copy of the facts',
    'api_logout': 'the session simply ends',
    'api_enroll_check': 'reads one link and changes nothing',
    'api_jobs_report': 'recorded as a job run',
    'api_jobs_state': 'a progress line that the next one replaces; the run itself is recorded',
    'api_scheduler_report': 'recorded as a schedule run',
    'api_security_report': 'recorded as security events',
    'api_moves_check': 'compares with the index and saves nothing',
    'api_changes_check': 'compares with the index and saves nothing',
    'api_clone_preview': 'builds plans from the index and saves nothing',
    'api_vm_copy_preview': 'builds a plan from the index and saves nothing',
    'api_tasks_check': 'compares with the index and saves nothing',
    'api_shares_validate': 'compares with the index and saves nothing',
    'api_planner_changes': 'compares with the index and saves nothing',
    'api_planner_version_compare': 'compares two designs and saves nothing',
}


class RouteRules(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.db = Database(f'sqlite:///{cls.tmp.name}/idx.db')
        conn = cls.db.connect()
        cls.db.migrate(conn)
        users.create(conn, 'root', PW, 'admin')
        conn.close()
        cls.web = server.create_app(server.App(cls.db), 's' * 48)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def writes(self):
        for rule in self.web.url_map.iter_rules():
            if rule.rule.startswith('/api/'):
                for method in sorted(rule.methods - {'OPTIONS', 'HEAD', 'GET'}):
                    yield method, rule

    def test_every_write_route_is_in_the_table(self):
        seen = {(m, r.rule) for m, r in self.writes()}
        self.assertEqual(seen - FRESH_PASSWORD - NO_FRESH_PASSWORD, set(), 'say whether a new route needs a fresh password')
        self.assertEqual((FRESH_PASSWORD | NO_FRESH_PASSWORD) - seen, set(), 'this route is gone: take it out of the table')
        self.assertEqual(FRESH_PASSWORD & NO_FRESH_PASSWORD, set())

    def test_the_table_is_what_the_routes_do(self):
        for method, rule in self.writes():
            path = re.sub(r'<int:\w+>', '1', rule.rule)
            path = re.sub(r'<any\(([^)]*)\):\w+>', lambda m: m[1].split(',')[0].strip(' "'), path)
            path = re.sub(r'<[^>]+>', 'x', path)
            c = self.web.test_client()
            self.assertEqual(c.post('/api/login', json={'username': 'root', 'password': PW}).status_code, 200)
            with c.session_transaction() as s:
                s['auth_at'] = 0
            r = c.open(path, method=method, json={})
            asked = (r.get_json(silent=True) or {}).get('reauth') is True
            self.assertEqual((method, rule.rule, asked), (method, rule.rule, (method, rule.rule) in FRESH_PASSWORD))

    def test_every_write_is_audited_or_says_why_not(self):
        for method, rule in self.writes():
            view = self.web.view_functions[rule.endpoint]
            name = rule.endpoint
            if name in AUDITED_ELSEWHERE or name in NOT_AUDITED or name in ('api_login',):
                continue
            src = inspect.getsource(inspect.unwrap(view))
            self.assertRegex(src, r'audit\(|git_call\(|save_role\(', f'{method} {rule.rule}: add an audit row, or a reason to the table')

    def gets_reaching_a_host(self, web):
        """Calls every GET-only route as an admin, with a host it could reach, and notes what tries to: a signed run, or any ssh at
        all. Actually calling them sees through helpers, which reading a view's own source cannot. Only this thread counts: the
        app's background loops measure hosts by themselves."""
        host = 'walkhost'
        conn = self.db.connect()
        conn.execute(f"""INSERT INTO hosts (hostname, ssh_host, ssh_user, inventory_json, last_scanned_at) VALUES (:n, :n, 'scan', '{{}}', {self.db.ts(':t')})
                         ON CONFLICT (hostname) DO NOTHING""", {'n': host, 't': 1600000000})
        deploy.set_access(conn, host, 'ready', '', 'test')
        conn.close()
        here, reached, real_popen = threading.current_thread(), [], subprocess.Popen

        class Spy(real_popen):
            def __init__(self, args, *a, **k):
                if threading.current_thread() is here and isinstance(args, (list, tuple)) and args and args[0] == 'ssh':
                    reached.append(current[0])
                super().__init__(args, *a, **k)

        def signed(*_a, **_k):
            if threading.current_thread() is here:
                reached.append(current[0])
            return {'run_id': 1, 'group_id': 'g', 'host': host, 'status': 'ok', 'exit_code': 0, 'output': ''}
        current = [None]
        c = web.test_client()
        self.assertEqual(c.post('/api/login', json={'username': 'root', 'password': PW}).status_code, 200)
        q = {'host': host, 'from': host, 'to': host, 'port': '445', 'src': 'x', 'dst': 'y', 'rel': 'z', 'path': '/', 'q': 'x'}
        with mock.patch.object(subprocess, 'Popen', Spy), mock.patch.object(deploy, 'run', signed), mock.patch.object(deploy, 'raw', signed):
            for rule in web.url_map.iter_rules():
                if not rule.rule.startswith('/api/') or rule.methods - {'GET', 'HEAD', 'OPTIONS'}:
                    continue                      # shared with a write: the write is what runs
                current[0] = rule.rule
                path = re.sub(r'<int:\w+>', '1', rule.rule)
                path = re.sub(r'<any\(([^)]*)\):\w+>', lambda m: m[1].split(',')[0].strip(' "'), path)
                c.get(re.sub(r'<[^>]+>', host, path), query_string=q)
        return reached

    def test_no_get_runs_on_a_host(self):
        self.assertEqual(self.gets_reaching_a_host(self.web), [], 'make it a POST')

    def test_the_walk_catches_a_get_that_reaches_a_host_through_a_helper(self):
        """Otherwise the test above could pass by seeing nothing."""
        web = server.create_app(server.App(self.db), 's' * 48)

        def helper():
            return deploy.run(self.db, 'walkhost', 'true', kind='test')

        @web.get('/api/planted')
        @login_required
        def planted():
            helper()
            return {}
        self.assertEqual(self.gets_reaching_a_host(web), ['/api/planted'])
