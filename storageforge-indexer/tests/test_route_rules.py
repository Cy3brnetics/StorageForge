"""Every route's rules in one table, so a new one has to say what it is (EQ-04). Walks the URL map, as test_every_route_is_listed
does for permissions. Docs: concepts rules 13 and 14."""
import inspect
import re
import tempfile
import unittest

from storageforge_index import server, users
from storageforge_index.db import Database

PW = 'a long enough password'

# Changes something, runs on a host or touches accounts and keys: asks for a password typed in the last 5 minutes.
FRESH_PASSWORD = {
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
}
# No fresh password: plans that only sit in the database, reads over SSH or signed read-only probes, or the sign-in routes themselves.
NO_FRESH_PASSWORD = {
    ('POST', '/api/clamav/hosts/<host>/collect'),
    ('POST', '/api/backups'),
    ('POST', '/api/changes'),
    ('DELETE', '/api/changes/<int:plan_id>'),
    ('PUT', '/api/changes/<int:plan_id>'),
    ('POST', '/api/changes/<int:plan_id>/ran'),
    ('POST', '/api/changes/check'),
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
}
# Writes no audit row in its own view, and why that is fine. Anything else must call audit() or git_call().
AUDITED_ELSEWHERE = {
    'api_deploy_access': 'deploy.enroll writes deploy.setup',
    'api_deploy_adopt': 'deploy.adopt goes through deploy.run',
    'api_deploy_check': 'a signed probe: deploy.run writes the row',
    'api_deploy_job_action': 'jobs.action goes through deploy.run',
    'api_deploy_job_browse': 'jobs.browse goes through deploy.run',
    'api_deploy_job_restore': 'jobs.restore goes through deploy.run',
    'api_roles': 'save_role writes role.add',
}
NOT_AUDITED = {
    'api_logout': 'the session simply ends',
    'api_enroll_check': 'reads one link and changes nothing',
    'api_jobs_report': 'recorded as a job run',
    'api_jobs_state': 'a progress line that the next one replaces; the run itself is recorded',
    'api_scheduler_report': 'recorded as a schedule run',
    'api_moves_check': 'compares with the index and saves nothing',
    'api_changes_check': 'compares with the index and saves nothing',
    'api_tasks_check': 'compares with the index and saves nothing',
    'api_shares_validate': 'compares with the index and saves nothing',
    'api_planner_changes': 'compares with the index and saves nothing',
}
# What it takes to run something on a host: never reachable from a GET.
RUNS_ON_HOST = re.compile(r'open_host_transport|deploy\.run\(|start_group|jobs\.action|repo_(status|sync|history|commit)|survey_host')


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

    def test_no_get_runs_on_a_host(self):
        for rule in self.web.url_map.iter_rules():
            if 'GET' in rule.methods and rule.rule.startswith('/api/'):
                if rule.methods - {'GET', 'HEAD', 'OPTIONS'}:
                    continue                          # shared with a write: the write is what runs
                src = inspect.getsource(inspect.unwrap(self.web.view_functions[rule.endpoint]))
                self.assertIsNone(RUNS_ON_HOST.search(src), f'GET {rule.rule} runs on a host: make it a POST')
