"""Every page and tab in a real browser, with no script errors (EQ-01). Needs Playwright and its Chromium, which CI installs;
without them this skips and says so."""
import tempfile
import threading
import unittest

from storageforge_index import scheduler, server, users
from storageforge_index.db import Database

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sync_playwright = None
PW = 'a long enough password'
TABS = ('details', 'search', 'changes', 'moves', 'schedule', 'deploy', 'docker', 'git', 'rebuild', 'cleanup', 'malware', 'access')


@unittest.skipUnless(sync_playwright, 'needs playwright (CI has it)')
class BrowserSmoke(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from werkzeug.serving import make_server
        cls.tmp = tempfile.TemporaryDirectory()
        cls.db = Database(f'sqlite:///{cls.tmp.name}/idx.db')
        conn = cls.db.connect()
        cls.db.migrate(conn)
        users.create(conn, 'admin', PW, 'admin')
        conn.execute(f"""INSERT INTO hosts (hostname, ssh_host, ssh_user, inventory_json, last_scanned_at)
                         VALUES ('nas', 'nas', 'scan', '{{}}', {cls.db.ts(':t')})""", {'t': 1600000000})
        hid = conn.scalar("SELECT host_id FROM hosts WHERE hostname = 'nas'")
        conn.execute("INSERT INTO git_repos (host_id, path, remotes_json, scan_id) VALUES (:h, '/srv/repo', '[]', 0)", {'h': hid})
        sid = scheduler.create_schedule(conn, {'name': 'nightly', 'host': 'nas', 'cron_expr': '0 3 * * *', 'task_type': 'command', 'task_ref': 'true'}, 'test')[0]['schedule_id']
        scheduler.ingest_report(conn, {'schedule_id': sid, 'exit_code': 0, 'output': 'fine'}, 'test')
        conn.close()
        cls.http = make_server('127.0.0.1', 0, server.create_app(server.App(cls.db), 's' * 48), threaded=True)
        threading.Thread(target=cls.http.serve_forever, daemon=True).start()
        cls.base = f'http://127.0.0.1:{cls.http.server_port}'
        cls.pw = sync_playwright().start()
        cls.browser = cls.pw.chromium.launch()

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls.pw.stop()
        cls.http.shutdown()
        cls.tmp.cleanup()

    def setUp(self):
        self.page = self.browser.new_page()
        self.addCleanup(self.page.close)
        self.errors = []
        self.page.on('pageerror', lambda e: self.errors.append(str(e)))
        self.page.goto(self.base + '/login')
        self.page.fill('input[type=text], input[name=username], #username', 'admin')
        self.page.fill('input[type=password]', PW)
        self.page.press('input[type=password]', 'Enter')
        self.page.wait_for_url(self.base + '/**')
        self.page.wait_for_selector('.tabs button')

    def test_every_tab_opens_without_a_script_error(self):
        found = self.page.eval_on_selector_all('.tabs button', 'bs => bs.map(b => b.dataset.tab)')
        self.assertGreaterEqual(len(found), len(TABS) - 1, found)
        for tab in found:
            self.page.click(f'.tabs button[data-tab="{tab}"]')
            self.page.wait_for_timeout(250)
            self.assertEqual(self.errors, [], tab)

    def settled(self):       # polled from here: wait_for_function evaluates in the page, which this CSP rightly refuses
        for _ in range(100):
            if 'Loading' not in self.page.inner_text('#sec-content'):
                return
            self.page.wait_for_timeout(100)
        self.fail('the security panel never finished loading')

    def test_the_security_panels_really_open_under_the_csp(self):       # they were onclick= attributes once, which the CSP refuses in silence
        self.page.click('.tabs button[data-tab="security"]')
        self.page.wait_for_selector('#sec-subnav button')
        self.page.wait_for_selector('#sec-content .sec-card')
        self.assertIn('never measured', self.page.inner_text('#sec-content'))
        self.assertIn('Not known', self.page.inner_text('#sec-banner'))
        self.assertNotIn('SECURE', self.page.inner_text('#tab-security'))
        for panel in ('worm', 'firewall', 'overview'):
            self.page.click(f'#sec-subnav button[data-sub="{panel}"]')
            self.page.wait_for_selector(f'#sec-subnav button[data-sub="{panel}"][aria-pressed="true"]')
            self.settled()
        self.page.select_option('#host', 'nas')
        for panel in ('decoys', 'mac', 'behavior', 'integrity', 'compliance', 'worm', 'firewall', 'overview'):
            self.page.click(f'#sec-subnav button[data-sub="{panel}"]')
            self.settled()
            self.assertEqual(self.errors, [], panel)
        self.page.click('#sec-subnav button[data-sub="mac"]')
        self.settled()
        self.assertIn('has not been measured', self.page.inner_text('#sec-content'))

    def test_the_planner_and_search_pages_load(self):
        for path in ('/planner', '/search'):
            self.page.goto(self.base + path)
            self.page.wait_for_timeout(400)
            self.assertEqual(self.errors, [], path)

    def test_a_long_unscanned_host_says_so(self):            # PF-08
        self.page.wait_for_selector('#host option:nth-child(2)', state='attached')
        self.assertRegex(self.page.inner_text('#host'), r'nas \(not scanned for \d+ days\)')

    def test_the_schedule_panel_shows_a_reported_run(self):  # PF-24
        self.page.click('.tabs button[data-tab="schedule"]')
        self.page.wait_for_selector('.pill:has-text("REPORTED")')
        for gone in ('Run local', 'Allow destructive', 'catchup', 'Host Scan (index host)'):
            self.assertEqual(self.page.locator(f'text={gone}').count(), 0, gone)
        self.assertEqual(self.errors, [])

    def test_git_calls_go_out_as_post(self):                 # SF-29
        self.page.evaluate("""async () => { window.__h = await postJSON('/api/git/history', {host: 'localhost', path: '/x'}).catch(e => e.message); }""")
        self.assertIn('is not a repository found', str(self.page.evaluate('window.__h')))
