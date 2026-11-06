"""A draft kept in the browser belongs to the account that wrote it (SF-80): the staged change plan and the planner's per-host
design are stamped with the signed-in name, a second account on the same browser never sees them, and the first finds its own
again. Drafts from before the stamp have no owner and are dropped. Needs Playwright and its Chromium, which CI installs."""
import tempfile
import threading
import unittest

from storageforge_index import server, users
from storageforge_index.db import Database

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sync_playwright = None
PW = 'a long enough password'
PLAN = 'admin-private-plan'


@unittest.skipUnless(sync_playwright, 'needs playwright (CI has it)')
class BrowserDrafts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from werkzeug.serving import make_server
        cls.tmp = tempfile.TemporaryDirectory()
        cls.db = Database(f'sqlite:///{cls.tmp.name}/idx.db')
        conn = cls.db.connect()
        cls.db.migrate(conn)
        users.create(conn, 'admin', PW, 'admin')
        users.create(conn, 'second', PW, 'admin')
        conn.execute(f"""INSERT INTO hosts (hostname, ssh_host, ssh_user, inventory_json, last_scanned_at)
                         VALUES ('nas', 'nas', 'scan', '{{}}', {cls.db.ts(':t')})""", {'t': 1600000000})
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
        self.page = self.browser.new_page()          # one page: both accounts share its localStorage, as on a shared workstation
        self.addCleanup(self.page.close)
        self.errors = []
        self.page.on('pageerror', lambda e: self.errors.append(str(e)))

    def sign_in(self, name):
        self.page.goto(self.base + '/login')
        self.page.fill('input[type=text], input[name=username], #username', name)
        self.page.fill('input[type=password]', PW)
        self.page.press('input[type=password]', 'Enter')
        self.page.wait_for_selector('.tabs button')
        self.page.wait_for_load_state('load')

    def sign_out(self):
        self.page.evaluate('sfSignOut()')
        self.page.wait_for_url(self.base + '/login*')

    def open_planner(self):
        self.page.goto(self.base + '/planner')
        self.page.wait_for_selector('#hostpick option[value="nas"]', state='attached')
        self.page.wait_for_load_state('load')
        self.page.evaluate('openDoc("nas")')
        self.page.wait_for_selector('#hostpick')

    def test_a_second_account_sees_no_draft_and_the_first_gets_its_own_back(self):
        self.sign_in('admin')
        self.page.evaluate(f"""() => {{ CH.plan.name = '{PLAN}'; CH.plan.tasks.push({{ id: 't1', type: 'dir', host: 'nas', params: {{ path: '/srv/secret-project' }} }}); chTouch(); }}""")
        self.page.wait_for_selector('#stagebar:not([hidden])')
        self.open_planner()
        self.page.evaluate('() => { S.host = "admin-private-disk"; save(); }')
        self.assertTrue(self.page.evaluate('DOC.dirty'))
        self.sign_out()

        self.sign_in('second')                                        # same browser profile, another account
        self.page.wait_for_selector('#lock:has-text("Sign out second")')
        self.page.wait_for_timeout(400)                               # long enough for a draft to turn up, if one were going to
        self.assertEqual(self.page.evaluate('[CH.plan.name, CH.plan.tasks.length, CH.dirty]'), ['', 0, False])
        self.assertTrue(self.page.locator('#stagebar').is_hidden())
        self.assertNotIn('admin-private', self.page.inner_text('body'))
        self.open_planner()
        self.assertFalse(self.page.evaluate('DOC.dirty'))
        self.assertNotIn('admin-private-disk', self.page.evaluate('JSON.stringify(S)'))
        self.sign_out()

        self.sign_in('admin')                                         # the first account finds its own again
        self.page.wait_for_selector('#stagebar:not([hidden])')
        self.assertEqual(self.page.evaluate('[CH.plan.name, CH.plan.tasks.length, CH.dirty]'), [PLAN, 1, True])
        self.open_planner()
        self.assertTrue(self.page.evaluate('DOC.dirty'))
        self.assertIn('admin-private-disk', self.page.evaluate('JSON.stringify(S)'))
        self.assertEqual(self.errors, [])

    def test_a_draft_from_before_the_stamp_is_dropped_and_shown_to_nobody(self):
        self.page.goto(self.base + '/login')
        self.page.evaluate(f"""() => {{
            localStorage.setItem('sf.changes.draft', JSON.stringify({{ name: '{PLAN}', tasks: [{{ id: 't1', type: 'dir', host: 'nas', params: {{ path: '/srv/x' }} }}], dirty: true }}));
            localStorage.setItem('storageforge.v1:nas', JSON.stringify({{ disks: [] }}));
            localStorage.setItem('storageforge.v1', JSON.stringify({{ disks: [] }}));
        }}""")
        self.sign_in('admin')
        self.page.wait_for_selector('#lock:has-text("Sign out admin")')
        self.page.wait_for_timeout(400)
        self.assertEqual(self.page.evaluate('[CH.plan.name, CH.plan.tasks.length, CH.dirty]'), ['', 0, False])
        self.assertIsNone(self.page.evaluate("localStorage.getItem('sf.changes.draft')"))
        self.open_planner()
        self.assertFalse(self.page.evaluate('DOC.dirty'))
        self.assertEqual(self.page.evaluate("[localStorage.getItem('storageforge.v1:nas'), localStorage.getItem('storageforge.v1')]"), [None, None])
        self.assertEqual(self.errors, [])
