"""The notification center in a real browser (roadmap section 12): the list ranked, the count in the header, what cannot be snoozed says so,
and acknowledging and snoozing change what is shown. Needs playwright and its chromium."""
import tempfile
import threading
import unittest
from unittest import mock

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sync_playwright = None
import time

from storageforge_index import alerts, logrules, server, users
from storageforge_index.db import Database

PW = 'correct horse battery staple'
HOSTILE = '<img src=x onerror=alert(1)> is full'
WRONG = {'crit': ('disk-crit', 'nas:/srv', '/srv is 97% full on nas', 'free up space', 'crit'),
         'drift': ('drift', 'nas:fstab', 'Changed by hand on nas', 'fstab differs', 'warn'),
         'scan': ('scan-failed', 'pc', 'Scan failed on pc', 'no route to host', 'warn'),
         **{f'm{i}': ('mount-gone', f'pc:/mnt/{i}', f'/mnt/{i} is gone on pc', HOSTILE, 'warn') for i in range(5)}}


@unittest.skipUnless(sync_playwright, 'needs playwright (CI has it)')
class BrowserNotifications(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from werkzeug.serving import make_server
        cls.tmp = tempfile.TemporaryDirectory()
        cls.db = Database(f'sqlite:///{cls.tmp.name}/idx.db')
        conn = cls.db.connect()
        cls.db.migrate(conn)
        users.create(conn, 'admin', PW, 'admin')
        for name in ('nas', 'pc'):
            conn.execute(f"""INSERT INTO hosts (hostname, ssh_host, ssh_user, inventory_json, last_scanned_at)
                             VALUES ('{name}', '{name}', 'scan', '{{}}', {cls.db.ts(':t')})""", {'t': 1600000000})
        conn.execute("INSERT INTO graph_nodes (node_id, kind, label, host, updated_at) VALUES ('host:nas', 'Host', 'nas', 'nas', 1)")
        rid = next(r['id'] for r in logrules.rules(conn) if r['builtin'] == 'unit-failed')
        conn.execute('INSERT INTO log_rule_hits (rule_id, host, bucket, hits, sample) VALUES (:r, :h, :b, 3, :s)',
                     {'r': rid, 'h': 'nas', 'b': int(time.time() // 300), 's': "smbd.service: Failed with result 'exit-code'."})
        WRONG[f'log-rule:{rid}:nas'] = ('log-rule', f'nas:{rid}', 'Services failing on nas', '3 line(s) in the last 1 h', 'info')
        conn.close()
        with mock.patch.object(alerts, 'problems', lambda conn: dict(WRONG)), mock.patch.object(alerts, 'send', lambda *a, **k: ['recorded']):
            alerts.evaluate(cls.db)
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
        self.page.set_default_timeout(30000)
        self.errors = []
        self.page.on('pageerror', lambda e: self.errors.append(e.stack or str(e)))      # the stack names the line when CI catches one
        self.page.on('console', lambda m: self.errors.append(m.text) if 'Content Security Policy' in m.text else None)
        self.page.goto(self.base + '/login')
        self.page.fill('input[type=text], input[name=username], #username', 'admin')
        self.page.fill('input[type=password]', PW)
        self.page.press('input[type=password]', 'Enter')
        self.page.wait_for_url(self.base + '/**')
        self.page.wait_for_selector('.tabs button')
        self.page.wait_for_selector('html[data-route-ready]', state='attached')

    def open_center(self):
        self.page.click('#tabbtn-notifications')
        self.page.wait_for_selector('#nt-groups .nt-group')

    def test_the_header_counts_the_critical_ones_in_words_and_opens_the_center(self):
        self.page.wait_for_selector('#notifchip:not([hidden])')
        self.assertIn('1 critical notification', self.page.inner_text('#notifchip'))
        self.assertIn('7 warnings', self.page.inner_text('#notifchip'))
        self.page.click('#notifchip')
        self.page.wait_for_selector('#nt-groups .nt-group')
        self.assertTrue(self.page.is_visible('#tab-notifications'))
        self.assertEqual(self.errors, [])

    def test_critical_is_first_and_a_flood_is_one_row_with_its_count(self):
        self.open_center()
        heads = [h.lower() for h in self.page.locator('#nt-groups .nt-group h3').all_inner_texts()]      # the panel's headings are set in capitals by the stylesheet
        self.assertTrue(heads[0].startswith('critical: disk-crit on nas'), heads)
        self.assertEqual(len(heads), 5, heads)
        flood = next(h for h in heads if 'mount-gone' in h)
        self.assertIn('× 5', flood)
        self.assertIn('9 open: 1 critical, 7 warnings, 1 for information', self.page.inner_text('#nt-count'))
        self.assertEqual(self.errors, [])

    def test_a_failing_service_has_a_fix_that_opens_as_a_plan_in_changes_and_then_its_way_back(self):
        self.open_center()
        mine = '#nt-groups .nt-group:has(h3:has-text("log-rule"))'
        self.assertIn('Its way back: Stop smbd.service again, as it was found', self.page.inner_text(mine))
        self.assertEqual(self.page.locator('#nt-groups .nt-group:has(h3:has-text("scan-failed")) button:has-text("Prepare a fix")').count(), 0, 'no way back, no fix')
        self.page.click(f'{mine} button:has-text("Prepare a fix: Restart smbd.service on nas")')
        self.page.wait_for_selector('.tabs button[data-tab="changes"][aria-selected="true"]')
        self.page.wait_for_selector('#tab-changes :text("Set service smbd.service → restarted")')      # the plan's step, not only its name in the list
        self.assertEqual(self.page.evaluate('CH.plan.tasks[0].params'), {'unit': 'smbd.service', 'state': 'restarted'})
        self.page.click('#tabbtn-notifications')
        self.page.wait_for_selector(f'{mine} button:has-text("Open the prepared fix")')
        self.page.click(f'{mine} button:has-text("Prepare the way back")')
        self.page.wait_for_selector('.tabs button[data-tab="changes"][aria-selected="true"]')
        self.page.wait_for_selector('#tab-changes option:text-matches("Undo: stop smbd.service on nas")', state='attached')
        self.page.wait_for_selector('#tab-changes :text("Set service smbd.service → stopped")')
        self.assertEqual(self.page.evaluate('CH.plan.tasks[0].params'), {'unit': 'smbd.service', 'state': 'stopped'})
        self.assertEqual(self.errors, [])

    def test_what_a_host_said_is_text_and_never_markup(self):
        self.open_center()
        self.assertEqual(self.page.locator('#nt-groups img').count(), 0)
        self.assertIn('<img src=x', self.page.inner_text('#nt-groups'))

    def test_what_cannot_be_ignored_has_no_snooze_and_says_why(self):
        self.open_center()
        for kind in ('disk-crit', 'drift'):
            group = self.page.locator(f'#nt-groups .nt-group:has(h3:has-text("{kind}"))')
            self.assertIn('Cannot be snoozed or muted', group.inner_text())
            self.assertEqual(group.locator('button:has-text("Snooze")').count(), 0, kind)
            self.assertEqual(group.locator('button:has-text("Acknowledge")').count(), 1, kind)
        plain = self.page.locator('#nt-groups .nt-group:has(h3:has-text("scan-failed"))')
        self.assertEqual(plain.locator('button:has-text("Snooze")').count(), 1)

    def test_acknowledging_keeps_it_in_the_list_and_snoozing_moves_it_aside(self):
        self.open_center()
        crit = '#nt-groups .nt-group:has(h3:has-text("disk-crit"))'
        self.page.click(f'{crit} button:has-text("Acknowledge")')
        self.page.fill('dialog[open] input', 'ordering a disk')
        self.page.click('dialog[open] button[type=submit]')
        self.page.wait_for_selector(f'{crit} :text("is on it: ordering a disk")')
        self.assertIn('1 critical', self.page.inner_text('#nt-count'), 'still counted: an acknowledgement removes nothing')
        self.page.click('#nt-groups .nt-group:has(h3:has-text("scan-failed")) button:has-text("Snooze")')
        self.page.wait_for_selector('#nt-groups .nt-group:has(h3:has-text("scan-failed"))', state='detached')
        self.assertIn('Snoozed and muted (1)', self.page.inner_text('#nt-quiet-sum'))
        self.page.click('#nt-quiet-sum')
        self.page.click('#nt-quiet button:has-text("End snooze")')
        self.page.wait_for_selector('#nt-groups .nt-group:has(h3:has-text("scan-failed"))')
        self.page.click('#nt-history-box summary')
        self.page.wait_for_selector('#nt-history li:has-text("acknowledged by web:admin: ordering a disk")')
        self.page.click(f'{crit} button:has-text("Not on it")')
        self.page.wait_for_selector(f'{crit} button:has-text("Acknowledge")')
        self.assertEqual(self.errors, [])


if __name__ == '__main__':
    unittest.main()
