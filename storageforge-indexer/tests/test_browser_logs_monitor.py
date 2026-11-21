"""The monitoring view of the Logs panel in a real browser (roadmap section 3, phase 4): each host against its usual, the silent one first,
open log alerts, new kinds of line as text, ingest health, and the ways into the logs from a notification and from a disk or a mount. The
counts behind it are real: weeks of lines stored through hostlogs.store, a pickup at a time, before the server starts. Needs Playwright and
its Chromium, which CI installs; without them this skips and says so."""
import tempfile
import threading
import time
import unittest
from unittest import mock

from storageforge_index import alerts, hostlogs, netconsole, pstore, server, users
from storageforge_index.db import Database

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sync_playwright = None
PW = 'a long enough password'
HOSTILE = '<img src=x onerror=alert(1)> controller <b>reset</b>'
HOUR, DAY, WEEK = 3600, 86400, 7 * 86400


@unittest.skipUnless(sync_playwright, 'needs playwright (CI has it)')
class BrowserLogsMonitor(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from werkzeug.serving import make_server
        cls.tmp = tempfile.TemporaryDirectory()
        cls.db = Database(f'sqlite:///{cls.tmp.name}/idx.db')
        conn = cls.db.connect()
        cls.db.migrate(conn)
        users.create(conn, 'admin', PW, 'admin')
        for name in ('nas', 'quiet', 'cold'):                         # cold has never had its journal collected
            conn.execute(f"""INSERT INTO hosts (hostname, ssh_host, ssh_user, inventory_json, last_scanned_at)
                             VALUES ('{name}', '{name}', 'scan', '{{}}', {cls.db.ts(':t')})""", {'t': 1600000000})
        now = time.time()
        cls.n = 0

        def hours(host, start, count, per_hour, unit='cron.service', via=None, msg='job {i} ran', priority=6):
            for h in range(count):
                t0 = start + h * HOUR
                lines = []
                for i in range(per_hour):
                    cls.n += 1
                    lines.append({'key': f'k{cls.n}', 'at_us': int((t0 + i * HOUR / per_hour) * 1e6), 'priority': priority, 'unit': unit, 'ident': None,
                                  'pid': None, 'message': msg.format(i=i)})
                hostlogs.store(conn, host, {'lines': lines, 'state': 'ok', 'cut': False}, min(t0 + HOUR, now), via=via)
        for k in (3, 2, 1):                                           # three weeks of the same hours before now
            hours('nas', now - k * WEEK - 3 * HOUR, 3, 20)
            hours('quiet', now - k * WEEK - 4 * HOUR, 4, 30, via='agent')
        hours('quiet', now - 4 * HOUR, 2, 30, via='agent')            # quiet's agent pushed until two hours ago, and nothing since
        hours('nas', now - 3 * HOUR, 2, 20)
        hours('nas', now - HOUR, 1, 400, unit='smbd.service', msg='smbd {i} refused')       # nas: twenty times its usual hour
        hours('nas', now - HOUR, 1, 1, unit='', msg=HOSTILE, priority=3)                    # and a kind of line it never logged
        netconsole.save_source(conn, 'nas', '10.42.0.7', 6665, 'admin')
        pstore.store(conn, 'quiet', pstore.parse(f'@@who 0\n@@records\n{int(now) - 7200} 900 /var/lib/systemd/pstore/1/dmesg.txt\n'
                                                 f'@@file {int(now) - 7200} /var/lib/systemd/pstore/1/dmesg.txt\n|<0>[ 9.1] Kernel panic - not syncing: VFS\n@@end\n', now), now)
        conn.close()
        with mock.patch.object(alerts, 'scan_problems', lambda conn: {}), mock.patch.object(alerts, 'backup_problems', lambda conn: {}), \
                mock.patch.object(alerts, 'cert_problems', lambda: {}), mock.patch.object(alerts, 'send', lambda *a, **k: ['recorded']):
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
        self.page.on('pageerror', lambda e: self.errors.append(str(e)))
        self.page.on('console', lambda m: self.errors.append(m.text) if 'Content Security Policy' in m.text else None)
        self.requests = []
        self.page.on('request', lambda r: self.requests.append(r.url) if '/api/' in r.url else None)
        self.page.goto(self.base + '/login')
        self.page.fill('input[type=text], input[name=username], #username', 'admin')
        self.page.fill('input[type=password]', PW)
        self.page.press('input[type=password]', 'Enter')
        self.page.wait_for_url(self.base + '/**')
        self.page.wait_for_selector('.tabs button')
        self.page.wait_for_load_state('load')
        self.page.wait_for_selector('html[data-route-ready]', state='attached')

    def open_logs(self, query=''):
        self.page.goto(f'{self.base}/#/topo/hostlogs{query}')
        self.page.reload()
        self.page.wait_for_selector('html[data-route-ready]', state='attached')
        self.page.wait_for_selector('#hl-monitor li.hl-host')

    def host(self, name):
        return self.page.locator(f'#hl-monitor li.hl-host[data-host="{name}"]')

    def test_the_silent_host_is_first_then_the_loud_one_and_each_says_so_in_words(self):
        self.open_logs()
        order = self.page.eval_on_selector_all('#hl-monitor li.hl-host', 'els => els.map((e) => e.dataset.host)')
        self.assertEqual(order, ['quiet', 'nas', 'cold'])
        quiet = self.host('quiet')
        self.assertEqual(quiet.locator('.hl-hname .st-failed').inner_text(), 'stopped logging', 'a word, not only a colour')
        self.assertIn('No new line since', quiet.inner_text())
        self.assertIn('pushed by the agent, signed', quiet.inner_text())
        self.assertIn('Critical: quiet has stopped logging', quiet.inner_text())
        nas = self.host('nas')
        self.assertRegex(nas.inner_text(), r'smbd\.service: \d{3} lines in the last hour, usually 0', 'whole 5 minutes only: the hour is a little less than the 400 lines')
        self.assertIn('Warning: nas is logging much more than usual', nas.inner_text())
        self.assertIn('collected by the scan over SSH, not signed', nas.inner_text())
        self.assertIn('not collected', self.host('cold').inner_text())
        self.assertIn('2 hosts with something to look at, first.', self.page.inner_text('#hl-mon-sum'))
        self.assertEqual(self.errors, [])

    def test_netconsole_and_pstore_are_said_beside_the_journal_and_never_as_signed(self):
        self.open_logs()
        self.assertIn('netconsole from 10.42.0.7 port 6665, not signed: nothing heard yet', self.host('nas').inner_text())
        quiet = self.host('quiet')
        self.assertIn('pstore: 1 crash record, the newest written', quiet.inner_text())
        self.assertIn('Warning: The kernel on quiet crashed and left a record', quiet.inner_text())
        self.assertEqual(self.errors, [])

    def test_a_netconsole_source_is_added_and_a_cancelled_dialog_draws_nothing_again(self):
        self.open_logs()
        self.page.click('#hl-nc-box summary')
        self.page.wait_for_selector('#hl-nc li:has-text("nas: 10.42.0.7 port 6665")')
        self.assertIn('does not listen for netconsole', self.page.inner_text('#hl-nc-recv'))
        self.page.eval_on_selector('#hl-nc li', 'li => { li.dataset.mark = "kept" }')
        asked = len([u for u in self.requests if '/api/hostlogs/netconsole' in u])
        self.page.click('#hl-nc-new')
        self.page.wait_for_selector('dialog[open]')
        self.page.keyboard.press('Escape')
        self.page.wait_for_selector('dialog[open]', state='detached')
        self.page.click('#hl-nc li button:has-text("Remove")')
        self.page.wait_for_selector('dialog[open]')
        self.page.keyboard.press('Escape')
        self.page.wait_for_selector('dialog[open]', state='detached')
        self.page.wait_for_timeout(300)
        self.assertEqual(self.page.locator('#hl-nc li[data-mark="kept"]').count(), 1)
        self.assertEqual(len([u for u in self.requests if '/api/hostlogs/netconsole' in u]), asked, 'a cancelled dialog asks the server nothing')
        self.page.click('#hl-nc-new')
        self.page.fill('dialog[open] input >> nth=0', 'cold')
        self.page.fill('dialog[open] input >> nth=1', '10.42.0.9')
        self.page.click('dialog[open] button[type=submit]')
        if self.page.locator('#reauthpw').count():
            self.page.fill('#reauthpw', PW)
            self.page.click('#reauthform button[type=submit]')
        self.page.wait_for_selector('#hl-nc li:has-text("cold: 10.42.0.9 port 6665")')
        self.assertEqual(self.errors, [])

    def test_a_new_kind_of_line_is_shown_as_text_and_opens_from_the_keyboard(self):
        self.open_logs()
        nas = self.host('nas')
        summary = nas.locator('details summary')
        self.assertIn('2 new kinds of line in the last day', summary.inner_text())
        summary.focus()
        self.page.keyboard.press('Enter')
        self.assertTrue(nas.locator('details').evaluate('d => d.open'))
        self.assertIn('<img src=x', nas.locator('details').inner_text())
        self.assertEqual(self.page.locator('#hl-monitor img').count(), 0)
        self.assertEqual(nas.locator('details .st-failed').count(), 1, 'the new kind at err is marked as one, in words')
        self.assertEqual(self.errors, [])

    def test_a_host_in_the_view_filters_the_lines_to_it(self):
        self.open_logs()
        self.host('quiet').locator('.hl-hname button').click()
        self.page.wait_for_function("document.querySelector('#hl-host').value === 'quiet'")
        self.page.wait_for_function("location.hash.includes('lhost=quiet')")
        self.assertEqual(self.errors, [])

    def test_a_notification_opens_its_hosts_lines_from_before_it_opened(self):
        self.page.click('#tabbtn-notifications')
        self.page.wait_for_selector('#nt-groups .nt-group')
        link = self.page.locator('#nt-groups .nt-group:has(h3:has-text("log-volume")) a:has-text("nas\'s logs")')
        href = link.get_attribute('href')
        self.assertIn('lhost=nas', href)
        self.assertIn('range=custom', href)
        link.click()
        self.page.wait_for_selector('#tab-hostlogs:not([hidden])')
        self.page.wait_for_selector('#hl-range button[data-range=custom][aria-pressed=true]')
        self.assertEqual(self.page.input_value('#hl-host'), 'nas')
        self.page.wait_for_selector('#hl-lines li:has-text("smbd")')
        self.assertEqual(self.errors, [])

    def test_cancelling_a_dialog_in_the_center_draws_nothing_again(self):
        self.page.click('#tabbtn-notifications')
        self.page.wait_for_selector('#nt-groups .nt-group')
        group = '#nt-groups .nt-group:has(h3:has-text("log-volume"))'
        self.page.eval_on_selector(group, 'g => { g.dataset.mark = "kept" }')
        asked = len([u for u in self.requests if '/api/notifications' in u])
        self.page.click(f'{group} button:has-text("Acknowledge")')
        self.page.wait_for_selector('dialog[open]')
        self.page.keyboard.press('Escape')
        self.page.wait_for_selector('dialog[open]', state='detached')
        self.page.click(f'{group} button:has-text("Mute")')
        self.page.wait_for_selector('dialog[open]')
        self.page.keyboard.press('Escape')
        self.page.wait_for_selector('dialog[open]', state='detached')
        self.page.wait_for_timeout(300)
        self.assertEqual(self.page.locator(f'{group}[data-mark="kept"]').count(), 1, 'the list was drawn again under a cancelled dialog')
        self.assertEqual(len([u for u in self.requests if '/api/notifications' in u]), asked)
        self.assertEqual(self.errors, [])

    def test_a_disk_a_partition_a_pool_and_a_mount_link_to_the_lines_that_name_them(self):
        self.open_logs()
        got = self.page.evaluate("""() => [hlDeviceWord('device', '/dev/sdb'), hlDeviceWord('device', '/dev/mapper/vg-data'), hlDeviceWord('device', 'tank'),
                                           hlDeviceWord('mount', '/srv/media'), hlDeviceWord('mount', '/dev/sdc1'), hlDeviceLinkEl('nas', 'device', '/dev/sdb').getAttribute('href')]""")
        self.assertEqual(got[:5], ['sdb', 'vg-data', 'tank', '/srv/media', 'sdc1'])
        self.assertIn('lhost=nas', got[5])
        self.assertIn('q=sdb', got[5])
        self.page.goto(f'{self.base}/{got[5]}')
        self.page.reload()
        self.page.wait_for_selector('html[data-route-ready]', state='attached')
        self.page.wait_for_function("document.querySelector('#hl-q').value === 'sdb'")
        self.assertEqual(self.errors, [])


if __name__ == '__main__':
    unittest.main()
