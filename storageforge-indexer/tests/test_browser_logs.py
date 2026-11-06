"""The Logs panel in a real browser (UX-30 of the UI audit of 2026-11-04): a time range kept in the URL, when each host was last collected, a
bar chart of lines by level and hour that colour alone does not carry, a unit filter, and a way in from a host. The server is real and its
database holds journal lines for one host and none for another. Needs Playwright and its Chromium, which CI installs; without them this
skips and says so."""
import tempfile
import threading
import time
import unittest

from storageforge_index import hostlogs, server, users
from storageforge_index.db import Database

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sync_playwright = None
PW = 'a long enough password'
HOSTILE = '<img src=x onerror=alert(1)> disk <b>failing</b>'


def line(n, at, priority, unit, message):
    return {'key': f'k{n}', 'at_us': int(at * 1e6), 'priority': priority, 'unit': unit, 'ident': None, 'pid': None, 'message': message}


@unittest.skipUnless(sync_playwright, 'needs playwright (CI has it)')
class BrowserLogs(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from werkzeug.serving import make_server
        cls.tmp = tempfile.TemporaryDirectory()
        cls.db = Database(f'sqlite:///{cls.tmp.name}/idx.db')
        conn = cls.db.connect()
        cls.db.migrate(conn)
        users.create(conn, 'admin', PW, 'admin')
        for name in ('nas', 'cold'):                                  # cold has never had its journal collected
            conn.execute(f"""INSERT INTO hosts (hostname, ssh_host, ssh_user, inventory_json, last_scanned_at)
                             VALUES ('{name}', '{name}', 'scan', '{{}}', {cls.db.ts(':t')})""", {'t': 1600000000})
        conn.execute("INSERT INTO graph_nodes (node_id, kind, label, host, updated_at) VALUES ('host:nas', 'Host', 'nas', 'nas', 1)")
        now = time.time()
        lines = [line(1, now - 600, 3, 'sshd.service', HOSTILE), line(2, now - 900, 4, 'zed.service', 'pool degraded'),
                 line(3, now - 1200, 5, 'sshd.service', 'session opened'), line(4, now - 7200, 6, 'cron.service', 'job ran'),
                 line(5, now - 3 * 86400, 7, 'cron.service', 'old debug'), line(6, now - 3 * 86400 - 60, 3, 'zed.service', 'old error')]
        hostlogs.store(conn, 'nas', {'lines': lines, 'state': 'ok', 'cut': False}, now)
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
        self.page.set_default_timeout(8000)
        self.errors = []
        self.page.on('pageerror', lambda e: self.errors.append(str(e)))
        self.page.on('console', lambda m: self.errors.append(m.text) if 'Content Security Policy' in m.text else None)
        self.requests = []
        self.page.on('request', lambda r: self.requests.append(r.url) if '/api/hostlogs' in r.url else None)
        self.page.goto(self.base + '/login')
        self.page.fill('input[type=text], input[name=username], #username', 'admin')
        self.page.fill('input[type=password]', PW)
        self.page.press('input[type=password]', 'Enter')
        self.page.wait_for_url(self.base + '/**')
        self.page.wait_for_selector('.tabs button')
        self.page.wait_for_load_state('load')

    def open_logs(self, query=''):
        self.page.goto(f'{self.base}/#/topo/hostlogs{query}')
        self.page.reload()                                           # a typed address is a fresh page, as a pasted link is
        self.page.wait_for_selector('#hl-lines li')

    def hash(self):
        return self.page.evaluate('location.hash')

    def sent(self, path, **needs):
        return [u for u in self.requests if path in u and all(f'{k}=' in u for k in needs)]

    # ── the range ────────────────────────────────────────────────────────────────────────────────────────────────
    def test_the_range_is_in_the_url_and_decides_what_is_asked(self):
        self.open_logs()
        self.assertEqual(self.page.get_attribute('#hl-range button[data-range=week]', 'aria-pressed'), 'true')
        self.assertTrue(self.sent('/api/hostlogs/counts', since=1), self.requests)
        self.page.click('#hl-range button[data-range=hour]')
        self.page.wait_for_selector('#hl-range button[data-range=hour][aria-pressed=true]')
        self.assertIn('range=hour', self.hash())
        self.page.wait_for_selector('#hl-count:has-text("3 lines shown")')                # the answer for the hour, not the week's still on screen
        self.assertNotIn('old error', self.page.inner_text('#hl-lines'))
        self.page.click('#hl-range button[data-range=month]')
        self.page.wait_for_selector('#hl-lines li:has-text("old error")')
        self.assertIn('range=month', self.hash())
        self.page.click('#hl-range button[data-range=week]')
        self.page.wait_for_selector('#hl-range button[data-range=week][aria-pressed=true]')
        self.assertNotIn('range=', self.hash())                       # the default is not written into the URL
        self.assertEqual(self.errors, [])

    def test_a_link_opens_on_its_range_and_filters_and_back_returns_to_the_last_one(self):
        self.open_logs('?lhost=nas&range=day&level=warning&unit=zed.service')
        self.assertEqual(self.page.get_attribute('#hl-range button[data-range=day]', 'aria-pressed'), 'true')
        self.assertEqual(self.page.input_value('#hl-host'), 'nas')
        self.assertEqual(self.page.input_value('#hl-level'), 'warning')
        self.assertEqual(self.page.input_value('#hl-unit'), 'zed.service')
        self.page.wait_for_selector('#hl-lines li:has-text("pool degraded")')
        self.assertEqual(self.page.locator('#hl-lines li').count(), 1)
        self.page.click('#hl-range button[data-range=month]')
        self.page.wait_for_selector('#hl-lines li:has-text("old error")')
        self.page.go_back()
        self.page.wait_for_selector('#hl-range button[data-range=day][aria-pressed=true]')
        self.page.wait_for_selector('#hl-lines li:has-text("pool degraded")')
        self.assertNotIn('old error', self.page.inner_text('#hl-lines'))
        self.assertEqual(self.errors, [])

    def test_a_custom_range_has_two_ends_and_a_wrong_order_searches_nothing(self):
        self.open_logs()
        self.page.click('#hl-range button[data-range=custom]')
        self.page.wait_for_selector('#hl-custom', state='visible')
        self.page.fill('#hl-from', '2000-01-01T00:00')
        self.page.fill('#hl-to', '2000-01-02T00:00')
        before = len(self.requests)
        self.page.click('#hl-custom button[type=submit]')
        self.page.wait_for_selector('#hl-lines li:has-text("No lines match")')
        self.assertRegex(self.hash(), r'range=custom&from=2000-01-01T\d\d%3A\d\dZ&to=2000-01-0[12]T\d\d%3A\d\dZ')
        self.assertTrue(any('since=' in u and 'until=' in u for u in self.requests[before:]), self.requests[before:])
        self.assertIn('nothing', self.page.inner_text('#hl-lines'))
        self.page.fill('#hl-from', '2000-01-03T00:00')
        before = len(self.requests)
        self.page.click('#hl-custom button[type=submit]')
        self.page.wait_for_selector('#hl-custom-msg:has-text("From is after To")')
        self.page.wait_for_timeout(200)
        self.assertEqual(self.requests[before:], [])
        # the same custom range, from the URL: what was typed is in the fields in local time
        self.open_logs('?range=custom&from=2026-01-01T10:00Z&to=2026-01-01T12:30Z')
        self.assertEqual(self.page.get_attribute('#hl-range button[data-range=custom]', 'aria-pressed'), 'true')
        got = self.page.evaluate("[hlParseField(document.getElementById('hl-from').value), hlParseField(document.getElementById('hl-to').value)]")
        self.assertEqual(got, [1767261600, 1767270600])
        self.assertEqual(self.errors, [])

    # ── hosts ────────────────────────────────────────────────────────────────────────────────────────────────────
    def test_each_host_says_when_it_was_collected_or_that_it_never_was(self):
        self.open_logs()
        self.page.wait_for_selector('#hl-status li.hl-host')
        rows = self.page.locator('#hl-status li.hl-host')
        text = {rows.nth(i).locator('button').inner_text(): rows.nth(i).inner_text() for i in range(rows.count())}
        self.assertIn('not collected', text['cold'])
        self.assertIn('last collected', text['nas'])
        self.assertRegex(text['nas'], r'\d+ lines kept')
        self.assertEqual(self.page.locator('#hl-status li.hl-host time').count(), 1)          # and the UTC form is on the time
        self.assertIn('UTC', self.page.get_attribute('#hl-status li.hl-host time', 'title'))
        self.assertEqual(self.errors, [])

    def test_an_empty_answer_says_whether_nothing_was_collected_or_nothing_matched(self):
        self.open_logs('?lhost=cold')
        self.page.wait_for_selector('#hl-lines li:has-text("nothing has been collected from cold")')
        self.open_logs('?lhost=nas&range=hour&q=zzzz-no-such-text')
        self.page.wait_for_selector('#hl-lines li:has-text("No lines match these filters")')
        self.assertIn('text', self.page.inner_text('#hl-lines'))
        self.open_logs('?range=custom&from=2000-01-01T00:00Z&to=2000-01-02T00:00Z')
        self.page.wait_for_selector('#hl-lines li:has-text("logged nothing")')
        self.assertEqual(self.errors, [])

    # ── the chart ────────────────────────────────────────────────────────────────────────────────────────────────
    def test_the_chart_has_bars_patterns_a_legend_and_a_text_alternative(self):
        self.open_logs('?range=month')
        self.page.wait_for_selector('#hl-svg')
        self.assertEqual(self.page.get_attribute('#hl-svg', 'role'), 'img')
        self.assertGreaterEqual(self.page.locator('#hl-svg g.hl-bar').count(), 24 * 30)             # an hour is a slot, a quiet one too
        bands = set(self.page.eval_on_selector_all('#hl-svg rect.hl-seg', 'rs => rs.map(r => r.dataset.band)'))
        self.assertEqual(bands, {'err', 'warning', 'notice', 'info'})
        fills = set(self.page.eval_on_selector_all('#hl-svg rect.hl-seg', 'rs => rs.map(r => r.getAttribute("fill"))'))
        self.assertEqual(fills, {f'url(#hl-pat-{k})' for k in ('err', 'warning', 'notice', 'info')})        # a pattern each: not colour alone
        self.assertEqual(self.page.locator('#hl-svg pattern').count(), 4)
        legend = self.page.inner_text('.hl-legend')
        for label, n in (('Errors or worse', 2), ('Warnings', 1), ('Notices', 1), ('Info and debug', 2)):
            self.assertIn(f'{label}: {n}', legend)
        self.assertEqual(self.page.locator('.hl-legend svg.hl-swatch rect').count(), 4)
        self.assertIn('6 lines', self.page.inner_text('#hl-summary'))
        self.assertIn('busiest hour', self.page.inner_text('#hl-summary'))
        title = self.page.eval_on_selector('#hl-svg g.hl-bar:has(rect.hl-seg) > title', 'e => e.textContent')
        self.assertRegex(title, r'UTC\): \d+ lines?\.')
        self.page.click('.hl-alt summary')
        self.page.wait_for_selector('.hl-hours li')
        self.assertIn('error', self.page.inner_text('.hl-hours'))
        self.assertEqual(self.errors, [])

    def test_the_chart_follows_the_host_and_the_range(self):
        self.open_logs('?lhost=cold')
        self.page.wait_for_selector('#hl-chart:has-text("No lines to draw")')
        self.page.select_option('#hl-host', 'nas')
        self.page.wait_for_selector('#hl-svg')
        self.assertIn('lhost=nas', self.hash())
        self.assertTrue(self.sent('/api/hostlogs/counts', host=1), self.requests)
        self.page.click('#hl-range button[data-range=hour]')
        self.page.wait_for_selector('#hl-summary:has-text("3 lines")')
        self.assertEqual(self.errors, [])

    # ── the unit filter ──────────────────────────────────────────────────────────────────────────────────────────
    def test_the_unit_filter_offers_the_units_stored_and_filters_as_it_is_typed(self):
        self.open_logs('?lhost=nas&range=month')
        self.page.wait_for_selector('#hl-units option', state='attached')
        values = self.page.eval_on_selector_all('#hl-units option', 'os => os.map(o => o.value)')
        self.assertEqual(sorted(values), ['cron.service', 'sshd.service', 'zed.service'])
        self.page.fill('#hl-unit', 'zed')                            # no Search button: the lines follow the typing
        self.page.wait_for_selector('#hl-lines li:has-text("pool degraded")')
        self.page.wait_for_selector('#hl-count:has-text("2 lines shown")')
        self.assertNotIn('session opened', self.page.inner_text('#hl-lines'))
        self.assertIn('unit=zed', self.hash())
        self.assertEqual(self.errors, [])

    # ── what a host says is only text ────────────────────────────────────────────────────────────────────────────
    def test_what_a_host_logged_is_shown_as_text_and_never_run(self):
        self.open_logs('?lhost=nas')
        self.page.wait_for_selector('#hl-lines li:has-text("disk")')
        self.assertEqual(self.page.locator('#hl-lines img, #hl-lines b').count(), 0)
        self.assertIn('<img src=x', self.page.inner_text('#hl-lines'))
        self.assertEqual(self.errors, [])

    # ── the way in ───────────────────────────────────────────────────────────────────────────────────────────────
    def test_a_hosts_details_link_to_its_logs(self):
        self.page.select_option('#host', 'nas')
        link = self.page.locator('#summary a:has-text("logs")')
        link.wait_for()
        self.assertIn('hostlogs', link.get_attribute('href'))
        link.click()
        self.page.wait_for_selector('#tab-hostlogs', state='visible')
        self.page.wait_for_selector('#hl-lines li:has-text("pool degraded")')
        self.assertEqual(self.page.input_value('#hl-host'), 'nas')
        self.assertRegex(self.hash(), r'^#/topo/hostlogs\?.*host=nas')
        self.assertIn('lhost=nas', self.hash())
        self.assertEqual(self.errors, [])

    def test_the_old_search_still_works_by_the_button(self):
        self.open_logs('?lhost=nas&range=month')
        self.page.fill('#hl-q', 'pool')
        self.page.click('#hl-form button[type=submit]')
        self.page.wait_for_selector('#hl-count:has-text("1 line shown")')
        self.assertIn('q=pool', self.hash())
        self.assertIn('format=csv', self.page.get_attribute('#hl-export', 'href'))
        self.assertIn('q=pool', self.page.get_attribute('#hl-export', 'href'))


if __name__ == '__main__':
    unittest.main()
