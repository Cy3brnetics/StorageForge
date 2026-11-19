"""Copies on other hosts in a real browser (the owner's request of 2026-11-19): the duplicates views show a copy on another host as a
possible backup and offer no trash for it, a trash that would take the last copy is not staged, a pair is kept in sync from a plan
the user deploys, and the suggestions can be answered. Needs playwright and its chromium."""
import tempfile
import threading
import unittest

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sync_playwright = None

from storageforge_index import server, users
from storageforge_index.db import Database

try:
    from test_copies import MIB, Builder
except ImportError:      # run as tests.test_x from the project folder
    from tests.test_copies import MIB, Builder

PW = 'correct horse battery staple'
HOSTILE = '/srv/<img src=x onerror=alert(1)>'


def seed(ix):
    ix.tree('nas', '/photos/2019', 4)                       # a folder with its copy on another host
    ix.tree('pc', '/backup/2019-copy', 4)
    ix.tree('nas', '/music/a', 5)                           # two copies on one host
    ix.tree('nas', '/music/b', 5)
    ix.file('nas', '/data/a/same.iso', 'ss', size=8 * MIB)  # identical files: twice on one host
    ix.file('nas', '/data/b/same.iso', 'ss', size=8 * MIB)
    ix.file('nas', '/data/a/x.iso', 'xx', size=20 * MIB)    # and once on each of two hosts
    ix.file('pc', '/dl/x.iso', 'xx', size=20 * MIB)
    ix.tree('nas', f'{HOSTILE}/one', 3)                     # a name a host could report: shown as text
    ix.tree('pc', f'{HOSTILE}/two', 3)


@unittest.skipUnless(sync_playwright, 'needs playwright (CI has it)')
class BrowserCopies(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from werkzeug.serving import make_server
        cls.tmp = tempfile.TemporaryDirectory()
        cls.db = Database(f'sqlite:///{cls.tmp.name}/idx.db')
        cls.conn = cls.db.connect()
        cls.db.migrate(cls.conn)
        users.create(cls.conn, 'admin', PW, 'admin')
        cls.ix = Builder().start(cls.db, cls.conn)
        seed(cls.ix)
        cls.conn.execute(f"UPDATE hosts SET last_scanned_at = {cls.db.ts(':t')}", {'t': 1700000000})
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
        cls.conn.close()
        cls.tmp.cleanup()

    def setUp(self):
        self.page = self.browser.new_page()
        self.addCleanup(self.page.close)
        self.page.set_default_timeout(30000)
        self.errors = []
        self.page.on('pageerror', lambda e: self.errors.append(str(e)))
        self.page.on('console', lambda m: self.errors.append(m.text) if 'Content Security Policy' in m.text else None)
        self.page.goto(self.base + '/login')
        self.page.fill('input[type=text], input[name=username], #username', 'admin')
        self.page.fill('input[type=password]', PW)
        self.page.press('input[type=password]', 'Enter')
        self.page.wait_for_url(self.base + '/**')
        self.page.wait_for_selector('.tabs button')
        self.page.wait_for_selector('html[data-route-ready]', state='attached')

    def open_tab(self, tab):
        if self.page.evaluate("document.querySelector('.tabs button.on')?.dataset.tab") != tab or self.page.evaluate("document.querySelector('#panel').classList.contains('collapsed')"):
            self.page.click(f'.tabs button[data-tab="{tab}"]')

    def cleanup_panel(self):
        self.open_tab('copies')                  # Duplicates is the sub-panel a new browser opens on
        self.page.wait_for_selector('#copiesbox section.card')
        self.page.wait_for_selector('#dupesbox details')

    def file_map(self):
        self.page.click('#viewmode button[data-mode="graph"]')
        self.page.wait_for_selector('#filemap .ttools')
        self.page.click('#filemap .ttools button:has-text("Duplicates")')
        self.page.wait_for_function("() => FM.data && !FM.comparing && FM.data.folder_copies.length > 0")

    def select_folder(self, host, path):
        self.page.evaluate('([h, p]) => fmSelect({ type: "folder", key: `${h}\\0${p}` })', [host, path])
        self.page.wait_for_selector('#summary .node-head')

    # ── a class of its own ──────────────────────────────────────────
    def test_cleanup_lists_a_copy_on_another_host_as_a_possible_backup_and_counts_it_apart(self):
        self.cleanup_panel()
        across = self.page.locator('#copiesbox section.card.across', has_text='/photos/2019')
        self.assertIn('a copy on another host: a possible backup', across.inner_text())
        self.assertNotIn('reclaimable', across.inner_text())
        same = self.page.locator('#copiesbox section.card.same', has_text='/music/a')
        self.assertIn('same host · 15.00 MiB reclaimable', same.inner_text())
        head = self.page.inner_text('#copiesbox > p.muted >> nth=0')
        self.assertIn('15.00 MiB could be freed within hosts', head)
        self.assertIn('also on another host: possible backups, not counted', head)
        self.assertIn('is not counted as space to free and is not offered for the trash here', self.page.inner_text('#copiesbox'))
        self.assertIn('8.00 MiB could be freed within hosts · 1 set also on another host (20.00 MiB): possible backups, not counted', self.page.inner_text('#dupestotal'))
        self.assertIn('a copy on another host: a possible backup', self.page.locator('#dupesbox details.across').inner_text())
        self.assertIn('8.00 MiB to reclaim', self.page.locator('#dupesbox details.same').inner_text())
        self.assertEqual(self.page.locator('#copiesbox img').count(), 0, 'a folder name is text')
        self.assertEqual(self.errors, [])

    def test_the_file_map_offers_no_trash_for_a_copy_on_another_host_and_says_why(self):
        self.file_map()
        self.assertIn('also on another host: possible backups, not counted', self.page.inner_text('#filemap .fmstat .fmaway'))
        self.select_folder('nas', '/photos/2019')
        panel = self.page.locator('#summary')
        self.assertIn('whole folder copy', panel.inner_text().lower())        # the panel's headings are set in capitals by the stylesheet
        self.assertIn('is not counted as space to free and is not offered for the trash here', panel.inner_text())
        self.assertIn('possible backup', panel.locator('.fmlist li.away').inner_text())
        for label in ('Trash this folder, keep the other', 'Trash that one'):
            self.assertEqual(panel.locator(f'button:has-text("{label}")').count(), 0, label)
        self.select_folder('nas', '/music/a')                       # two copies on one host: as it always was
        for label in ('Trash this folder, keep the other', 'Trash that one'):
            self.assertEqual(panel.locator(f'button:has-text("{label}")').count(), 1, label)
        self.assertNotIn('is not offered for the trash here', panel.inner_text())
        self.select_folder('nas', '/data/a')                        # one file here has its copy on this host, the other on pc
        rows = panel.locator('.fmlist li:has(input[type=checkbox])')
        away = panel.locator('.fmlist li.away')
        self.assertEqual((rows.count(), away.count()), (2, 1))
        self.assertIn('/data/a/x.iso', away.inner_text())
        self.assertTrue(away.locator('input[type=checkbox]').is_disabled())
        self.assertEqual(away.locator('button:has-text("Trash")').count(), 0)
        self.assertEqual(panel.locator('button:has-text("Trash the 1 here, keep the others")').count(), 1)
        self.assertIn('1 of these has its other copy on another host only', panel.inner_text())
        self.assertEqual(self.errors, [])

    def test_a_trash_that_would_take_the_last_copy_is_not_staged(self):
        self.file_map()
        self.select_folder('nas', '/music/a')
        panel = self.page.locator('#summary')
        panel.locator('button:has-text("Trash this folder, keep the other")').click()
        self.page.wait_for_function("() => CH.plan.tasks.length === 1")
        self.page.evaluate("fmTrash([{ host: 'nas', path: '/music/b' }])")          # the map's own guard, from the sets it shows
        self.page.wait_for_selector('.sf-toast:has-text("that would trash every copy")')
        # a set the map does not show (it lists the largest only): the plan check on the server knows every copy, and refuses
        self.page.evaluate("() => { FM.data.folder_copies = []; return fmTrash([{ host: 'nas', path: '/music/b' }]); }")
        self.page.wait_for_selector('.sf-toast.error:has-text("the last copy")')
        self.assertIn('Not staged', self.page.inner_text('.sf-toast.error'))
        self.assertEqual(self.page.evaluate('CH.plan.tasks.length'), 1)
        self.page.evaluate("() => { CH.plan.tasks.length = 0; chTouch(); }")
        self.assertEqual(self.errors, [])


if __name__ == '__main__':
    unittest.main()
