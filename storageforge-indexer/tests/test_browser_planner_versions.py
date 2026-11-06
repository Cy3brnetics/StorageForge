"""The planner's Versions panel in a real browser (roadmap 3g, UX-38): save the design on screen as a version, see a comparison in plain
words, restore with the current design kept first, delete, and text from the server shown as text. Needs Playwright and its Chromium,
which CI installs; without them this skips and says so. Its own server and database, set up as test_browser_smoke.py does."""
import json
import tempfile
import threading
import unittest
from pathlib import Path

from storageforge_index import graph, server, users
from storageforge_index.db import Database

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sync_playwright = None
PW = 'a long enough password'
HOST = 'planned-01'
ATLAS = Path(__file__).resolve().parents[1] / 'examples' / 'atlas' / 'blueprint.json'


@unittest.skipUnless(sync_playwright, 'needs playwright (CI has it)')
class PlannerVersions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from werkzeug.serving import make_server
        cls.tmp = tempfile.TemporaryDirectory()
        cls.db = Database(f'sqlite:///{cls.tmp.name}/idx.db')
        conn = cls.db.connect()
        cls.db.migrate(conn)
        users.create(conn, 'admin', PW, 'admin')
        bp = json.loads(ATLAS.read_text())
        bp['metadata']['host'] = HOST                         # a planned host: saved, never scanned
        graph.store_blueprint(conn, bp)
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
        self.page.wait_for_selector('.tabs button')              # the main page: the session is made (wait_for_url would match /login itself)
        self.page.wait_for_load_state('load')
        conn = self.db.connect()
        conn.execute('DELETE FROM design_versions')
        conn.close()
        self.page.goto(f'{self.base}/planner#devices@{HOST}')
        self.page.wait_for_selector('#versions:not([hidden])')
        self.page.wait_for_function('h => DOC.host === h && !!S.host', arg=HOST)

    def open_panel(self):
        self.page.click('#versions')
        self.page.wait_for_selector('dialog.pv[open] #pv-list')
        self.page.wait_for_selector('#pv-count:not(:empty)')

    def confirm(self, button='Restore'):
        self.page.click('dialog[open]:not(.pv) button[type=submit]')
        self.page.wait_for_selector('dialog[open]:not(.pv)', state='detached')

    def other_mode(self):
        return 'LABEL' if self.page.evaluate('S.idMode') == 'UUID' else 'UUID'

    def test_save_compare_restore_and_delete(self):
        before = self.page.evaluate('S.idMode')
        after = self.other_mode()
        self.open_panel()
        self.assertEqual(self.page.inner_text('#pv-empty'), 'No versions yet.')
        self.page.fill('#pv-name', 'first plan')
        self.page.fill('#pv-note', 'as it was')
        self.page.click('#pv-save')
        self.page.wait_for_selector('#pv-list .pv-item')
        item = self.page.inner_text('#pv-list .pv-item')
        for text in ('first plan', 'admin', 'as it was'):
            self.assertIn(text, item)
        self.assertNotIn('web:', item)
        self.assertEqual(self.page.input_value('#pv-name'), '')
        self.assertIn('1 of at most 50', self.page.inner_text('#pv-count'))
        # change the design on screen, then compare: in words, and nothing is saved by looking
        self.page.click('#pv-close')
        self.page.wait_for_selector('dialog[open]', state='detached')
        self.page.evaluate(f'S.idMode = "{after}"; commit()')
        self.open_panel()
        self.page.click('#pv-list .pv-item button[data-act=compare]')
        self.page.wait_for_selector('#pv-result h3')
        shown = self.page.inner_text('#pv-result')
        self.assertIn('“first plan” against the current design', shown)
        self.assertIn('Setting fstab identifiers: identifiers is ' + before + ' in this version and ' + after + ' now', shown)
        self.assertEqual(self.page.evaluate('S.idMode'), after)
        # restore: the design on screen goes back, and the one it replaced is kept first
        self.page.click('#pv-list .pv-item button[data-act=restore]')
        self.page.wait_for_selector('dialog[open]:not(.pv) h2')
        self.assertIn('Restore “first plan”?', self.page.inner_text('dialog[open]:not(.pv) h2'))
        self.assertIn('kept first as an automatic version', self.page.inner_text('dialog[open]:not(.pv)'))
        self.confirm()
        self.page.wait_for_selector('dialog.pv', state='detached')
        self.page.wait_for_function('m => S.idMode === m', arg=before)
        self.assertIn('Restored “first plan”', self.page.inner_text('#sf-toasts'))
        self.open_panel()
        names = self.page.eval_on_selector_all('#pv-list .pv-name', 'ns => ns.map(n => n.textContent)')
        self.assertEqual(names, ['Before restoring first plan', 'first plan'])
        self.assertIn('kept automatically', self.page.inner_text('#pv-list .pv-item'))
        # delete the automatic one
        self.page.click('#pv-list .pv-item[data-id] button[data-act=delete]')
        self.page.wait_for_selector('dialog[open]:not(.pv) h2')
        self.confirm()
        self.page.wait_for_function('() => document.querySelectorAll("#pv-list .pv-item").length === 1')
        self.assertEqual(self.page.inner_text('#pv-list .pv-name'), 'first plan')
        self.assertEqual(self.errors, [])

    def test_a_refusal_from_the_server_is_shown_as_text_and_makes_no_markup(self):
        self.open_panel()
        self.page.fill('#pv-name', '<img src=x onerror="window.pwned=1">')
        self.page.click('#pv-save')
        self.page.wait_for_selector('#pv-err:not([hidden])')
        self.assertIn('control character', self.page.inner_text('#pv-err'))
        self.assertEqual(self.page.locator('dialog.pv img').count(), 0)
        self.assertEqual(self.page.locator('#pv-list .pv-item').count(), 0)
        self.assertIsNone(self.page.evaluate('window.pwned || null'))

    def test_text_that_looks_like_markup_in_a_stored_version_is_shown_as_text(self):
        conn = self.db.connect()
        bp = json.loads(ATLAS.read_text())
        bp['metadata']['host'] = HOST
        conn.execute("""INSERT INTO design_versions (host, name, note, author, auto, body_json, size_bytes, created_at)
                        VALUES (:h, :n, :o, :a, 0, :b, 2, 1700000000)""",
                     {'h': HOST, 'n': '<b id=bold>name</b>', 'o': '<script>window.pwned=1</script>', 'a': '<i>ann</i>', 'b': json.dumps(bp)})
        conn.close()
        self.open_panel()
        self.assertEqual(self.page.inner_text('#pv-list .pv-name'), '<b id=bold>name</b>')
        self.assertEqual(self.page.locator('dialog.pv #bold, dialog.pv i, dialog.pv script').count(), 0)
        self.assertIsNone(self.page.evaluate('window.pwned || null'))
        self.assertEqual(self.errors, [])

    def test_the_panel_is_the_kernels_modal_and_escape_returns_focus_to_the_button(self):
        self.open_panel()
        self.assertEqual(self.page.evaluate('document.querySelector("dialog.pv").getAttribute("aria-labelledby")'), 'pv-title')
        self.assertEqual(self.page.evaluate('document.activeElement.id'), 'pv-name')
        self.page.keyboard.press('Escape')
        self.page.wait_for_selector('dialog[open]', state='detached')
        self.assertEqual(self.page.evaluate('document.activeElement.id'), 'versions')


if __name__ == '__main__':
    unittest.main()
