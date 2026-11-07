"""UI phase 5, "Polish and scale", in a real browser: the Ctrl+K palette, per-user preferences, the first-run checklist, colour never alone and
the tablet header. Needs Playwright and its Chromium, which CI installs; without them this skips and says so. The set-up is a small copy of
test_browser_smoke.py's (that file's class carries its whole suite, so subclassing it would run every test of it again)."""
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


def serve(with_host):
    from werkzeug.serving import make_server
    tmp = tempfile.TemporaryDirectory()
    db = Database(f'sqlite:///{tmp.name}/idx.db')
    conn = db.connect()
    db.migrate(conn)
    users.create(conn, 'admin', PW, 'admin')
    users.create(conn, 'viewer', PW, 'viewer')
    if with_host:
        conn.execute(f"""INSERT INTO hosts (hostname, ssh_host, ssh_user, inventory_json, last_scanned_at)
                         VALUES ('nas', 'nas', 'scan', '{{}}', {db.ts(':t')})""", {'t': 1600000000})
    conn.close()
    http = make_server('127.0.0.1', 0, server.create_app(server.App(db), 's' * 48), threaded=True)
    threading.Thread(target=http.serve_forever, daemon=True).start()
    return tmp, http, f'http://127.0.0.1:{http.server_port}'


@unittest.skipUnless(sync_playwright, 'needs playwright (CI has it)')
class BrowserPolish(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.empty_tmp, cls.empty_http, cls.empty = serve(False)
        cls.full_tmp, cls.full_http, cls.full = serve(True)
        cls.pw = sync_playwright().start()
        cls.browser = cls.pw.chromium.launch()

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls.pw.stop()
        for http, tmp in ((cls.empty_http, cls.empty_tmp), (cls.full_http, cls.full_tmp)):
            http.shutdown()
            tmp.cleanup()

    def open(self, base, user='admin', size=None):
        self.page = self.browser.new_page(**({'viewport': size} if size else {}))
        self.addCleanup(self.page.close)
        self.errors = []
        self.page.on('pageerror', lambda e: self.errors.append(str(e)))
        self.login(base, user)
        return self.page

    def login(self, base, user):
        self.page.goto(base + '/login')
        self.page.fill('#username', user)
        self.page.fill('input[type=password]', PW)
        self.page.press('input[type=password]', 'Enter')
        self.page.wait_for_selector('.tabs button')
        self.page.wait_for_load_state('load')
        self.page.wait_for_selector('#host option[value="nas"], #firstrun:not([hidden]), .tnote:not([hidden])', state='attached')

    def palette(self):
        self.page.keyboard.press('Control+k')
        self.page.wait_for_selector('dialog.sf-palette[open] input[role=combobox]')

    def labels(self):
        return self.page.eval_on_selector_all('dialog.sf-palette [role=option] .sf-pal-label', 'els => els.map(e => e.textContent)')

    # ── Ctrl+K ───────────────────────────────────────────────────────────────────────────────────────────────────────
    def test_the_palette_filters_runs_and_gives_focus_back(self):
        page = self.open(self.full)
        page.wait_for_selector('#sesslen')                                  # the account's permissions are known once the session box shows
        page.focus('#q')
        self.palette()                                                       # Ctrl+K works from inside a text field
        self.assertEqual(page.get_attribute('dialog.sf-palette input', 'aria-expanded'), 'true')
        self.assertTrue(page.eval_on_selector('dialog.sf-palette input', 'e => e === document.activeElement'))
        self.assertGreater(len(self.labels()), 10)
        page.keyboard.type('sched')
        self.assertEqual(self.labels()[0], 'Go to Schedule')                 # a plain substring, case folded
        self.assertEqual(page.get_attribute('dialog.sf-palette [role=option][aria-selected=true]', 'id'), page.get_attribute('dialog.sf-palette input', 'aria-activedescendant'))
        page.keyboard.press('Enter')
        page.wait_for_selector('.tabs button[data-tab="schedule"][aria-selected="true"]')
        self.assertIn('/topo/schedule', page.evaluate('location.hash'))      # the router's own form, so Back returns
        page.go_back()
        page.wait_for_selector('.tabs button[data-tab="schedule"][aria-selected="false"]')
        self.assertEqual(self.errors, [])

    def test_the_palette_moves_with_arrows_and_closes_with_escape_to_where_focus_was(self):
        page = self.open(self.full)
        page.wait_for_selector('#sesslen')
        page.focus('#host')
        self.palette()
        first = self.labels()
        page.keyboard.press('ArrowDown')
        self.assertEqual(page.eval_on_selector_all('dialog.sf-palette [role=option]', 'els => els.findIndex(e => e.getAttribute("aria-selected") === "true")'), 1)
        page.keyboard.press('ArrowUp')
        page.keyboard.press('ArrowUp')                                       # from the top it wraps to the bottom
        self.assertEqual(page.eval_on_selector_all('dialog.sf-palette [role=option]', 'els => els.findIndex(e => e.getAttribute("aria-selected") === "true")'), len(first) - 1)
        page.keyboard.type('zzzz-no-such-thing')
        self.assertEqual(self.labels(), [])
        self.assertIn('Nothing matches', page.inner_text('dialog.sf-palette [role=status]'))
        page.keyboard.press('Escape')
        page.wait_for_selector('dialog.sf-palette', state='detached')
        self.assertEqual(page.evaluate('document.activeElement.id'), 'host')
        self.palette()
        page.keyboard.press('Control+k')                                     # the same key closes it again
        page.wait_for_selector('dialog.sf-palette', state='detached')

    def test_the_palette_lists_the_registered_shortcuts_and_the_help_shows_it(self):
        page = self.open(self.full)
        page.wait_for_selector('#sesslen')
        got = {s['id']: s for s in page.evaluate('sfShortcuts()')}
        self.assertIn('palette', got)
        self.assertIn('shortcut-help', got)
        self.assertTrue(got['palette']['label'] and got['palette']['key'] == 'k' and got['palette']['mods'] == 'mod')
        self.palette()
        page.keyboard.type('panel')
        self.assertIn('Show or hide the panel', self.labels())
        self.assertNotIn('Open the command palette', self.labels())          # it is the palette
        page.keyboard.press('Escape')
        page.wait_for_selector('dialog.sf-palette', state='detached')
        page.evaluate('document.activeElement.blur()')
        page.keyboard.press('Shift+?')
        page.wait_for_selector('dialog.sf-dialog[open] .sf-keys-list')
        text = page.inner_text('.sf-keys-list')
        self.assertIn('Ctrl+K', text)
        self.assertIn('Open the command palette', text)

    def test_the_palette_runs_a_shortcut_where_focus_was(self):
        page = self.open(self.full)
        page.wait_for_selector('#sesslen')
        before = page.evaluate("document.querySelector('#panel').classList.contains('collapsed')")
        self.palette()
        page.keyboard.type('show or hide the panel')
        page.keyboard.press('Enter')
        page.wait_for_selector('dialog.sf-palette', state='detached')
        page.wait_for_timeout(150)
        self.assertNotEqual(page.evaluate("document.querySelector('#panel').classList.contains('collapsed')"), before)

    def test_the_palette_offers_only_what_the_account_may_use(self):
        page = self.open(self.full)
        page.wait_for_selector('#sesslen')
        self.palette()
        admin = self.labels()
        for want in ('Go to Logs', 'Go to Keys', 'Go to Security: Firewall', 'Go to Map', 'Preferences', 'Go to Storage planner'):
            self.assertIn(want, admin)
        page.keyboard.press('Escape')
        page.close()
        page = self.open(self.full, user='viewer')
        page.wait_for_selector('#sesslen')
        self.palette()
        viewer = self.labels()
        self.assertIn('Go to Schedule', viewer)
        self.assertNotIn('Go to Logs', viewer)                               # hostlogs.view is not in the viewer role
        self.assertLess(len(viewer), len(admin))

    def test_the_palette_sets_every_label_as_text(self):
        page = self.open(self.full)
        page.wait_for_selector('#sesslen')
        page.evaluate("""() => sfPaletteSource(() => [{ label: '<img src=x onerror=window.__pwned=1>', hint: '<b>x</b>', run() {} }])""")
        self.palette()
        page.keyboard.type('img')
        self.assertEqual(self.labels(), ['<img src=x onerror=window.__pwned=1>'])
        self.assertEqual(page.evaluate('document.querySelectorAll("dialog.sf-palette img, dialog.sf-palette b").length'), 0)
        self.assertIsNone(page.evaluate('window.__pwned || null'))

    # ── preferences ──────────────────────────────────────────────────────────────────────────────────────────────────
    def test_preferences_apply_at_once_are_kept_per_account_and_come_back_on_reload(self):
        page = self.open(self.full)
        page.wait_for_selector('#sesslen')
        self.assertIsNone(page.evaluate('document.documentElement.dataset.theme || null'))
        page.click('#prefs')
        page.wait_for_selector('dialog.sf-prefs[open] fieldset')
        page.check('dialog.sf-prefs input[name="pref-theme"][value="dark"]')
        page.check('dialog.sf-prefs input[name="pref-density"][value="compact"]')
        page.check('dialog.sf-prefs input[name="pref-motion"][value="reduce"]')
        root = lambda: {k: v for k, v in page.evaluate('({...document.documentElement.dataset})').items() if k != 'routeReady'}      # the router's marker is not a preference
        self.assertEqual(root(), {'theme': 'dark', 'density': 'compact', 'motion': 'reduce'})
        self.assertEqual(page.evaluate("getComputedStyle(document.body).fontSize"), '13px')
        self.assertLess(page.evaluate("parseFloat(getComputedStyle(document.querySelector('.brand b')).transitionDuration)"), 0.001)   # nothing animates a person who asked for none
        kept = page.evaluate("JSON.parse(localStorage.getItem('sf.prefs.admin'))")
        self.assertEqual(kept, {'user': 'admin', 'value': {'theme': 'dark', 'density': 'compact', 'motion': 'reduce'}})
        page.keyboard.press('Escape')
        page.wait_for_selector('dialog.sf-prefs', state='detached')
        page.reload()
        page.wait_for_selector('.tabs button')
        self.assertEqual(root(), {'theme': 'dark', 'density': 'compact', 'motion': 'reduce'})
        # another account on the same browser starts from the defaults, and does not inherit these
        page.click('#lock')
        page.wait_for_url(self.full + '/login*')
        self.login(self.full, 'viewer')
        page.wait_for_selector('#sesslen')
        self.assertEqual(root(), {})
        self.assertIsNone(page.evaluate("localStorage.getItem('sf.prefs.viewer')"))
        self.assertEqual(self.errors, [])

    def test_the_theme_really_changes_the_colours_both_ways(self):
        page = self.open(self.full)
        page.wait_for_selector('#sesslen')
        colour = lambda: page.evaluate("getComputedStyle(document.body).backgroundColor")
        page.evaluate("sfPrefsApply({ theme: 'dark', density: 'comfortable', motion: 'system' })")
        dark = colour()
        page.evaluate("sfPrefsApply({ theme: 'light', density: 'comfortable', motion: 'system' })")
        light = colour()
        self.assertNotEqual(dark, light)
        self.assertEqual(light, 'rgb(238, 241, 245)')
        self.assertEqual(dark, 'rgb(13, 16, 21)')

    def test_preferences_open_from_the_palette_and_reset(self):
        page = self.open(self.full)
        page.wait_for_selector('#sesslen')
        self.palette()
        page.keyboard.type('preferences')
        page.keyboard.press('Enter')
        page.wait_for_selector('dialog.sf-prefs[open]')
        page.check('dialog.sf-prefs input[name="pref-theme"][value="light"]')
        page.click('dialog.sf-prefs button:has-text("Reset")')
        self.assertIsNone(page.evaluate('document.documentElement.dataset.theme || null'))
        self.assertIsNone(page.evaluate("localStorage.getItem('sf.prefs.admin')"))       # all defaults: nothing is kept

    def test_the_planner_has_preferences_in_its_user_menu(self):
        page = self.open(self.full)
        page.goto(self.full + '/manage')
        page.wait_for_selector('.sf-user button:has-text("Preferences")')
        page.click('.sf-user button:has-text("Preferences")')
        page.wait_for_selector('dialog.sf-prefs[open]')

    # ── the first-run checklist ──────────────────────────────────────────────────────────────────────────────────────
    def test_an_empty_install_shows_the_checklist_with_real_links_into_panels(self):
        page = self.open(self.empty)
        page.wait_for_selector('#firstrun:not([hidden])')
        links = page.eval_on_selector_all('#firstrun a', 'els => els.map(a => [a.textContent, a.getAttribute("href")])')
        self.assertEqual(links, [['Enrol a host', '#/topo/keys'], ['Run the first scan', '#/topo/jobs'], ['Set up a backup alert', '#/topo/deploy']])
        self.assertEqual(page.eval_on_selector_all('#firstrun .frstate', 'els => els.map(e => e.textContent)'), ['To do'] * 3)
        page.click('#firstrun a:has-text("Set up a backup alert")')
        page.wait_for_selector('.tabs button[data-tab="deploy"][aria-selected="true"]')
        self.assertIn('/topo/deploy', page.evaluate('location.hash'))
        page.click('#firstrun a:has-text("Enrol a host")')
        page.wait_for_selector('.tabs button[data-tab="keys"][aria-selected="true"]')
        self.assertEqual(self.errors, [])

    def test_the_checklist_stays_gone_once_dismissed_for_that_account_only(self):
        page = self.open(self.empty)
        page.wait_for_selector('#firstrun:not([hidden])')
        page.click('#firstrun button:has-text("Dismiss")')
        self.assertTrue(page.is_hidden('#firstrun'))
        page.reload()
        page.wait_for_selector('.tabs button')
        page.wait_for_selector('.tnote:not([hidden])')
        page.wait_for_timeout(400)
        self.assertTrue(page.is_hidden('#firstrun'))
        page.click('#lock')
        page.wait_for_url(self.empty + '/login*')
        self.login(self.empty, 'viewer')
        page.wait_for_selector('#firstrun:not([hidden])')                    # the viewer never dismissed it

    def test_a_step_that_can_be_seen_to_be_done_says_so_and_a_finished_list_goes(self):
        page = self.open(self.empty)
        page.wait_for_selector('#firstrun:not([hidden])')
        shown = page.evaluate("""() => { const card = document.querySelector('#firstrun');
          return [sfFirstRun(card, { user: 'x', steps: [{ label: 'a', detail: 'd', href: '#/topo/keys', done: true }, { label: 'b', detail: 'd', href: '#/topo/jobs', done: false }] }),
                  [...card.querySelectorAll('.frstate')].map((e) => e.textContent),
                  sfFirstRun(card, { user: 'x', steps: [{ label: 'a', detail: 'd', href: '#/topo/keys', done: true }] }), card.hidden]; }""")
        self.assertEqual(shown, [True, ['✓ Done', 'To do'], False, True])

    def test_a_install_with_hosts_has_no_checklist(self):
        page = self.open(self.full)
        page.wait_for_selector('#host option[value="nas"]', state='attached')
        page.wait_for_timeout(400)
        self.assertTrue(page.is_hidden('#firstrun'))

    # ── colour never alone ───────────────────────────────────────────────────────────────────────────────────────────
    def test_each_health_dot_has_a_shape_of_its_own(self):
        page = self.open(self.full)
        page.wait_for_selector('.legend .dot', state='attached')
        looks = page.evaluate("""() => Object.fromEntries(['protected', 'local-only', 'broken', 'unknown'].map((h) => {
          const e = document.querySelector(`.legend .dot.${h}`), cs = getComputedStyle(e);
          return [h, cs.clipPath + '|' + cs.boxShadow.replace(/rgb\\([^)]*\\)/g, 'c') + '|' + cs.borderRadius]; }))""")
        self.assertEqual(len(set(looks.values())), 4, looks)                  # four states, four different looks without the colour

    # ── a tablet ─────────────────────────────────────────────────────────────────────────────────────────────────────
    def overflow(self):
        return self.page.evaluate("""() => {
          const bar = document.querySelector('.bar'), iw = document.documentElement.clientWidth;
          const out = [...bar.querySelectorAll('*')].filter((e) => e.getClientRects().length && e.getBoundingClientRect().right > iw + 0.5).map((e) => e.id || e.className || e.tagName);
          return { page: document.documentElement.scrollWidth - iw, bar: bar.scrollWidth - bar.clientWidth, out };
        }""")

    def test_the_header_does_not_overflow_on_a_tablet_in_any_view(self):
        for width in (700, 820, 1000):
            page = self.open(self.full, size={'width': width, 'height': 1180})
            page.wait_for_selector('#sesslen', state='attached')
            for mode in ('topo', 'graph', 'tasks', 'map', 'scan'):
                page.click(f'#viewmode button[data-mode="{mode}"]')
                page.wait_for_timeout(150)
                self.assertEqual(self.overflow(), {'page': 0, 'bar': 0, 'out': []}, (width, mode))
            self.assertTrue(page.is_visible('#hmore'))
            self.assertTrue(page.is_hidden('#toplanner'))                    # Planner, Manage, Session and Preferences are behind More
            page.click('#hmore')
            self.assertEqual(page.get_attribute('#hmore', 'aria-expanded'), 'true')
            self.assertTrue(page.is_visible('#toplanner') and page.is_visible('#prefs'))
            self.assertEqual(self.overflow(), {'page': 0, 'bar': 0, 'out': []}, (width, 'More open'))
            page.close()

    def test_the_header_keeps_its_controls_in_view_on_a_wide_screen(self):
        page = self.open(self.full, size={'width': 1280, 'height': 800})
        page.wait_for_selector('#sesslen', state='attached')
        self.assertTrue(page.is_hidden('#hmore'))
        self.assertTrue(page.is_visible('#toplanner') and page.is_visible('#prefs') and page.is_visible('#cmdk'))
        self.assertEqual(self.overflow(), {'page': 0, 'bar': 0, 'out': []})

    def test_the_header_with_a_security_chip_does_not_overflow_at_820(self):
        page = self.open(self.full, size={'width': 820, 'height': 1180})
        page.wait_for_selector('#sesslen', state='attached')
        page.evaluate("""() => { const c = document.querySelector('#threatbanner'); c.hidden = false; c.className = 'threat sec-warning';
          c.replaceChildren(Object.assign(document.createElement('b'), { textContent: 'Security: needs a look' }), Object.assign(document.createElement('span'), { className: 'threat-detail', textContent: 'x'.repeat(300) })); }""")
        self.assertEqual(self.overflow(), {'page': 0, 'bar': 0, 'out': []})


if __name__ == '__main__':
    unittest.main()
