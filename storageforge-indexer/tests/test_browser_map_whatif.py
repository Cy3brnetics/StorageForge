"""The map's what-if in plain words, its zoom controls and its legend, in a real browser under the CSP (roadmap A4 phase 4, UX-27, UX-26).
Needs Playwright and its Chromium, like test_browser_smoke.py, whose seed this repeats in small. Waits are on selectors: the CSP blocks
wait_for_function with a string."""
import json
import tempfile
import threading
import time
import unittest

from storageforge_index import firewall, infragraph, scheduler, security, server, users
from storageforge_index.db import Database

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sync_playwright = None
PW = 'a long enough password'


@unittest.skipUnless(sync_playwright, 'needs playwright (CI has it)')
class MapWhatIfBrowser(unittest.TestCase):
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
        net = {'interfaces': [{'name': 'eth0', 'kind': 'ethernet', 'state': 'up', 'mac': '52:54:00:00:00:01', 'addresses': [{'ip': '192.168.1.10', 'prefix': 24}]}],
               'routes': [{'dst': '192.168.1.0/24', 'via': None, 'dev': 'eth0', 'family': 4}, {'dst': 'default', 'via': '192.168.1.1', 'dev': 'eth0', 'family': 4}], 'gateways': ['192.168.1.1'],
               'dns': {'nameservers': []}, 'neighbours': [], 'listeners': [{'proto': 'tcp', 'addr': '0.0.0.0', 'port': 8000, 'scope': 'any'}], 'unreadable': []}
        conn.execute('INSERT INTO host_network (host_id, data_json, scan_id, updated_at) VALUES (:h, :d, 1, 1)', {'h': hid, 'd': json.dumps(net)})
        security._save_measurement(conn, 'nas', 'infra', int(time.time()), 'test', {'firewall': firewall.model({'tools': []}), 'listeners': net['listeners'], 'storage_clients': [], 'libvirt': [], 'incus': [], 'lxc': [], 'proxmox': [],
                                                                                  'podman_rootless': [], 'access': {'wireguard': None, 'tailscale': None, 'proxy_routes': [], 'units': []}})
        conn.execute("INSERT INTO graph_nodes (node_id, kind, label, host, updated_at) VALUES ('host:nas', 'Host', 'nas', 'nas', 1)")
        infragraph.rebuild(conn, 'nas')
        _ = scheduler
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
        self.page.wait_for_load_state('load')
        self.page.click('#viewmode button[data-mode="map"]')
        self.page.wait_for_selector('#mpsvg g.k-listener')

    def block_the_listener(self):
        self.page.click('#mpsvg g.k-listener')
        self.page.click('#mpdetail button:has-text("Block it from everyone")')
        self.page.wait_for_selector('#mpwhatif .mpsay-list li')

    def test_the_what_if_is_sentences_first_and_the_codes_are_behind_details(self):
        self.block_the_listener()
        first = self.page.inner_text('#mpwhatif .mpsay-list li:first-child')
        self.assertTrue(first.startswith(('Danger: ', 'Careful: ', 'Note: ', 'Fine: ')), first)
        self.assertIn('port 8000/tcp goes from', self.page.inner_text('#mpwhatif .mpsay-list'))
        self.assertIn('so nothing else can reach it', self.page.inner_text('#mpwhatif .mpsay-list'))
        self.assertFalse(self.page.is_visible('#mpwhatif details.mpdetails p'))                    # the technical lines wait behind Details
        self.page.click('#mpwhatif details.mpdetails summary')
        self.page.wait_for_selector('#mpwhatif details.mpdetails p')
        self.assertIn('8000/tcp:', self.page.inner_text('#mpwhatif details.mpdetails'))
        self.assertIn('Per configuration', self.page.inner_text('#mpwhatif details.mpdetails'))
        self.assertEqual(self.errors, [])

    def test_the_sentences_and_details_are_reached_and_opened_from_the_keyboard(self):
        self.block_the_listener()
        self.page.focus('#mpwhatif .mpsay')
        self.assertTrue(self.page.evaluate("() => document.activeElement.classList.contains('mpsay')"))
        self.page.focus('#mpwhatif details.mpdetails summary')
        self.page.keyboard.press('Enter')
        self.page.wait_for_selector('#mpwhatif details.mpdetails[open]')
        self.page.keyboard.press('Enter')
        self.page.wait_for_selector('#mpwhatif details.mpdetails:not([open])')
        self.assertEqual(self.errors, [])

    def test_the_answer_is_announced_politely(self):
        self.block_the_listener()
        self.page.wait_for_selector('.sf-live:has-text("What this would do")', state='attached')
        self.assertEqual(self.page.get_attribute('.sf-live', 'aria-live'), 'polite')
        self.assertIn('the worst is', self.page.text_content('.sf-live'))

    def test_a_removed_service_says_what_stops_answering(self):
        self.page.evaluate("""() => { MP.draft.push({ type: 'workload-remove', host: 'nas', params: { runtime: 'docker', name: 'web' } }); mapWhatIf(); }""")
        self.page.wait_for_selector('#mpwhatif .mpsay-list li')
        self.assertIn('if web is removed from nas', self.page.inner_text('#mpwhatif .mpsay-list'))
        self.assertIn('nas: workload-remove', self.page.inner_text('#mpwhatif'))               # the staged step keeps its name, with its plain title beside it
        self.page.click('#mpwhatif button:has-text("Forget it")')

    def test_zoom_controls_work_by_button_and_by_key(self):
        shown = lambda: self.page.inner_text('#mpzoom')
        self.page.click('#mpfit')
        fitted = shown()
        self.page.click('.mptools button[aria-label^="Zoom in"]')
        self.assertNotEqual(shown(), fitted)
        self.page.click('.mptools button[aria-label^="Zoom out"]')
        self.page.click('.mptools button[aria-label^="Reset the zoom"]')
        self.assertEqual(shown(), '100%')
        self.page.focus('#mpsvg g.k-listener')
        self.page.keyboard.press('-')
        self.assertNotEqual(shown(), '100%')
        self.page.keyboard.press('0')
        self.assertEqual(shown(), '100%')
        self.page.keyboard.press('f')
        self.assertEqual(shown(), fitted)
        self.assertEqual(self.errors, [])

    def test_the_legend_says_what_the_colours_and_lines_mean_and_a_port_says_who_reaches_it(self):
        legend = self.page.inner_text('#mapview .mplegend')
        for words in ('Any address', 'Private networks', 'Blocked', 'Dashed outline or line: inferred', 'Dotted outline: staged', 'Struck-through name: would be removed', 'Thick line: the path you asked about'):
            self.assertIn(words, legend)
        self.assertEqual(self.page.text_content('#mpsvg g.k-listener .mptag'), 'LAN')                # the second cue, beside the colour
        self.assertIn('Private networks', self.page.get_attribute('#mpsvg g.k-listener', 'aria-label'))
        self.page.click('#mapview .mplegend summary')
        self.assertFalse(self.page.is_visible('#mapview .mplegend ul'))
        self.assertEqual(self.errors, [])


if __name__ == '__main__':
    unittest.main()
