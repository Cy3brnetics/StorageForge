"""The StorageForge network's page in a real browser (roadmap section 2.1): make the network, add members, see what the readings
confirm, rotate a key, remove a member, save the plan, and the findings. Needs playwright and its chromium."""
import json
import tempfile
import threading
import time
import unittest

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sync_playwright = None

from storageforge_index import server, sfnet, sfnetwork, users
from storageforge_index.db import Database
from test_sfnet import key

PW = 'correct horse battery staple'
HOSTS = (('ctl', '10.42.0.2'), ('nas', '10.42.0.10'), ('pi', '10.42.0.20'))


@unittest.skipUnless(sync_playwright, 'needs playwright (CI has it)')
class BrowserSfnet(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from werkzeug.serving import make_server
        cls.tmp = tempfile.TemporaryDirectory()
        cls.db = Database(f'sqlite:///{cls.tmp.name}/idx.db')
        conn = cls.db.connect()
        cls.db.migrate(conn)
        users.create(conn, 'admin', PW, 'admin')
        users.create(conn, 'viewer', PW, 'viewer')
        for name, address in HOSTS:
            conn.execute(f"""INSERT INTO hosts (hostname, ssh_host, ip_address, ssh_user, inventory_json, last_scanned_at)
                             VALUES (:h, :a, :a, 'scan', '{{}}', {cls.db.ts(':t')})""", {'h': name, 'a': address, 't': 1600000000})
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
        self.conn = self.db.connect()
        self.addCleanup(self.conn.close)
        self.conn.execute("DELETE FROM settings WHERE key = 'sfnet'")
        self.conn.execute("DELETE FROM security_measurements WHERE kind = 'infra'")
        self.errors = []

    def sign_in(self, who='admin'):
        self.page = self.browser.new_page()
        self.addCleanup(self.page.close)
        self.page.set_default_timeout(30000)
        self.page.on('pageerror', lambda e: self.errors.append(str(e)))
        self.page.on('console', lambda m: self.errors.append(m.text) if 'Content Security Policy' in m.text else None)
        self.page.goto(self.base + '/login')
        self.page.fill('input[type=text], input[name=username], #username', who)
        self.page.fill('input[type=password]', PW)
        self.page.press('input[type=password]', 'Enter')
        self.page.wait_for_url(self.base + '/**')
        self.page.wait_for_selector('.tabs button')
        self.page.wait_for_selector('html[data-route-ready]', state='attached')
        self.page.click('#tabbtn-infra')
        self.page.click('#infrabox .seg button:has-text("StorageForge network")')
        self.page.wait_for_selector('#sfn-summary, #sfn-none')

    def read(self, host, own, peers=None, waiting=None):
        iface = {'name': 'sf0', 'public_key': key(own), 'listen_port': 51903, 'peers': [{'public_key': key(k), 'allowed_ips': a} for k, a in (peers or {}).items()]}
        if waiting:
            iface['next_public_key'] = key(waiting)
        self.conn.execute("DELETE FROM security_measurements WHERE host = :h AND kind = 'infra'", {'h': host})
        self.conn.execute("INSERT INTO security_measurements (host, kind, measured_at, via, data_json) VALUES (:h, 'infra', :t, 'controller', :d)",
                          {'h': host, 't': int(time.time()), 'd': json.dumps({'access': {'wireguard': [iface]}})})

    def settled(self):
        """ctl, nas and pi as members with keys 1, 2 and 3 and every peer in place."""
        sfnetwork.create(self.conn, 'test')
        for i, (host, _) in enumerate(HOSTS, 1):
            sfnetwork.join(self.conn, host, 'test')
            self.read(host, i)
        sfnetwork.observe(self.conn)
        a = {1: ['10.203.0.1/32'], 2: ['10.203.0.2/32'], 3: ['10.203.0.3/32']}
        for i, (host, _) in enumerate(HOSTS, 1):
            self.read(host, i, {k: v for k, v in a.items() if k != i})

    def row(self, host):
        return self.page.locator(f'#infrabox table tbody tr:has([data-member="{host}"])')

    def reload(self):
        self.page.click('#infrabox .seg button:has-text("StorageForge network")')
        self.page.wait_for_selector('#sfn-summary, #sfn-none')

    def test_from_nothing_the_network_is_made_members_are_added_and_the_plan_is_saved(self):
        self.sign_in()
        self.assertIn('There is no StorageForge network yet', self.page.inner_text('#sfn-none'))
        self.page.click('button:has-text("Make the network")')
        self.page.wait_for_selector('#sfn-summary')
        self.assertIn('Range 10.203.0.0/20 · UDP port 51903 · mesh · interface sf0 · 0 members', self.page.inner_text('#sfn-summary'))
        self.assertEqual(self.page.locator('#sfn-host option').all_inner_texts(), ['ctl', 'nas', 'pi'])
        self.page.select_option('#sfn-host', 'nas')
        self.page.click('#sfn-add button:has-text("Add")')
        self.row('nas').wait_for()
        self.assertIn('10.203.0.1', self.row('nas').inner_text())
        self.assertIn('No reading yet', self.row('nas').inner_text())
        self.assertIn('10.42.0.10', self.row('nas').inner_text(), 'called where scans reach it')
        self.assertEqual(self.page.locator('#sfn-host option').all_inner_texts(), ['ctl', 'pi'])
        self.page.select_option('#sfn-host', 'pi')
        self.page.check('#sfn-nat')
        self.page.click('#sfn-add button:has-text("Add")')
        self.row('pi').wait_for()
        self.assertIn('calls the others', self.row('pi').inner_text())
        self.page.click('button:has-text("Save the plan")')
        self.page.wait_for_selector('#sfn-plan-out button:has-text("Open it in Changes")')
        self.assertIn('with 2 steps', self.page.inner_text('#sfn-plan-out'))
        self.page.click('#sfn-plan-out button:has-text("Open it in Changes")')
        self.page.wait_for_selector('#tab-changes:not([hidden])')
        self.assertTrue(self.page.is_visible('#tab-changes'))
        made = sfnetwork.load(self.conn)
        self.assertEqual([(m['host'], m['endpoint'], m['state']) for m in made['members']], [('nas', '10.42.0.10', 'pending'), ('pi', None, 'pending')])
        self.assertEqual(self.errors, [])

    def test_members_show_what_the_readings_confirm_and_a_key_is_rotated_and_taken_back(self):
        self.settled()
        self.sign_in()
        for host in ('ctl', 'nas', 'pi'):
            text = self.row(host).inner_text()
            self.assertIn('Confirmed', text)
            self.assertIn('2 confirmed by key', text)
        self.assertEqual(self.row('nas').locator('.st-ok').first.evaluate('e => getComputedStyle(e, "::before").content'), '"✓ "', 'a state has a sign, not a colour alone')
        self.assertIn(key(2)[:12], self.row('nas').inner_text())
        self.assertEqual(self.row('nas').locator('code').get_attribute('title'), key(2))
        self.assertIn('Nothing is wrong that the readings show', self.page.inner_text('#sfn-findings'))
        self.page.click('button:has-text("Save the plan")')
        self.page.wait_for_selector('#sfn-plan-out .st-ok')
        self.assertIn('nothing to plan', self.page.inner_text('#sfn-plan-out'))

        self.row('nas').locator('button:has-text("Rotate key")').click()
        self.page.wait_for_selector('dialog[open]')
        self.assertIn('Rotate the key of nas', self.page.inner_text('dialog[open]'))
        self.page.click('dialog[open] button:has-text("Rotate")')
        self.row('nas').locator('button:has-text("Take the rotation back")').wait_for()
        self.assertIn('Rotation: the next plan makes a second key on the host', self.row('nas').inner_text())
        self.assertEqual(sfnet.member(sfnetwork.load(self.conn), 'nas')['rotation'], 'asked')
        # the host made its second key and a reading brought the public half
        self.read('nas', 2, {1: ['10.203.0.1/32'], 3: ['10.203.0.3/32']}, waiting=22)
        self.reload()
        self.assertIn('the next plan tells its peers the new key (waiting for ctl, pi)', self.row('nas').inner_text())
        self.row('nas').locator('button:has-text("Take the rotation back")').click()
        self.row('nas').locator('button:has-text("Rotate key")').wait_for()
        self.assertEqual(sfnet.member(sfnetwork.load(self.conn), 'nas')['next_public_key'], None)
        self.assertEqual(self.errors, [])

    def test_a_changed_key_and_a_peer_nobody_asked_for_are_findings_and_a_member_is_removed(self):
        self.settled()
        self.read('nas', 99, {1: ['10.203.0.1/32'], 3: ['10.203.0.3/32']})
        self.read('pi', 3, {1: ['10.203.0.1/32'], 2: ['10.203.0.2/32'], 77: ['0.0.0.0/0']})
        self.sign_in()
        found = self.page.locator('#sfn-findings li')
        self.assertEqual(found.count(), 2)
        self.assertEqual(found.nth(0).get_attribute('data-level'), 'crit', 'the critical one is first')
        self.assertIn('nas shows a key that is not the one on record', found.nth(0).inner_text())
        self.assertIn('pi has 1 peer nobody asked for', found.nth(1).inner_text())
        self.assertIn('A different key', self.row('nas').inner_text())
        self.assertEqual(self.row('nas').locator('button:has-text("Rotate key")').count(), 0, 'a key that changed on its own is not rotated from here')
        self.assertIn(key(2)[:12], self.row('nas').inner_text(), 'the key shown is the one on record')
        self.assertNotIn(key(99)[:12], self.page.inner_text('#infrabox'))

        self.row('nas').locator('button:has-text("Remove")').click()
        self.page.wait_for_selector('dialog[open]')
        self.page.click('dialog[open] button:has-text("Remove")')
        self.page.wait_for_selector('#infrabox table tbody tr:has-text("Removed")')
        self.assertIn('Removed', self.row('nas').inner_text())
        self.assertEqual(self.row('nas').locator('button').count(), 0)
        self.assertIn('nas was removed and its interface is still up', self.page.inner_text('#sfn-findings'))
        self.assertEqual(sfnet.member(sfnetwork.load(self.conn), 'nas')['state'], 'revoked')
        self.assertEqual(self.errors, [])

    def test_the_controller_is_said_to_run_on_a_member_and_every_control_has_a_name(self):
        self.settled()
        self.sign_in()
        self.assertIn('not started with a link', self.page.inner_text('#sfn-controller'))
        self.page.select_option('#sfn-on', 'ctl')
        self.page.click('button:has-text("The controller runs on this member")')
        self.page.wait_for_selector('#sfn-controller button:has-text("It does not run there")')
        self.assertIn('The controller runs on ctl', self.page.inner_text('#sfn-controller'))
        self.assertIn('(the controller runs here)', self.row('ctl').inner_text())
        self.assertEqual(sfnetwork.load(self.conn)['controller'], 'ctl')
        # every field has a label or a name, every section a heading, and the whole view works from the keyboard
        unnamed = self.page.evaluate("""() => [...document.querySelectorAll('#infrabox input, #infrabox select, #infrabox button')].filter((e) =>
            !(e.labels && e.labels.length) && !e.getAttribute('aria-label') && !e.textContent.trim()).map((e) => e.outerHTML)""")
        self.assertEqual(unnamed, [])
        self.assertEqual(self.page.evaluate("() => [...document.querySelectorAll('#infrabox section')].filter((s) => !document.getElementById(s.getAttribute('aria-labelledby'))).length"), 0)
        self.row('ctl').locator('button:has-text("Rotate key")').focus()
        self.page.keyboard.press('Tab')
        self.assertEqual(self.page.evaluate('() => document.activeElement.textContent'), 'Remove')
        self.page.keyboard.press('Enter')
        self.page.wait_for_selector('dialog[open]')
        self.page.keyboard.press('Escape')
        self.page.wait_for_selector('dialog[open]', state='detached')
        self.assertEqual(self.page.evaluate('() => document.activeElement.textContent'), 'Remove', 'focus comes back to where it was')
        self.assertEqual(sfnet.member(sfnetwork.load(self.conn), 'ctl')['state'], 'active', 'and Escape removed nothing')
        self.assertEqual(self.page.evaluate("() => [...document.querySelectorAll('#infrabox th')].map((e) => e.textContent)"),
                         ['Member', 'Address', 'State', 'Public key', 'Peers', 'Called at', 'Actions'])
        self.assertEqual(self.errors, [])

    def test_an_account_that_may_only_look_sees_the_members_and_no_way_to_change_them(self):
        self.settled()
        self.sign_in('viewer')
        self.assertIn('Confirmed', self.row('nas').inner_text())
        for label in ('Rotate key', 'Remove', 'Save the plan', 'Add', 'The controller runs on this member'):
            self.assertEqual(self.page.locator(f'#infrabox button:text-is("{label}")').count(), 0, label)
        self.assertEqual(self.page.locator('#sfn-add').count(), 0)
        self.assertEqual(self.errors, [])


if __name__ == '__main__':
    unittest.main()
