"""The VM panel of a libvirt host in a real browser (docs/vms.md): a VM's disks and snapshots from its reading, the buttons that
stage a plan step with its fields filled in, the networks and pools under it, and the copy form. Values from the host reach
the page as text. The server is real, with a database holding a reading of two libvirt hosts. Needs Playwright and its
Chromium, which CI installs; without them this skips and says so."""
import tempfile
import threading
import time
import unittest

from storageforge_index import security, server, users
from storageforge_index.db import Database

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sync_playwright = None
PW = 'a long enough password'
HOSTILE = '<img src=x onerror=alert(1)>'


@unittest.skipUnless(sync_playwright, 'needs playwright (CI has it)')
class BrowserVms(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from werkzeug.serving import make_server
        cls.tmp = tempfile.TemporaryDirectory()
        cls.db = Database(f'sqlite:///{cls.tmp.name}/idx.db')
        conn = cls.db.connect()
        cls.db.migrate(conn)
        users.create(conn, 'admin', PW, 'admin')
        for name in ('kvm1', 'kvm2'):
            conn.execute(f"""INSERT INTO hosts (hostname, ssh_host, ssh_user, inventory_json, last_scanned_at)
                             VALUES ('{name}', '{name}', 'scan', '{{}}', {cls.db.ts(':t')})""", {'t': 1600000000})
        web = {'name': 'web', 'state': 'running', 'autostart': True, 'vcpus': '2', 'memory_mib': 2048, 'firmware': 'uefi', 'agent': 'connected',
               'disks': [{'device': 'disk', 'target': 'vda', 'bus': 'virtio', 'format': 'qcow2', 'source': '/var/lib/libvirt/images/web.qcow2'}],
               'nics': [{'type': 'network', 'source': 'default', 'mac': '52:54:00:aa:bb:cc', 'model': 'virtio'}],
               'snapshots': [{'name': 'before-upgrade', 'location': 'external', 'state': 'disk-snapshot', 'created': 1794190000, 'current': True,
                              'description': HOSTILE}]}
        now = int(time.time())
        security._save_measurement(conn, 'kvm1', 'infra', now, 'test', {
            'tools': ['virsh'], 'libvirt': [web],
            'libvirt_networks': [{'name': 'default', 'mode': 'nat', 'address': '192.168.122.1', 'netmask': '255.255.255.0', 'dhcp': '192.168.122.2-192.168.122.254', 'active': True, 'autostart': True}],
            'libvirt_pools': [{'name': 'default', 'type': 'dir', 'path': '/var/lib/libvirt/images', 'active': True, 'autostart': True, 'capacity': 100 * 2**30, 'available': 60 * 2**30}]})
        security._save_measurement(conn, 'kvm2', 'infra', now, 'test', {
            'tools': ['virsh'], 'libvirt': [], 'libvirt_networks': [{'name': 'default', 'mode': 'nat'}],
            'libvirt_pools': [{'name': 'vms', 'type': 'dir', 'path': '/srv/vms'}]})
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
        self.page.set_default_timeout(30000)
        self.errors = []
        self.page.on('pageerror', lambda e: self.errors.append(str(e)))
        self.page.on('dialog', lambda d: (self.errors.append(f'dialog: {d.message}'), d.dismiss()))
        self.page.goto(self.base + '/login')
        self.page.fill('input[type=text], input[name=username], #username', 'admin')
        self.page.fill('input[type=password]', PW)
        self.page.press('input[type=password]', 'Enter')
        self.page.wait_for_url(self.base + '/**')
        self.page.wait_for_selector('.tabs button')
        self.page.wait_for_load_state('load')
        self.page.wait_for_selector('html[data-route-ready]', state='attached')
        self.page.click('.tabs button[data-tab="infra"]')
        self.page.wait_for_selector('#infrabox .seg button')
        self.page.click('#infrabox .seg button:has-text("Workloads")')
        self.page.wait_for_selector('#infrabox button.mono:has-text("web")')

    def test_the_panel_shows_the_vm_and_stages_its_steps(self):
        self.page.click('#infrabox button.mono:has-text("web")')
        panel = self.page.locator('[role=region][aria-label="VM web"]')
        panel.wait_for()
        body = panel.inner_text()
        for want in ('guest agent answers', '/var/lib/libvirt/images/web.qcow2', 'before-upgrade (current)', 'disk-only', 'Force off', 'Copy to another host…'):
            self.assertIn(want, body)
        self.assertNotIn('Start\n', body)                        # it runs: no Start
        panel.locator('button:has-text("Revert…")').click()
        form = self.page.locator('.stageform')
        form.wait_for()
        self.assertIn('Revert a VM to a snapshot', form.inner_text())
        self.assertEqual(form.locator('input').nth(0).input_value(), 'web')
        self.assertEqual(form.locator('input').nth(1).input_value(), 'before-upgrade')
        self.assertEqual(self.errors, [])

    def test_networks_and_pools_under_the_host(self):
        box = self.page.inner_text('#infrabox')
        for want in ('libvirt networks', '192.168.122.1/24', '192.168.122.2-192.168.122.254', 'Storage pools', '/var/lib/libvirt/images', '60.00 GiB of 100.00 GiB'):
            self.assertIn(want, box)
        self.page.locator('#infrabox button:has-text("Change…")').first.click()
        form = self.page.locator('.stageform')
        form.wait_for()
        self.assertIn('Define or change a libvirt network', form.inner_text())
        values = form.locator('input[type=text]').evaluate_all('xs => xs.map((x) => x.value)')
        self.assertIn('192.168.122.1/24', values)
        self.assertIn('192.168.122.2-192.168.122.254', values)
        self.assertEqual(self.errors, [])

    def test_the_copy_form_previews_two_steps(self):
        self.page.click('#infrabox button.mono:has-text("web")')
        self.page.click('button:has-text("Copy to another host…")')
        form = self.page.locator('.stageform:has-text("Copy VM web")')
        form.wait_for()
        form.locator('select').first.select_option('kvm2')
        self.assertIn('/srv/vms', form.locator('select').nth(1).inner_text())
        self.assertTrue(form.locator('input[type=checkbox]').first.is_checked())           # it runs: live
        form.locator('button:has-text("Preview")').click()
        self.page.wait_for_selector('.stageform li:has-text("Send VM web to kvm2")')
        self.assertIn('Define VM web on /srv/vms', form.inner_text())
        self.assertEqual(self.errors, [])


if __name__ == '__main__':
    unittest.main()
