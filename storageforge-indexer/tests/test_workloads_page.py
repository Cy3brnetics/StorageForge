"""The Workloads page (/workloads): its route and permission, the shell it serves, and that the Proxmox steps carry no 'managed by' warning."""
import re
import tempfile
import unittest
from pathlib import Path

from storageforge_index import changes, server, users, wlmanaged
from storageforge_index.db import Database

PW = 'a very secure password for tests'


class Page(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Database(f'sqlite:///{self.tmp.name}/idx.db')
        self.conn = self.db.connect()
        self.addCleanup(self.conn.close)
        self.db.migrate(self.conn)
        users.create(self.conn, 'root', PW, 'admin')
        self.web = server.create_app(server.App(self.db), 's' * 48)

    def client(self, name, role=None):
        if role:
            users.create(self.conn, name, PW, role)
        c = self.web.test_client()
        self.assertEqual(c.post('/api/login', json={'username': name, 'password': PW}).status_code, 200)
        return c

    def test_an_admin_gets_the_page_and_its_files(self):
        c = self.client('root')
        r = c.get('/workloads')
        self.assertEqual(r.status_code, 200)
        body = r.data.decode()
        self.assertIn('workloads.js', body)
        self.assertIn('role="tree"', body)
        for f in re.findall(r'(?:src|href)="/(workloads\.(?:js|css)|workloadwiz\.js|stepfields\.js|canvas\.js|ui\.js)"', body):
            self.assertEqual(c.get('/' + f).status_code, 200, f)
        self.assertEqual(c.get('/api/workloads').status_code, 200)
        self.assertLess(body.index('stepfields.js'), body.index('workloadwiz.js'))
        self.assertIn('workloadwiz.js', body)
        self.assertEqual(c.get('/stepfields.js').status_code, 200)

    def test_the_page_needs_a_sign_in(self):
        self.assertEqual(self.web.test_client().get('/workloads').status_code, 302)

    def test_a_custom_role_without_workloads_view_is_refused_the_listing(self):
        admin = self.client('root')
        self.assertEqual(admin.post('/api/roles', json={'name': 'hostsonly', 'permissions': ['hosts.view']}).status_code, 200)
        c = self.client('hank', 'hostsonly')
        self.assertEqual(c.get('/workloads').status_code, 200)
        self.assertEqual(c.get('/api/workloads').status_code, 403)

    def test_the_top_bar_names_the_page(self):
        static = Path(server.__file__).parent / 'static'
        self.assertTrue("'/workloads'" in (static / 'chrome.js').read_text())
        self.assertTrue('href="/workloads"' in (static / 'index.html').read_text())


class ProxmoxStepsAreNotWarned(unittest.TestCase):
    """The pve-* steps are Proxmox's own tools: wlmanaged wraps only the steps in its TARGET table, and none of them is a pve step."""

    def test_no_pve_step_is_wrapped_by_the_managed_warning(self):
        for kind in ('pve-action', 'pve-remove', 'pve-vm', 'pve-ct'):
            self.assertNotIn(kind, wlmanaged.TARGET)
            self.assertFalse(getattr(changes.EXTRA[kind]['check'], 'warns_managed', False), kind)

    def test_the_generic_workload_steps_are_still_wrapped(self):
        self.assertTrue(getattr(changes.EXTRA['workload-action']['check'], 'warns_managed', False))


class Index(unittest.TestCase):
    def test_the_main_page_loads_stepfields_before_changes(self):
        html = (Path(server.__file__).parent / 'static' / 'index.html').read_text()
        self.assertLess(html.index('/stepfields.js'), html.index('/changes.js'))


if __name__ == '__main__':
    unittest.main()
