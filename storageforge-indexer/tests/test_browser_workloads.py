"""The Workloads page in a real browser: the tree of a fixture fleet (a Docker host with a stack, a libvirt host, a Proxmox VE node), folding, the
filter, the keyboard, an action from the panel through its check to a saved plan, typed confirmation of a destructive step, typing in a review that
keeps re-checking, and the create wizard on a Proxmox node. Nothing is applied: the page only saves plans. Needs Playwright and its Chromium."""
import json
import tempfile
import threading
import time
import unittest

from storageforge_index import pvenode, security, server, users
from storageforge_index.db import Database

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sync_playwright = None
PW = 'a long enough password'
NODE = pvenode.parse_node([
    's\tlocal\tdir\tactive\t98497780\t12345678',
    's\tlocal-lvm\tlvmthin\tactive\t365768704\t0',
    't\tlocal\tiso,vztmpl,backup',
    't\tlocal-lvm\timages,rootdir',
    'i\tlocal:iso/debian-13.iso\t786432000',
    'v\tlocal:vztmpl/debian-13-standard_13.0-1_amd64.tar.zst\t126000000'])
DISK = {'target': 'vda', 'device': 'disk', 'bus': 'virtio', 'format': 'qcow2', 'source': '/var/lib/libvirt/images/x.qcow2'}


@unittest.skipUnless(sync_playwright, 'needs playwright (CI has it)')
class BrowserWorkloads(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from werkzeug.serving import make_server
        cls.tmp = tempfile.TemporaryDirectory()
        cls.db = Database(f'sqlite:///{cls.tmp.name}/idx.db')
        conn = cls.db.connect()
        cls.db.migrate(conn)
        users.create(conn, 'admin', PW, 'admin')
        now = int(time.time())
        for name in ('dock', 'kvm', 'pve'):
            conn.execute(f"""INSERT INTO hosts (hostname, ssh_host, ssh_user, inventory_json, last_scanned_at)
                             VALUES (:n, :n, 'scan', '{{}}', {cls.db.ts(':t')})""", {'n': name, 't': now})
        hid = conn.scalar("SELECT host_id FROM hosts WHERE hostname = 'dock'")
        cs = [{'id': 'a', 'name': 'wiki-db-1', 'image': 'postgres:16', 'state': 'running', 'labels': {'com.docker.compose.project': 'wiki'}, 'mounts': []},
              {'id': 'b', 'name': 'wiki-web-1', 'image': 'nginx:1.27', 'state': 'running', 'labels': {'com.docker.compose.project': 'wiki'}, 'mounts': []}]
        conn.execute("INSERT INTO docker_hosts (host_id, engine, access, root_dir, containers_json, volumes_json, compose_json, scan_id, updated_at) "
                     "VALUES (:h, 'docker', 'direct', '/var/lib/docker', :c, '[]', '[]', NULL, :t)", {'h': hid, 'c': json.dumps(cs), 't': now})
        security._save_measurement(conn, 'kvm', 'infra', now, 'test', {'tools': ['virsh'], 'libvirt': [
            {'name': 'db-vm', 'state': 'running', 'vcpus': 2, 'memory_mib': 4096, 'disks': [DISK], 'nics': [], 'graphics': [], 'snapshots': []},
            {'name': 'test-vm', 'state': 'shut off', 'vcpus': 1, 'memory_mib': 1024, 'disks': [], 'nics': [], 'graphics': [], 'snapshots': []}]})
        security._save_measurement(conn, 'pve', 'infra', now, 'test', {'tools': ['qm', 'pct', 'lxc-ls', 'pvesm'], 'proxmox_node': NODE, 'proxmox': [
            {'kind': 'qemu', 'vmid': 101, 'name': 'web', 'state': 'running', 'memory_mib': 2048, 'cores': 2, 'disks': [], 'nics': []},
            {'kind': 'lxc', 'vmid': 200, 'name': 'dns', 'state': 'stopped', 'memory_mib': 512, 'cores': 1, 'disks': [], 'nics': [], 'unprivileged': True}],
            'lxc': [{'name': '200', 'state': 'stopped'}]})
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
        self.page = self.browser.new_page(viewport={'width': 1400, 'height': 900})
        self.addCleanup(self.page.close)
        self.errors = []
        self.page.on('pageerror', lambda e: self.errors.append(str(e)))
        self.page.goto(self.base + '/login')
        self.page.fill('input[type=text], input[name=username], #username', 'admin')
        self.page.fill('input[type=password]', PW)
        self.page.press('input[type=password]', 'Enter')
        self.page.wait_for_selector('.tabs button')
        self.page.goto(self.base + '/workloads')
        self.page.wait_for_selector('.wl-node')

    def tearDown(self):
        self.assertEqual(self.errors, [])

    def node(self, id):
        return self.page.locator(f'.wl-node[data-id="{id}"]')

    def open_panel(self, id):
        self.node(id).click()
        self.page.wait_for_selector(f'.wl-node[data-id="{id}"][aria-selected="true"]')

    def act(self, label):
        self.page.click(f'#wl-panel button:text-is("{label}")')
        self.page.wait_for_selector('dialog.wlwiz[open]')

    def ready(self):
        self.page.wait_for_selector('.wlsave:not([disabled])', timeout=5000)

    def plans(self):
        return self.page.evaluate("""async () => {
            const list = (await (await fetch('/api/changes')).json()).plans;
            return Promise.all(list.map(async (p) => (await fetch('/api/changes/' + p.id)).json()));
        }""")

    def test_the_tree_folds_filters_and_moves_by_keyboard(self):
        hosts = self.page.locator('.wl-node.k-host')
        self.assertEqual(hosts.count(), 3)
        self.assertEqual(self.page.locator('.wl-node[data-id^="rt:pve:"]').count(), 1)       # one proxmox branch; the guests read as lxc too are not a second
        self.assertEqual(self.page.locator('.wl-node[data-id="rt:pve:proxmox"]').count(), 1)
        self.assertEqual(self.page.locator('.wl-node[data-id="wl:pve:proxmox:web"]').count(), 1)
        self.assertEqual(self.page.locator('.wl-node[data-id="wl:kvm:libvirt:db-vm"]').count(), 1)
        self.node('host:kvm').locator('[data-fold]').click()
        self.assertEqual(self.page.locator('.wl-node[data-id^="wl:kvm:"]').count(), 0)
        self.node('host:kvm').locator('[data-fold]').click()
        self.assertEqual(self.page.locator('.wl-node[data-id^="wl:kvm:"]').count(), 2)
        self.page.fill('#wl-q', 'db')
        self.assertTrue(self.node('wl:dock:docker:wiki-db-1').evaluate('n => !n.classList.contains("dim")'))
        self.assertTrue(self.node('wl:dock:docker:wiki-web-1').evaluate('n => n.classList.contains("dim")'))
        self.assertTrue(self.node('wl:pve:proxmox:web').evaluate('n => n.classList.contains("dim")'))
        self.assertTrue(self.node('wl:kvm:libvirt:db-vm').evaluate('n => !n.classList.contains("dim")'))
        self.page.fill('#wl-q', '')
        self.page.focus('.wl-node[data-id="fleet"]')
        for _ in range(4):                                  # fleet, dock, docker, the wiki stack, wiki-db-1
            self.page.keyboard.press('ArrowDown')
        self.assertEqual(self.page.evaluate('document.activeElement.dataset.id'), 'wl:dock:docker:wiki-db-1')
        self.page.keyboard.press('Enter')
        self.page.wait_for_selector('#wl-panel h2:text-is("wiki-db-1")')

    def test_stop_is_checked_and_saved_as_a_plan_and_again_without_a_clash(self):
        self.open_panel('wl:kvm:libvirt:db-vm')
        ids = []
        for _ in range(2):                                  # the same action twice in a row: the second name would clash, and retries
            self.act('Stop')
            self.ready()
            self.page.click('.wlsave')
            self.page.wait_for_selector('.wlopen')
            ids.append(self.page.locator('.wlopen').get_attribute('href'))
            self.page.click('dialog.wlwiz button:text-is("Close")')
        self.assertEqual(len(set(ids)), 2, ids)
        mine = [p for p in self.plans() if any(t['type'] == 'workload-action' for t in p['tasks'])]
        self.assertEqual(len(mine), 2, mine)
        self.assertTrue(all(len(p['tasks']) == 1 and p['tasks'][0]['params']['name'] == 'db-vm' for p in mine))
        self.assertEqual(len({p['name'] for p in mine}), 2)

    def test_typing_in_a_review_keeps_its_focus_while_the_check_reruns(self):
        for panel, button, field in (('wl:kvm:libvirt:db-vm', 'Snapshots…', 'Snapshot'), ('wl:pve:proxmox:web', 'Snapshot', 'Snapshot name (snapshot only)')):
            self.open_panel(panel)
            self.act(button)
            self.page.wait_for_selector('dialog.wlwiz input[aria-label="Plan name"]')
            box = self.page.locator(f'dialog.wlwiz label.field:has(> span:text-is("{field} (optional)")) input, dialog.wlwiz label.field:has(> span:text-is("{field}")) input').first
            box.click()
            self.page.keyboard.type('ab')
            self.page.wait_for_timeout(700)                 # longer than the 300 ms wait and the check
            self.page.keyboard.type('cd')
            self.assertEqual(box.input_value(), 'abcd')
            self.assertTrue(box.evaluate('n => n === document.activeElement'))
            name = self.page.locator('dialog.wlwiz input[aria-label="Plan name"]')
            name.click()
            self.page.keyboard.press('End')
            self.page.keyboard.type('xy')
            self.page.wait_for_timeout(700)
            self.page.keyboard.type('zw')
            self.assertTrue(name.input_value().endswith('xyzw'))
            self.assertTrue(name.evaluate('n => n === document.activeElement'))
            self.page.keyboard.press('Escape')
            self.page.wait_for_selector('dialog.wlwiz', state='detached')

    def test_a_destructive_action_needs_its_name_typed(self):
        self.open_panel('wl:pve:proxmox:dns')
        self.act('Remove…')
        self.assertIn('destructive', self.page.inner_text('dialog.wlwiz'))
        box = self.page.locator('dialog.wlwiz input[aria-label="Type its name again to confirm"]')
        self.assertTrue(self.page.locator('.wlsave').is_disabled())
        box.fill('dn')
        self.page.wait_for_timeout(600)
        self.assertTrue(self.page.locator('.wlsave').is_disabled())
        box.fill('dns')
        self.ready()
        self.assertTrue(self.page.locator('.wlsave').is_enabled())

    def test_a_failed_save_does_not_keep_save_disabled_after_the_name_changes(self):
        self.open_panel('wl:kvm:libvirt:db-vm')
        self.act('Stop')
        self.ready()
        self.page.route('**/api/changes', lambda r: r.fulfill(status=400, json={'error': 'refused for the test'}) if r.request.method == 'POST' else r.continue_())
        self.page.click('.wlsave')
        self.page.wait_for_selector('dialog.wlwiz .st-failed:has-text("refused for the test")')
        self.assertTrue(self.page.locator('.wlsave').is_disabled())
        self.page.unroute('**/api/changes')
        self.page.locator('dialog.wlwiz input[aria-label="Plan name"]').fill('another name')
        self.ready()

    def test_the_wizard_on_a_proxmox_node_makes_a_container_plan(self):
        self.open_panel('host:pve')
        self.page.click('#wl-panel button:text-is("+ New")')
        self.page.wait_for_selector('dialog.wlwiz .wlwiz-kind')
        self.assertEqual(sorted(self.page.locator('dialog.wlwiz .wlwiz-kind').evaluate_all('xs => xs.map(x => x.dataset.kind)')), ['pve-ct', 'pve-vm'])
        self.page.click('.wlwiz-kind[data-kind="pve-ct"] input')
        self.page.click('dialog.wlwiz button:text-is("Next")')
        field = lambda label, tag: self.page.locator(f'dialog.wlwiz label.field:has(> span:text-is("{label}")) {tag}').first
        field('Hostname', 'input').fill('web-02')
        template = field('Template (storage:vztmpl/file, or a name to download)', 'select')
        self.assertEqual(template.evaluate('n => n.tagName'), 'SELECT')
        self.assertIn('Another template…', template.evaluate('n => [...n.options].map(o => o.text)'))
        template.select_option(index=1)
        typed = self.page.locator('dialog.wlwiz label.field:has(> span:text-is("Template (storage:vztmpl/file, or a name to download)")) input')
        self.assertTrue(typed.is_hidden())
        template.select_option(label='Another template…')
        self.assertTrue(typed.is_visible())
        typed.fill('alpine-3.22-default_20250617_amd64.tar.xz')
        storage = field('Storage for the root disk', 'select')
        self.assertEqual(storage.evaluate('n => [...n.options].map(o => o.value)'), ['', 'local-lvm'])      # only the storage that holds containers' disks
        storage.select_option('local-lvm')
        for _ in range(6):
            if self.page.locator('.wlsave').count():
                break
            self.page.click('dialog.wlwiz button:text-is("Next")')
        self.ready()
        self.page.click('.wlsave')
        self.page.wait_for_selector('.wlopen')
        made = [p for p in self.plans() if any(t['type'] == 'pve-ct' for t in p['tasks'])]
        self.assertEqual(len(made), 1)
        self.assertEqual(made[0]['tasks'][0]['params']['hostname'], 'web-02')
        self.assertEqual(made[0]['tasks'][0]['params']['template'], 'alpine-3.22-default_20250617_amd64.tar.xz')
