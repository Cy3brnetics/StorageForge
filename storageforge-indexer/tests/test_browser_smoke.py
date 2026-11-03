"""Every page and tab in a real browser, with no script errors (EQ-01). Needs Playwright and its Chromium, which CI installs;
without them this skips and says so."""
import tempfile
import threading
import time
import unittest

from storageforge_index import scheduler, server, users
from storageforge_index.db import Database

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sync_playwright = None
PW = 'a long enough password'
TABS = ('details', 'search', 'changes', 'moves', 'schedule', 'deploy', 'docker', 'infra', 'git', 'rebuild', 'cleanup', 'malware', 'access')


@unittest.skipUnless(sync_playwright, 'needs playwright (CI has it)')
class BrowserSmoke(unittest.TestCase):
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
        conn.execute("INSERT INTO git_repos (host_id, path, remotes_json, scan_id) VALUES (:h, '/srv/repo', '[]', 0)", {'h': hid})
        sid = scheduler.create_schedule(conn, {'name': 'nightly', 'host': 'nas', 'cron_expr': '0 3 * * *', 'task_type': 'command', 'task_ref': 'true'}, 'test')[0]['schedule_id']
        scheduler.ingest_report(conn, {'schedule_id': sid, 'exit_code': 0, 'output': 'fine'}, 'test')
        from storageforge_index import security
        import json
        from storageforge_index import firewall, infragraph
        net = {'interfaces': [{'name': 'eth0', 'kind': 'ethernet', 'state': 'up', 'mac': '52:54:00:00:00:01', 'addresses': [{'ip': '192.168.1.10', 'prefix': 24}]}], 'routes': [{'dst': '192.168.1.0/24', 'via': None, 'dev': 'eth0', 'family': 4}, {'dst': 'default', 'via': '192.168.1.1', 'dev': 'eth0', 'family': 4}],
               'gateways': ['192.168.1.1'], 'dns': {'nameservers': []}, 'neighbours': [{'ip': '192.168.1.77', 'mac': 'b8:27:eb:00:00:01', 'dev': 'eth0'}], 'listeners': [{'proto': 'tcp', 'addr': '0.0.0.0', 'port': 8000, 'scope': 'any'}], 'unreadable': []}
        conn.execute('INSERT INTO host_network (host_id, data_json, scan_id, updated_at) VALUES (:h, :d, 1, 1)', {'h': hid, 'd': json.dumps(net)})
        security._save_measurement(conn, 'nas', 'infra', int(time.time()), 'test', {'firewall': firewall.model({'tools': []}), 'listeners': net['listeners'], 'storage_clients': [], 'libvirt': [], 'incus': [], 'lxc': [], 'proxmox': [], 'podman_rootless': [], 'access': {'wireguard': None, 'tailscale': None, 'proxy_routes': [], 'units': []}})
        conn.execute("INSERT INTO graph_nodes (node_id, kind, label, host, updated_at) VALUES ('host:nas', 'Host', 'nas', 'nas', 1)")
        infragraph.rebuild(conn, 'nas')
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

    def test_every_tab_opens_without_a_script_error(self):
        found = self.page.eval_on_selector_all('.tabs button', 'bs => bs.map(b => b.dataset.tab)')
        self.assertGreaterEqual(len(found), len(TABS) - 1, found)
        for tab in found:
            self.page.click(f'.tabs button[data-tab="{tab}"]')
            self.page.wait_for_timeout(250)
            self.assertEqual(self.errors, [], tab)

    def test_the_infrastructure_panel_and_map_really_open_under_the_csp(self):
        self.page.click('.tabs button[data-tab="infra"]')
        self.page.wait_for_selector('#infrabox button')
        for label in ('Exposure', 'Network', 'Firewall', 'Workloads'):
            self.page.click(f'#infrabox .seg button:has-text("{label}")')
            self.page.wait_for_timeout(200)
            self.assertNotIn('Loading', self.page.inner_text('#infrabox'))
            self.assertEqual(self.errors, [], label)
        self.page.click('#viewmode button[data-mode="map"]')
        self.page.wait_for_selector('.mpbar')
        self.page.wait_for_timeout(300)
        self.assertEqual(self.errors, [])
        self.page.click('#viewmode button[data-mode="topo"]')

    def test_the_map_controls_really_work_under_the_csp(self):
        self.page.click('#viewmode button[data-mode="map"]')
        self.page.wait_for_selector('.mpmodes')
        for mode in ('Network', 'Flow', 'Workloads', 'Storage', 'Security', 'Custom'):
            self.page.click(f'.mpmodes button:has-text("{mode}")')
            self.page.wait_for_selector('.mpmodes')
            self.page.wait_for_timeout(200)
            self.assertEqual(self.errors, [], mode)
        self.page.click('#viewmode button[data-mode="topo"]')

    def confirm_password(self):
        self.page.on('dialog', lambda d: d.accept(PW))

    def test_from_the_map_a_step_is_drawn_first_and_then_staged(self):
        self.page.click('#viewmode button[data-mode="map"]')
        self.page.wait_for_selector('#mpsvg g.k-listener')
        self.page.click('#mpsvg g.k-listener')
        self.page.click('#mpdetail button:has-text("Block it from everyone")')
        self.page.wait_for_selector('#mpwhatif h4')
        self.page.wait_for_selector('#mpwhatif >> text=Private networks to Blocked')
        self.page.wait_for_selector('#mpsvg')
        self.page.click('#mpwhatif button:has-text("Stage in Changes")')
        self.page.wait_for_selector('#mpwhatif >> text=The Report on the host comes next')
        self.assertEqual(self.errors, [])
        self.page.click('#viewmode button[data-mode="topo"]')

    def test_the_exports_drawn_in_the_browser_really_download(self):
        self.page.click('#viewmode button[data-mode="map"]')
        self.page.wait_for_selector('#mpsvg g.k-listener')
        for choice, name in (('png', 'storageforge-map.png'), ('drawn', 'storageforge-map.svg')):
            with self.page.expect_download(timeout=15000) as got:
                self.page.select_option('select[aria-label="Export as"]', choice)
            self.assertEqual(got.value.suggested_filename, name)
            with open(got.value.path(), 'rb') as f:
                head = f.read(8)
            self.assertTrue(head.startswith(b'\x89PNG') if choice == 'png' else head.startswith(b'<svg'), head)
        self.assertEqual(self.errors, [])
        self.page.click('#viewmode button[data-mode="topo"]')

    def test_a_path_query_answers_in_the_panel(self):
        self.page.click('#viewmode button[data-mode="map"]')
        self.page.wait_for_selector('#mpreach input')
        inputs = self.page.query_selector_all('#mpreach input')
        inputs[0].fill('192.168.1.20')
        inputs[1].fill('nas')
        inputs[2].fill('8000')
        self.page.click('#mpreach button:has-text("Work it out")')
        self.page.wait_for_selector('#mpreach >> text=Per configuration')
        self.assertEqual(self.errors, [])
        self.page.click('#viewmode button[data-mode="topo"]')

    def test_a_placeholder_says_who_made_it_and_a_design_compares(self):
        self.page.click('#viewmode button[data-mode="map"]')
        self.page.wait_for_selector('.mpmodes')
        self.page.click('.mpbar label:has-text("Devices nearby")')
        self.page.wait_for_selector('#mpsvg g.k-neighbour')
        self.page.click('#mpsvg g.k-neighbour')
        self.page.wait_for_selector('#mpdetail >> text=made by Raspberry Pi')
        self.page.fill('#mpdesigns input', 'smoke')
        self.page.fill('#mpdesigns textarea', '{"hosts": [{"name": "nas", "firewall": [{"action": "allow", "proto": "tcp", "port": "8000"}]}]}')
        self.page.click('#mpdesigns button:has-text("Save design")')
        self.page.wait_for_selector('#mpdesigns b:has-text("smoke")')
        self.page.click('#mpdesigns button:has-text("Compare")')
        self.page.wait_for_selector('#mpdesigns >> text=Missing: 1')
        self.assertEqual(self.errors, [])
        self.page.click('#viewmode button[data-mode="topo"]')

    def test_a_hardware_key_enrolls_and_touches_through_the_browser(self):
        """Chromium's own virtual authenticator, so the browser's API and the server's checks meet. A browser only offers this on HTTPS or localhost."""
        port = self.http.server_port
        base = f'http://localhost:{port}'
        page = self.browser.new_page()
        self.addCleanup(page.close)
        errors = []
        page.on('pageerror', lambda e: errors.append(str(e)))
        cdp = page.context.new_cdp_session(page)
        cdp.send('WebAuthn.enable')
        cdp.send('WebAuthn.addVirtualAuthenticator', {'options': {'protocol': 'ctap2', 'transport': 'usb', 'hasResidentKey': False, 'hasUserVerification': True, 'isUserVerified': True, 'automaticPresenceSimulation': True}})
        page.goto(base + '/login')
        page.fill('input[type=text], input[name=username], #username', 'admin')
        page.fill('input[type=password]', PW)
        page.press('input[type=password]', 'Enter')
        page.wait_for_url(base + '/**')
        page.wait_for_selector('.tabs button')
        self.assertEqual(page.request.post(base + '/api/reauth', data={'password': PW}).status, 200)
        page.click('.tabs button[data-tab="security"]')
        page.wait_for_selector('#sec-subnav button')
        page.click('#sec-subnav button[data-sub="seckeys"]')
        page.wait_for_selector('#sec-content button:has-text("Enroll a key")')
        page.click('#sec-content button:has-text("Enroll a key")')
        page.wait_for_selector('#sec-content button:has-text("Touched")', timeout=15000)
        c = self.db.connect()
        self.assertEqual(c.scalar("SELECT count(*) FROM security_webauthn WHERE username = 'admin'"), 1)
        c.execute("DELETE FROM security_webauthn")
        c.close()
        self.assertEqual(errors, [])

    def test_every_new_security_panel_really_opens_under_the_csp(self):
        self.page.click('.tabs button[data-tab="security"]')
        self.page.wait_for_selector('#sec-subnav button')
        for sub in ('policy', 'playbooks', 'dash', 'timeline', 'seckeys'):
            self.page.click(f'#sec-subnav button[data-sub="{sub}"]')
            self.settled()
            self.page.wait_for_timeout(200)
            self.assertEqual(self.errors, [], sub)

    def a_read_host(self):
        """A host with a reading, for this one test: with it there, the fleet is no longer 'not known', which another test checks."""
        from storageforge_index import security
        c = self.db.connect()
        c.execute(f"""INSERT INTO hosts (hostname, ssh_host, ssh_user, inventory_json, last_scanned_at)
                         VALUES ('read', 'read', 'scan', '{{}}', {self.db.ts(':t')})""", {'t': 1600000000})
        security._save_measurement(c, 'read', 'host', int(time.time()), 'test', {   # a reading, so the panels that wait for one draw all they have
            'host_now': int(time.time()), 'tools': ['nft', 'aide', 'lynis'], 'selinux': 'Enforcing', 'booleans': [{'name': 'samba_export_all_rw', 'value': 'on', 'expected': 'off', 'ok': False}], 'apparmor': {'enabled': True, 'enforce': 3, 'complain': 0},
            'avc': [{'at': 1, 'daemon': 'smbd', 'action': 'read', 'path': '/etc/shadow', 'scontext': 's', 'tcontext': 't', 'storage': True}], 'fcontext': [{'path': '/srv', 'live': 'var_t', 'expected': 'var_t', 'aligned': True}], 'sysctl': {'fs.protected_hardlinks': '0'},
            'aide': {'baseline_at': 1, 'last_action': 'check', 'last_at': 1, 'added': 0, 'removed': 0, 'changed': 0, 'entries': []}, 'lynis': {'at': 1, 'hardening_index': 70, 'warnings': [], 'suggestions': [{'id': 'AUTH-9328', 'text': 'umask', 'detail': ''}]},
            'falco': {'installed': True, 'active': True}, 'sentinel': {'active': True, 'armed': False}, 'holds_zfs': [], 'holds_btrfs': {}, 'zfs_allow': [], 'canaries': {}, 'auditd': {'active': True, 'storageforge_rules': 1}, 'audit_rules': ['-w /etc/fstab -p wa -k sf_config'],
            'snapshots': ['tank/a@1'], 'sessions': [{'at': 1, 'user': 'alice', 'client': '10.0.0.5', 'share': 'hr'}], 'falco_alerts': [], 'quarantined': [], 'chrony': None, 'nts_sources': 0, 'ntp_synced': True, 'fence': True, 'airgap': False, 'umask': '027', 'clock_offset': 0, 'uptime': 100})
        c.close()

        def gone():
            d = self.db.connect()
            d.execute("DELETE FROM security_measurements WHERE host = 'read'")
            d.execute("DELETE FROM hosts WHERE hostname = 'read'")
            d.close()
        self.addCleanup(gone)
        self.page.reload()
        self.page.wait_for_selector('.tabs button')

    def test_the_panels_about_one_host_really_draw_under_the_csp(self):
        self.a_read_host()
        self.page.wait_for_selector('#host option[value="read"]', state='attached')
        self.page.select_option('#host', 'read')
        self.page.click('.tabs button[data-tab="security"]')
        self.page.wait_for_selector('#sec-subnav button')
        for sub in ('overview', 'worm', 'decoys', 'mac', 'firewall', 'behavior', 'integrity', 'compliance', 'policy', 'fencing', 'identity', 'detect', 'playbooks', 'dash', 'timeline', 'seckeys'):
            self.page.click(f'#sec-subnav button[data-sub="{sub}"]')
            self.settled()
            self.page.wait_for_timeout(200)
            self.assertEqual(self.errors, [], sub)
            self.assertFalse(self.page.query_selector('#sec-content p.st-failed'), f'{sub}: {self.page.inner_text("#sec-content")[:300]}')
        self.page.select_option('#host', '')

    def settled(self):       # polled from here: wait_for_function evaluates in the page, which this CSP rightly refuses
        for _ in range(100):
            if 'Loading' not in self.page.inner_text('#sec-content'):
                return
            self.page.wait_for_timeout(100)
        self.fail('the security panel never finished loading')

    def test_the_security_panels_really_open_under_the_csp(self):       # they were onclick= attributes once, which the CSP refuses in silence
        self.page.click('.tabs button[data-tab="security"]')
        self.page.wait_for_selector('#sec-subnav button')
        self.page.wait_for_selector('#sec-content .sec-card')
        self.assertIn('never measured', self.page.inner_text('#sec-content'))
        self.assertIn('Not known', self.page.inner_text('#sec-banner'))
        self.assertNotIn('SECURE', self.page.inner_text('#tab-security'))
        for panel in ('worm', 'firewall', 'overview'):
            self.page.click(f'#sec-subnav button[data-sub="{panel}"]')
            self.page.wait_for_selector(f'#sec-subnav button[data-sub="{panel}"][aria-pressed="true"]')
            self.settled()
        self.page.select_option('#host', 'nas')
        for panel in ('decoys', 'mac', 'behavior', 'integrity', 'compliance', 'worm', 'firewall', 'overview'):
            self.page.click(f'#sec-subnav button[data-sub="{panel}"]')
            self.settled()
            self.assertEqual(self.errors, [], panel)
        self.page.click('#sec-subnav button[data-sub="mac"]')
        self.settled()
        self.assertIn('has not been measured', self.page.inner_text('#sec-content'))

    def running_deploy(self, gid):
        conn = self.db.connect()
        now = int(time.time())
        conn.execute("""INSERT INTO deploy_groups (group_id, kind, ref, mode, title, state, options_json, actor, started_at)
                        VALUES (:g, 'shares', 'nas', 'report', 'shares of nas', 'running', '{}', 'test', :t)""", {'g': gid, 't': now})
        run = conn.scalar("""INSERT INTO deploy_runs (group_id, host, kind, ref, mode, status, actor, started_at, phase, output)
                              VALUES (:g, 'nas', 'shares', 'nas', 'report', 'running', 'test', :t, 0, 'line 1') RETURNING run_id""", {'g': gid, 't': now})
        return conn, run

    def test_a_running_deploy_keeps_its_output_on_screen(self):
        """Each poll built a new card and put the new output in the old one, so the output went away on every other poll."""
        gid = 'a' * 32
        conn, run = self.running_deploy(gid)
        self.addCleanup(conn.close)
        self.page.click('.tabs button[data-tab="deploy"]')
        self.page.wait_for_selector('#deploybox section')
        self.page.evaluate('(g) => openGroup(g)', gid)
        card = self.page.wait_for_selector(f'#dp-run-{run}')
        self.page.evaluate("(c) => { window.seen = []; window.same = c; setInterval(() => { const n = document.querySelector('[id^=dp-run-]'); window.seen.push([n === window.same, Boolean(n.querySelector(':scope > pre.dpout'))]); }, 50); }", card)
        for n in range(2, 5):
            conn.execute('UPDATE deploy_runs SET output = :o WHERE run_id = :r', {'o': ''.join(f'line {i}\n' for i in range(1, n + 1)), 'r': run})
            self.page.wait_for_function('(n) => document.querySelector("#dpgroup pre.dpout").textContent.includes(`line ${n}`)', arg=n, timeout=5000)
        self.assertTrue(all(same and output for same, output in self.page.evaluate('window.seen')))
        self.page.click(f'#dp-run-{run} > summary')                 # closed by hand, it stays closed through polls
        conn.execute('UPDATE deploy_runs SET output = :o WHERE run_id = :r', {'o': 'changed', 'r': run})
        self.page.wait_for_function('() => document.querySelector("#dpgroup pre.dpout").textContent.includes("changed")', timeout=5000)
        self.assertFalse(self.page.evaluate('document.querySelector("[id^=dp-run-]").open'))
        self.page.evaluate('DP.group = null; renderGroup();')
        conn.execute("UPDATE deploy_groups SET state = 'cancelled' WHERE group_id = :g", {'g': gid})
        conn.execute("UPDATE deploy_runs SET status = 'cancelled' WHERE group_id = :g", {'g': gid})

    def test_a_second_click_does_not_start_a_second_deploy(self):
        posts = []

        def answer(route):
            posts.append(route.request.post_data_json)
            self.page.wait_for_timeout(50)
            route.fulfill(status=409, json={'error': 'not this time'})
        self.page.route('**/api/deploy/start', answer)
        self.page.evaluate("startDeploy('shares', 'nas', 'report', 'shares of nas'); startDeploy('shares', 'nas', 'report', 'shares of nas');")
        self.page.wait_for_selector('#dpgroup .st-failed')
        self.assertEqual(len(posts), 1)
        self.assertIn('not this time', self.page.inner_text('#dpgroup'))

    def test_choosing_the_folder_goes_on_to_who_may_use_it(self):
        self.page.click('#viewmode button[data-mode="topo"]')
        self.page.evaluate("openShareWizard({ host: 'nas', path: '/' })")
        self.page.click('.swdlg .fsfoot button:has-text("Share this folder")')
        self.page.wait_for_selector('.swdlg [aria-label="Protocol"]')
        self.assertEqual(self.errors, [])
        self.page.click('.swdlg .swhead button:has-text("Close")')

    def test_the_planner_and_search_pages_load(self):
        for path in ('/planner', '/search'):
            self.page.goto(self.base + path)
            self.page.wait_for_timeout(400)
            self.assertEqual(self.errors, [], path)

    def test_a_long_unscanned_host_says_so(self):            # PF-08
        self.page.wait_for_selector('#host option:nth-child(2)', state='attached')
        self.assertRegex(self.page.inner_text('#host'), r'nas \(not scanned for \d+ days\)')

    def test_the_schedule_panel_shows_a_reported_run(self):  # PF-24
        self.page.click('.tabs button[data-tab="schedule"]')
        self.page.wait_for_selector('.pill:has-text("REPORTED")')
        for gone in ('Run local', 'Allow destructive', 'catchup', 'Host Scan (index host)'):
            self.assertEqual(self.page.locator(f'text={gone}').count(), 0, gone)
        self.assertEqual(self.errors, [])

    def test_git_calls_go_out_as_post(self):                 # SF-29
        self.page.evaluate("""async () => { window.__h = await postJSON('/api/git/history', {host: 'localhost', path: '/x'}).catch(e => e.message); }""")
        self.assertIn('is not a repository found', str(self.page.evaluate('window.__h')))


@unittest.skipUnless(sync_playwright, 'needs playwright (CI has it)')
class MapAtScale(unittest.TestCase):
    """A synthetic 200 hosts and 2,000 workloads. It has to stay usable: the numbers here decide whether the map needs more."""

    def test_a_large_fleet_draws_and_stays_usable(self):
        import json
        import time
        from werkzeug.serving import make_server
        with tempfile.TemporaryDirectory() as tmp:
            db = Database(f'sqlite:///{tmp}/idx.db')
            conn = db.connect()
            db.migrate(conn)
            users.create(conn, 'admin', PW, 'admin')
            now = int(time.time())
            with conn.tx():
                for h in range(200):
                    name = f'host{h:03}'
                    conn.execute(f"""INSERT INTO hosts (hostname, ssh_host, ssh_user, inventory_json, last_scanned_at) VALUES (:n, :n, 'scan', '{{}}', {db.ts(':t')})""", {'n': name, 't': now})
                    conn.execute("INSERT INTO graph_nodes (node_id, kind, label, host, updated_at, layer) VALUES (:i, 'Host', :n, :n, :t, 'storage')", {'i': f'host:{name}', 'n': name, 't': now})
                    nic = f'nic:{name}:eth0'
                    conn.execute("INSERT INTO graph_nodes (node_id, kind, label, host, updated_at, layer, props_json) VALUES (:i, 'NIC', 'eth0', :n, :t, 'network', :p)", {'i': nic, 'n': name, 't': now, 'p': json.dumps({'addresses': [f'10.0.{h // 250}.{h % 250 + 1}/16']})})
                    conn.execute("INSERT INTO graph_edges (src, dst, rel, props_json, built_by) VALUES (:s, :d, 'ATTACHED_TO', '{}', :b)", {'s': nic, 'd': f'host:{name}', 'b': f'infra:{name}'})
                    for w in range(10):
                        wid = f'wl:{name}:docker::c{w}'
                        conn.execute("INSERT INTO graph_nodes (node_id, kind, label, host, updated_at, layer, props_json) VALUES (:i, 'Container', :l, :n, :t, 'workloads', :p)", {'i': wid, 'l': f'c{w}', 'n': name, 't': now, 'p': json.dumps({'runtime': 'docker', 'state': 'running'})})
                        conn.execute("INSERT INTO graph_edges (src, dst, rel, props_json, built_by) VALUES (:s, :d, 'RUNS_ON', '{}', :b)", {'s': wid, 'd': f'host:{name}', 'b': f'infra:{name}'})
            conn.close()
            http = make_server('127.0.0.1', 0, server.create_app(server.App(db), 's' * 48), threaded=True)
            threading.Thread(target=http.serve_forever, daemon=True).start()
            base = f'http://127.0.0.1:{http.server_port}'
            with sync_playwright() as pw:
                browser = pw.chromium.launch()
                page = browser.new_page(viewport={'width': 1500, 'height': 900})
                errors = []
                page.on('pageerror', lambda e: errors.append(str(e)))
                page.goto(base + '/login')
                page.fill('input[type=text], input[name=username], #username', 'admin')
                page.fill('input[type=password]', PW)
                page.press('input[type=password]', 'Enter')
                page.wait_for_url(base + '/**')
                page.wait_for_selector('.tabs button')
                start = time.time()
                page.click('#viewmode button[data-mode="map"]')
                page.wait_for_selector('#mpsvg', timeout=30000)
                drawn = time.time() - start
                start = time.time()
                page.fill('#mpfilter', 'host150')
                page.wait_for_timeout(50)
                filtered = time.time() - start
                self.assertEqual(errors, [])
                self.assertLess(drawn, 15, f'took {drawn:.1f} s to draw')
                self.assertLess(filtered, 8, f'took {filtered:.1f} s to filter')
                browser.close()
            http.shutdown()

