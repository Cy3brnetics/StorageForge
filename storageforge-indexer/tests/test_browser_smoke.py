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

    def test_the_scan_tab_says_it_is_off_and_turns_on_under_the_csp(self):
        self.page.click('#viewmode button[data-mode="scan"]')
        self.page.wait_for_selector('.nscan')
        self.assertIn('Off', self.page.inner_text('.nscan-head'))
        self.assertTrue(self.page.is_hidden('#mapview'))
        self.page.fill('input[aria-label="Networks to scan"]', '10.77.0.0/28')
        self.page.click('.nscan-head button')
        self.page.wait_for_selector('.nscan-head .nscan-chip.on')
        self.assertIn('Scan now', self.page.inner_text('.nscan-ctl'))
        self.page.click('.nscan-head button')       # and back off, for the next test
        self.page.wait_for_selector('.nscan-head:has-text("Off")')
        self.assertEqual(self.errors, [])

    def test_a_scan_result_links_back_to_that_machines_pages(self):
        from storageforge_index import netscan
        conn = self.db.connect()
        ip = conn.scalar("SELECT ip_address FROM hosts WHERE hostname = 'nas'") or '192.168.1.10'
        conn.execute("UPDATE hosts SET ip_address = :i WHERE hostname = 'nas'", {'i': ip})
        netscan.save_settings(conn, {'enabled': True, 'ranges': [f'{ip}/24']}, 'test')
        port = '<ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port></ports>'
        xml = f'<nmaprun><host><status state="up"/><address addr="{ip}" addrtype="ipv4"/>{port}</host><host><status state="up"/><address addr="192.168.1.250" addrtype="ipv4"/>{port}</host></nmaprun>'
        netscan.run(self.db, conn, None, 'test', wait=True, runner=lambda argv: xml)
        netscan.save_settings(conn, {'enabled': False}, 'test')
        conn.close()
        self.page.click('#viewmode button[data-mode="scan"]')
        self.page.wait_for_selector('.nscan-card')
        self.page.click('.nscan-card:has-text("nas") a:has-text("Config")')
        self.page.wait_for_selector('.tabs button[data-tab="rebuild"][aria-selected="true"]')
        self.assertEqual(self.page.input_value('#host'), 'nas')
        self.page.click('#viewmode button[data-mode="scan"]')
        self.page.wait_for_selector('.nscan-card.unknown')
        self.page.click('.nscan-card.unknown a:has-text("Add as a device")')
        self.page.wait_for_selector('input[aria-label="Address"]')
        self.assertEqual(self.page.input_value('input[aria-label="Address"]'), '192.168.1.250')
        self.assertEqual(self.errors, [])

    def test_scan_groups_hosts_by_the_ranges_that_were_scanned(self):              # UX-29
        """Every address went under an assumed /24: two hosts of one /20 came out as two networks, and a range that found nothing was not there at all."""
        from storageforge_index import netscan
        conn = self.db.connect()
        netscan.save_settings(conn, {'enabled': True, 'ranges': ['10.20.0.0/20', '192.168.7.0/25', '10.30.0.0/24']}, 'test')
        up = lambda ip: f'<host><status state="up"/><address addr="{ip}" addrtype="ipv4"/></host>'
        answers = {'10.20.0.0/20': ['10.20.5.9', '10.20.15.1'], '192.168.7.0/25': ['192.168.7.9', '172.16.0.4'], '10.30.0.0/24': []}      # the second one sends back a stray
        netscan.run(self.db, conn, None, 'test', wait=True, runner=lambda argv: '<nmaprun>' + ''.join(up(ip) for ip in answers[argv[-1]]) + '</nmaprun>')
        netscan.save_settings(conn, {'enabled': False}, 'test')
        conn.close()
        self.page.click('#viewmode button[data-mode="scan"]')
        self.page.wait_for_selector('.nscan-net')
        heads = self.page.eval_on_selector_all('.nscan-net h3', 'hs => hs.map((h) => h.textContent)')
        self.assertEqual(heads, ['10.20.0.0/20 · 2', '192.168.7.0/25 · 1', '10.30.0.0/24 · 0', 'Outside the scanned ranges · 1'])
        self.assertIn('Nothing answered.', self.page.inner_text('.nscan-net:has(h3:has-text("10.30.0.0/24"))'))
        self.assertEqual(self.errors, [])

    def test_the_management_planner_opens_every_view_and_compiles_under_the_csp(self):
        self.page.goto(self.base + '/manage')
        self.page.wait_for_selector('#mgnav button')
        for view in ('devices', 'changes', 'traffic', 'scanner', 'fleet'):
            self.page.click(f'#mgnav button[data-v="{view}"]')
            self.page.wait_for_timeout(400)
            self.assertEqual(self.errors, [], view)
            self.assertEqual(self.page.locator('#mgview p.bad').count(), 0, view)
        self.page.click('#mgnav button[data-v="compose"]')
        self.page.wait_for_selector('textarea')
        self.page.fill('textarea', '/ip firewall filter add chain=input protocol=tcp dst-port=22 action=accept')
        self.page.select_option('select[aria-label="Show as"]', 'iptables')
        self.page.wait_for_selector('.mg-cols pre:has-text("--dport 22")')
        self.page.fill('textarea', '/nonsense add a=1')
        self.page.wait_for_selector('.mg-cols p.bad')
        self.assertEqual(self.errors, [])

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


    def open_tab(self, tab):
        """The rail button of the tab that is already open hides the panel, so click it only when it is another one."""
        if self.page.evaluate("document.querySelector('.tabs button.on')?.dataset.tab") != tab or self.page.evaluate("document.querySelector('#panel').classList.contains('collapsed')"):
            self.page.click(f'.tabs button[data-tab="{tab}"]')

    # ── the keyboard: UX-40 and UX-41 of the UI audit of 2026-11-04 ─────────────────────────────────────────────────────
    def test_a_slash_types_into_every_kind_of_field_and_the_shortcut_still_works(self):       # UX-40
        """`/` moved focus to the search box from anywhere, so a path lost its first character and a password its tail."""
        searches = []
        self.page.on('request', lambda r: searches.append(r.url) if '/api/search' in r.url else None)
        for tab, sel, typed in (('jobs', '#scanhost', '/mnt/x'), ('keys', '#genname', 'a/b'), ('keys', '#instpw', 'pa/ss'),
                                ('audit', '#pwnew', 'pa/ss'), ('hostlogs', '#hl-q', '/var/log')):
            self.open_tab(tab)
            self.page.wait_for_selector(sel, state='visible')
            self.page.fill(sel, '')
            self.page.focus(sel)
            self.page.keyboard.type(typed)
            self.assertEqual(self.page.input_value(sel), typed, sel)
        self.page.wait_for_timeout(500)                          # the search box debounces: a stolen tail would be sent by now
        self.assertEqual(self.page.input_value('#q'), '')
        self.assertEqual(searches, [])
        self.page.evaluate('document.activeElement.blur()')      # the shortcut itself, with nothing focused
        self.page.keyboard.press('/')
        self.assertEqual(self.page.evaluate('document.activeElement.id'), 'q')
        self.page.evaluate('document.activeElement.blur()')      # and a modifier makes it something else
        self.page.keyboard.press('Control+/')
        self.assertNotEqual(self.page.evaluate('document.activeElement.id'), 'q')
        self.assertEqual(self.errors, [])

    def test_a_password_with_a_slash_can_be_typed_into_the_confirm_dialog(self):               # UX-40
        self.page.evaluate('() => { window.__p = confirmPassword(); window.__p.catch(() => {}); }')
        self.page.wait_for_selector('#reauthpw', state='visible')
        self.page.focus('#reauthpw')
        self.page.keyboard.type('pa/ss')
        self.assertEqual(self.page.input_value('#reauthpw'), 'pa/ss')
        self.page.click('#reauthcancel')

    def test_the_menu_key_in_a_text_field_leaves_the_browsers_own_menu_alone(self):           # UX-41
        self.page.click('#viewmode button[data-mode="tasks"]')
        self.page.click('.tkchip:has-text("Copy with rsync")')
        self.page.wait_for_selector('.tkblist input')
        self.page.evaluate("""() => { for (const i of document.querySelectorAll('#tasksview input[type=text]')) { let n = i; while (n && !n._menu) n = n.parentElement;
                                       if (n) { i.setAttribute('data-probe', '1'); break; } } }""")
        for key in ('Shift+F10', 'ContextMenu'):
            self.page.focus('[data-probe="1"]')
            self.page.keyboard.press(key)
            self.assertEqual(self.page.locator('.ctxmenu').count(), 0, key)
        self.page.focus('.tkblist .tkhead button, .tkblist button')      # on a button of the block, the app's menu is still there
        self.page.keyboard.press('Shift+F10')
        self.page.wait_for_selector('.ctxmenu')
        self.page.keyboard.press('Escape')
        self.page.click('#viewmode button[data-mode="topo"]')

    def test_backslash_leaves_the_panel_alone_under_an_open_dialog(self):                       # UX-41
        was = self.page.evaluate("document.querySelector('#panel').classList.contains('collapsed')")
        self.page.evaluate('() => { window.__p = confirmPassword(); window.__p.catch(() => {}); }')
        self.page.wait_for_selector('#reauthcancel', state='visible')
        self.page.focus('#reauthcancel')
        self.page.keyboard.press('\\')
        self.assertEqual(self.page.evaluate("document.querySelector('#panel').classList.contains('collapsed')"), was)
        self.page.click('#reauthcancel')
        self.page.evaluate('document.activeElement.blur()')      # with the dialog gone it is the shortcut again
        self.page.keyboard.press('\\')
        self.assertNotEqual(self.page.evaluate("document.querySelector('#panel').classList.contains('collapsed')"), was)
        self.page.keyboard.press('\\')

    def test_escape_asks_before_it_throws_away_a_share_that_was_edited(self):                   # UX-41
        share = "{ path: '/srv/photos', name: 'photos', protocol: 'NFSv4.2', clients: '10.0.0.0/24', options: 'rw' }"
        self.page.evaluate(f"openShareWizard({{ host: 'nas', share: {share} }})")
        self.page.wait_for_selector('dialog.swdlg[open]')
        self.page.keyboard.press('Escape')                      # nothing edited: it just closes
        self.page.wait_for_selector('dialog.swdlg', state='detached')
        self.page.evaluate(f"openShareWizard({{ host: 'nas', share: {share} }})")
        self.page.wait_for_selector('dialog.swdlg[open] input[placeholder="photos"]')
        self.page.fill('dialog.swdlg input[placeholder="photos"]', 'photos-renamed')
        self.page.keyboard.press('Escape')
        self.page.wait_for_selector('.swdiscard')               # edited: it asks, and the wizard stays
        self.assertEqual(self.page.locator('dialog.swdlg[open]').count(), 1)
        self.page.click('.swdiscard button:has-text("Keep editing")')
        self.assertEqual(self.page.locator('.swdiscard').count(), 0)
        self.assertEqual(self.page.input_value('dialog.swdlg input[placeholder="photos"]'), 'photos-renamed')
        self.page.keyboard.press('Escape')
        self.page.click('.swdiscard button:has-text("Discard")')
        self.page.wait_for_selector('dialog.swdlg', state='detached')
        self.assertEqual(self.errors, [])


    # ── the chrome: UX-01 and UX-02 ────────────────────────────────────────────────────────────────────────────────────
    IN_VIEW = """(tab) => { const r = document.querySelector('.rail').getBoundingClientRect(), b = document.querySelector(`.tabs button[data-tab="${tab}"]`).getBoundingClientRect();
                          return b.top >= r.top - 1 && b.bottom <= r.bottom + 1; }"""

    def test_the_rail_says_when_more_of_it_is_below_the_fold(self):            # UX-01
        """The rail needs about 1000 px and scrolls with its scrollbar hidden: Security and Logs were out of sight, with nothing to say so."""
        self.page.set_viewport_size({'width': 1366, 'height': 768})
        self.page.wait_for_timeout(300)
        self.assertEqual(self.page.evaluate("document.querySelector('.rail').dataset.more"), 'after')
        self.assertTrue(self.page.is_visible('#railmore'))
        self.assertFalse(self.page.evaluate(self.IN_VIEW, 'audit'))
        for _ in range(8):                                        # the chevron scrolls it, until there is no more
            if not self.page.is_visible('#railmore'):
                break
            self.page.click('#railmore')
            self.page.wait_for_timeout(500)
        self.assertFalse(self.page.is_visible('#railmore'))
        self.assertEqual(self.page.evaluate("document.querySelector('.rail').dataset.more"), 'before')
        self.assertTrue(self.page.evaluate(self.IN_VIEW, 'audit'))
        self.page.set_viewport_size({'width': 1920, 'height': 1200})   # with room for all of it there is nothing to say
        self.page.wait_for_timeout(300)
        self.assertEqual(self.page.evaluate("document.querySelector('.rail').dataset.more"), '')
        self.assertFalse(self.page.is_visible('#railmore'))
        self.assertEqual(self.errors, [])

    def test_a_panel_opened_from_a_link_is_in_view_in_the_rail(self):          # UX-01
        self.page.set_viewport_size({'width': 1366, 'height': 768})
        self.page.goto(self.base + '/search')                      # from another page, as a link from the planner is: on the same page a hash change is not read (UX-08)
        self.page.goto(self.base + '/#tab=audit')
        self.page.wait_for_selector('.tabs button[data-tab="audit"][aria-selected="true"]')
        self.page.wait_for_timeout(400)
        self.assertTrue(self.page.evaluate(self.IN_VIEW, 'audit'))

    def test_the_header_has_no_primary_button_and_export_shows_only_where_it_applies(self):    # UX-02
        for mode, shown in (('topo', True), ('graph', True), ('tasks', False), ('map', False), ('scan', False)):
            self.page.click(f'#viewmode button[data-mode="{mode}"]')
            self.assertEqual(self.page.is_visible('#export'), shown, mode)
        self.assertEqual(self.page.locator('.bar .btn.pri').count(), 0)
        self.page.click('#viewmode button[data-mode="topo"]')


    # ── the planner: UX-18 and UX-32 ───────────────────────────────────────────────────────────────────────────────────
    def test_the_planner_keeps_focus_when_a_field_is_changed(self):             # UX-18
        """Every change re-rendered the whole view: Tab out of an edited field and focus landed on the page, not on the next field."""
        self.page.goto(self.base + '/planner#devices')
        self.page.wait_for_selector('#view .seg[data-act=sel][data-id="nvme0n1p1"]')
        self.page.click('#view .seg[data-act=sel][data-id="nvme0n1p1"]')
        self.page.wait_for_selector('#i-label')
        self.page.focus('#i-label')
        self.page.keyboard.press('Control+A')
        self.page.keyboard.type('boot')
        self.page.keyboard.press('Tab')
        self.page.wait_for_timeout(250)
        self.assertEqual(self.page.evaluate('document.activeElement.id'), 'i-fs')
        self.assertEqual(self.page.input_value('#i-label'), 'boot')               # and the change was kept
        self.page.click('#view .seg[data-act=sel][data-id="nvme0n1p2"]')          # Enter adds a subvolume and keeps the field for the next one
        self.page.wait_for_selector('#i-newsv')
        self.page.focus('#i-newsv')
        self.page.keyboard.type('docker')
        self.page.keyboard.press('Enter')
        self.page.wait_for_timeout(250)
        self.assertEqual(self.page.evaluate('document.activeElement.id'), 'i-newsv')
        self.assertIn('@docker', self.page.inner_text('#view'))
        self.page.focus('#nav button[data-view="mounts"]')                       # changing view from the keyboard keeps focus on the nav
        self.page.keyboard.press('Enter')
        self.page.wait_for_timeout(250)
        self.assertEqual(self.page.evaluate('document.activeElement.dataset.view'), 'mounts')

    def test_offsite_is_what_the_design_says_and_not_what_a_name_looks_like(self):   # UX-32
        self.page.goto(self.base + '/planner#protection')
        self.page.wait_for_selector('#view table')
        got = self.page.evaluate("""() => [copies321({sync:{state:'Active Sync',target:'rsync → office-nas'},backup:{target:null,offsite:false}}),
                                           copies321({sync:{state:'Active Sync',target:'rsync → x',offsite:true},backup:{target:null,offsite:false}}),
                                           copies321({sync:{state:'None'},backup:{target:'restic → B2',offsite:true}}),
                                           copies321({sync:{state:'Active Sync',target:'rsync → nas-02',offsite:false},backup:{target:null,offsite:false}})]""")
        self.assertEqual([(r['c'], r['off'], r['unstated']) for r in got], [(2, False, True), (2, True, False), (2, True, False), (2, False, False)])
        example = self.page.evaluate("""() => { const r = S.protection.find(x => x.name === 'tank/media'); return [r.sync.offsite, protStatus(r).why.join(' ')]; }""")
        self.assertTrue(example[0])                                              # the example says where its replica is, and the reason no longer calls a replica a backup
        self.assertIn('the replica is a copy, not a backup', example[1])
        self.page.evaluate("() => { S.protection.find(x => x.name === 'tank/media').sync = {state: 'Active Sync', target: 'rsync → office-nas'}; render(); }")
        row = self.page.locator('#view tbody tr', has_text='tank/media').first.inner_text()
        self.assertIn('offsite not stated', row)                                 # the same row with a name that sounds remote and nothing said
        self.assertNotIn('offsite ✓', row)


    # ── what is cut, and copy that fits the screen: UX-13, UX-14 and UX-09 ──────────────────────────────────────────────
    def test_needs_attention_says_what_it_leaves_out(self):                     # UX-13
        """It listed twelve broken things and said nothing about the rest, with the Health block above it counting all of them."""
        self.page.click('#viewmode button[data-mode="graph"]')
        self.page.click('#graphsub button[data-sub="structure"]')                 # Files, the default, owns the panel with its own overview
        base = self.page.evaluate("S.nodes.filter((n) => n.health === 'broken' && n.kind !== 'Host').length")
        self.page.evaluate("""() => { for (let i = 0; i < 15; i++) S.nodes.push({id: `x:${i}`, kind: 'Share', label: `broken ${i}`, health: 'broken', props: {}}); renderSummary(); }""")
        rows = lambda: self.page.locator('#summary ul.nbrs li').count()
        self.assertEqual(rows(), 12)
        self.assertEqual(self.page.inner_text('#needsmore'), f'+{base + 15 - 12} more')
        self.assertEqual(self.page.get_attribute('#needsmore', 'aria-expanded'), 'false')
        self.page.click('#needsmore')
        self.assertEqual(rows(), base + 15)                                       # a way to see them
        self.assertEqual(self.page.inner_text('#needsmore'), 'Show fewer')
        self.assertEqual(self.page.get_attribute('#needsmore', 'aria-expanded'), 'true')
        self.assertEqual(self.page.evaluate('document.activeElement.id'), 'needsmore')        # and the keyboard stays where it was
        self.page.keyboard.press('Enter')
        self.assertEqual(rows(), 12)
        self.page.evaluate("() => { S.nodes.splice(S.nodes.length - 15, 15); renderSummary(); }")
        if base <= 12:                                                            # nothing was left out, so nothing is said
            self.assertEqual(self.page.locator('#needsmore').count(), 0)
        self.assertEqual(self.errors, [])

    def test_the_maps_lists_say_what_they_leave_out(self):                     # UX-13
        import json
        changes = [{'host': 'nas', 'taken_at': 1700000000 + i * 60, 'first': False, 'added': [f'h:nas:svc{i}'], 'removed': [], 'changed': []} for i in range(23)]
        cover = {'coverage': [{'host': 'nas', 'workload': f'w{i}', 'mount': f'/m{i}', 'hold': False, 'decoy': False} for i in range(23)],
                 'warnings': [{'address': f'10.0.0.{i}', 'why': ['a rule']} for i in range(12)]}
        compare = {'missing': [{'host': 'nas', 'kind': 'port', 'what': str(8000 + i)} for i in range(33)], 'different': [], 'extra': [], 'unknown': [], 'there': []}
        answer = lambda body: (lambda route: route.fulfill(body=json.dumps(body), content_type='application/json'))
        self.page.route('**/api/map/snapshots', answer({'changes': changes}))
        self.page.route('**/api/map/coverage', answer(cover))
        self.page.route('**/api/map/designs', answer({'designs': [{'id': 7, 'name': 'wanted'}]}))
        self.page.route('**/api/map/designs/7/compare', answer(compare))
        self.page.click('#viewmode button[data-mode="map"]')
        self.page.wait_for_selector('#mpchanges [data-more="changes"]')
        self.page.wait_for_selector('#mpcover [data-more="warn"]')
        count = lambda box: self.page.locator(f'{box} p').count()
        self.assertEqual((count('#mpchanges'), self.page.inner_text('#mpchanges [data-more="changes"]')), (20, '+3 more'))
        self.assertEqual((count('#mpcover'), self.page.inner_text('#mpcover [data-more="cover"]'), self.page.inner_text('#mpcover [data-more="warn"]')), (30, '+3 more', '+2 more'))
        self.page.click('#mpchanges [data-more="changes"]')
        self.page.wait_for_selector('#mpchanges [data-more="changes"]:has-text("Show fewer")')
        self.assertEqual(self.page.evaluate('document.activeElement.dataset.more'), 'changes')
        self.assertEqual(self.page.inner_text('#mpchanges [data-more="changes"]'), 'Show fewer')
        self.page.click('#mpcover [data-more="cover"]')
        self.page.click('#mpcover [data-more="warn"]')
        self.assertEqual(count('#mpcover'), 35)
        self.page.click('#mpcover [data-more="cover"]')                           # and the same button puts them away again
        self.assertEqual(count('#mpcover'), 32)
        self.page.click('#mpdesigns button:has-text("Compare")')                   # the comparison counts all 33 and used to show 30 without saying so
        self.page.wait_for_selector('#mpdesigns >> text=Missing: 33')
        shown = lambda: self.page.locator('#mpdesigns p', has_text='nas: port').count()
        self.assertEqual(shown(), 30)
        self.page.click('#mpdesigns button:has-text("+3 more")')
        self.assertEqual(shown(), 33)
        self.assertEqual(self.errors, [])

    def test_details_says_what_it_is_for_in_every_view(self):                  # UX-14
        """Map, Tasks and Scan kept the graph's instructions and counted nodes of a graph that was not on screen."""
        hints = {}
        for mode in ('topo', 'graph', 'tasks', 'map', 'scan'):
            self.page.click(f'#viewmode button[data-mode="{mode}"]')
            if mode == 'graph':
                self.page.click('#graphsub button[data-sub="structure"]')           # Files, the default, owns the panel with its own overview
            hints[mode] = self.page.text_content('#detailshint')
            summary = self.page.text_content('#summary')
            if mode in ('tasks', 'map', 'scan'):
                self.assertNotIn('Health', summary, mode)
                self.assertNotIn('Double-click', hints[mode], mode)
                self.assertIn('Topology and Graph', hints[mode], mode)
        self.assertEqual(len(set(hints.values())), 5, hints)                      # one hint for each
        self.assertIn('Double-click', hints['graph'])
        self.page.click('#viewmode button[data-mode="graph"]')
        self.assertIn('Health', self.page.text_content('#summary'))
        node = self.page.evaluate("() => { const n = S.nodes[0]; select(n.id); return [n.id, n.label]; }")
        self.page.click('#viewmode button[data-mode="map"]')
        self.page.click('#viewmode button[data-mode="graph"]')                    # a node picked in Graph is still picked, and its details with it
        self.assertIn(node[1], self.page.text_content('#summary'))
        self.assertEqual(self.errors, [])

    def test_the_map_names_its_presets_and_its_layers_apart(self):             # UX-14
        """A preset and a layer were both called Storage, in one unlabelled row."""
        self.page.click('#viewmode button[data-mode="map"]')
        self.page.wait_for_selector('.mpmodes')
        modes = self.page.eval_on_selector_all('.mpmodes button', 'bs => bs.map((b) => b.textContent)')
        layers = self.page.eval_on_selector_all('.mplayers label', 'ls => ls.map((l) => l.textContent.trim())')
        self.assertIn('Storage only', modes)
        self.assertNotIn('Storage', modes)
        self.assertEqual(layers[0], 'Storage')
        self.assertEqual(self.page.eval_on_selector_all('.mpbar .mpcap', 'cs => cs.map((c) => c.textContent)'), ['Look at', 'Layers'])
        self.assertEqual(self.page.get_attribute('.mplayers', 'aria-label'), 'Layers')
        self.page.click('.mpmodes button:has-text("Storage only")')
        self.page.wait_for_selector('.mpmodes button[aria-pressed="true"]:has-text("Storage only")')
        self.page.click('.mplayers label:has-text("Network") input')                # a layer picked by hand means no preset describes the map any more
        self.assertEqual(self.page.eval_on_selector_all('.mpmodes button[aria-pressed="true"]', 'bs => bs.map((b) => b.textContent)'), ['Custom'])
        self.assertEqual(self.errors, [])
        self.page.click('#viewmode button[data-mode="topo"]')

    def test_compose_says_what_its_button_will_do(self):                       # UX-14
        """It said Report for both, though a Linux host's rules become steps in Changes and only a device is reported on."""
        import json

        def fleet(route):
            real = route.fetch().json()
            real['machines'].append(dict(real['machines'][0], name='edge-fw', kind='device', platform='routeros', label='MikroTik RouterOS', target='routeros'))
            route.fulfill(body=json.dumps(real), content_type='application/json')
        self.page.route('**/api/fleet', fleet)
        self.page.goto(self.base + '/manage')
        self.page.click('#mgnav button[data-v="compose"]')
        self.page.wait_for_selector('select[aria-label="Machine"]')
        label = lambda: self.page.inner_text('#mgview .mg-row button.pri')
        self.assertEqual(label(), 'Stage in Changes')
        self.page.select_option('select[aria-label="Machine"]', 'edge-fw')
        self.assertEqual(label(), 'Check')
        self.page.select_option('select[aria-label="Machine"]', 'nas')
        self.assertEqual(label(), 'Stage in Changes')
        self.assertEqual(self.errors, [])

    def test_the_security_banner_always_says_security_and_shows_its_detail(self):    # UX-09
        """The secure state read 'Nothing wrong found' with no 'Security:' in front, and the detail was a tooltip no keyboard or finger could reach."""
        import json
        self.page.wait_for_selector('#threatbanner:not([hidden])', timeout=8000)
        self.assertTrue(self.page.inner_text('#threatbanner').startswith('Security: '), self.page.inner_text('#threatbanner'))
        self.assertIn('measured in the last day', self.page.inner_text('#threatbanner .threat-detail'))     # the real detail, on the page
        posture = {'state': 'secure', 'banner': 'All 1 host(s) measured in the last day, and nothing wrong found.'}
        self.page.route('**/api/security/posture', lambda route: route.fulfill(body=json.dumps(posture), content_type='application/json'))
        for state, label in (('secure', 'Security: nothing wrong found'), ('warning', 'Security: needs a look'), ('critical', 'Security: incident'), ('unknown', 'Security: not known')):
            posture.update(state=state, banner=f'the detail for {state}')
            self.page.evaluate('threatBanner()')
            self.page.wait_for_selector(f'#threatbanner b:text-is({json.dumps(label)})')
            self.assertEqual(self.page.inner_text('#threatbanner .threat-detail'), f'the detail for {state}')
            self.assertTrue(self.page.is_visible('#threatbanner .threat-detail'))
            self.assertIn(f'sec-{state}', self.page.get_attribute('#threatbanner', 'class'))
        self.assertEqual(self.errors, [])


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

