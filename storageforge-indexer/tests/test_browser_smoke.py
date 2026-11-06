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
        self.page.wait_for_load_state('load')                    # the markup is there before the last script has run: a test that asks for a global waits for it

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
        for view in ('devices', 'changes', 'traffic', 'fleet'):
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

    def test_manage_has_no_scanner_stub_and_traffic_points_to_scan(self):             # UX-28
        """A view whose whole content was a link to another page is gone; the one way from here to the scanner is on Traffic, which says it sends nothing."""
        self.page.goto(self.base + '/manage')
        self.page.wait_for_selector('#mgnav button')
        self.assertEqual(self.page.eval_on_selector_all('#mgnav button', 'bs => bs.map((b) => b.textContent)'), ['Fleet', 'Devices', 'Compose', 'Changes', 'Traffic'])
        self.page.click('#mgnav button[data-v="traffic"]')
        self.page.click('#mgview a:has-text("Open Scan")')
        self.page.wait_for_selector('.nscan')
        self.assertTrue(self.page.is_visible('#netscanview'))
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

    def mount_more_list(self, count, **opts):
        """Mounts an sfMoreList of `count` items on the page, the third of them named like markup, and returns the id of its holder."""
        return self.page.evaluate("""([count, opts]) => {
            document.getElementById('t-more')?.remove();
            const names = Array.from({ length: count }, (_, i) => (i === 2 ? '<b>bold</b> <img src=x onerror=window.__pwned=1>' : `item ${i}`));
            const host = document.createElement('div');
            host.id = 't-more';
            host.append(sfMoreList(names, (n) => { const li = document.createElement('li'); li.textContent = n; return li; }, { tag: 'ul', ...opts }));
            document.body.append(host);
            return host.querySelector('ul').id;
        }""", [count, opts])

    def test_a_cut_list_is_a_button_that_shows_the_rest_and_hides_it_again(self):        # UX-13, sfMoreList
        list_id = self.mount_more_list(30, label='findings')
        items = lambda: self.page.locator('#t-more ul li').count()
        button = '#t-more button.sf-more-btn'
        self.assertEqual(items(), 12)                                                  # cut at the default twelve
        self.assertEqual(self.page.inner_text(button), 'Show 18 more')
        self.assertEqual(self.page.evaluate(f"document.querySelector('{button}').tagName + document.querySelector('{button}').type"), 'BUTTONbutton')
        self.assertEqual(self.page.get_attribute(button, 'aria-expanded'), 'false')
        self.assertEqual(self.page.get_attribute(button, 'aria-controls'), list_id)
        self.page.click(button)
        self.assertEqual(items(), 30)
        self.assertEqual(self.page.inner_text(button), 'Show fewer')
        self.assertEqual(self.page.get_attribute(button, 'aria-expanded'), 'true')
        self.page.wait_for_selector('.sf-live:has-text("Showing all 30 findings")')       # said aloud, not only shown
        self.assertEqual(self.page.evaluate("document.activeElement.className"), 'sf-btn ghost sf-more-btn')     # focus did not move
        self.page.click(button)
        self.assertEqual(items(), 12)
        self.assertEqual(self.page.inner_text(button), 'Show 18 more')
        self.assertEqual(self.page.get_attribute(button, 'aria-expanded'), 'false')
        self.page.wait_for_selector('.sf-live:has-text("Showing the first 12 of 30 findings")')
        self.assertEqual(self.errors, [])

    def test_a_cut_list_opens_and_closes_from_the_keyboard(self):                        # UX-13, sfMoreList
        self.mount_more_list(30)
        items = lambda: self.page.locator('#t-more ul li').count()
        button = '#t-more button.sf-more-btn'
        self.page.focus(button)
        self.page.keyboard.press('Enter')
        self.assertEqual((items(), self.page.get_attribute(button, 'aria-expanded')), (30, 'true'))
        self.assertTrue(self.page.evaluate(f"document.activeElement === document.querySelector('{button}')"))
        self.page.keyboard.press('Enter')
        self.assertEqual((items(), self.page.get_attribute(button, 'aria-expanded')), (12, 'false'))
        self.page.keyboard.press('Space')
        self.assertEqual((items(), self.page.get_attribute(button, 'aria-expanded')), (30, 'true'))
        self.assertEqual(self.page.inner_text(button), 'Show fewer')
        self.page.keyboard.press('Space')
        self.assertEqual((items(), self.page.inner_text(button)), (12, 'Show 18 more'))
        self.assertEqual(self.errors, [])

    def test_a_cut_list_shows_a_name_that_looks_like_markup_as_text(self):                # UX-13, sfMoreList
        self.mount_more_list(30, limit=2)                                               # the markup-like name is third: it is in the part that opens
        self.page.click('#t-more button.sf-more-btn')
        row = self.page.locator('#t-more ul li').nth(2)
        self.assertEqual(row.inner_text(), '<b>bold</b> <img src=x onerror=window.__pwned=1>')
        self.assertEqual(self.page.locator('#t-more ul b, #t-more ul img').count(), 0)
        self.page.wait_for_timeout(100)
        self.assertIsNone(self.page.evaluate('window.__pwned'))
        self.mount_more_list(30)                                                        # and in the part that is shown at first
        self.assertEqual(self.page.locator('#t-more ul li').nth(2).inner_text(), '<b>bold</b> <img src=x onerror=window.__pwned=1>')
        self.assertEqual(self.page.locator('#t-more ul b, #t-more ul img').count(), 0)
        self.assertEqual(self.errors, [])

    def test_a_list_that_is_not_cut_has_no_button(self):                                   # UX-13, sfMoreList
        self.mount_more_list(12)
        self.assertEqual((self.page.locator('#t-more ul li').count(), self.page.locator('#t-more button').count()), (12, 0))
        self.mount_more_list(13)
        self.assertEqual((self.page.locator('#t-more ul li').count(), self.page.inner_text('#t-more button')), (12, 'Show 1 more'))
        self.mount_more_list(0)
        self.assertEqual((self.page.locator('#t-more ul li').count(), self.page.locator('#t-more button').count()), (0, 0))
        self.assertEqual(self.errors, [])

    def test_the_security_rows_say_what_they_leave_out(self):                             # UX-13, sfMoreList
        """Four of its tables showed the first fifty (forty, three hundred) rows of a longer answer and said nothing."""
        self.page.evaluate("""() => {
            document.getElementById('t-more')?.remove();
            const host = document.createElement('div');
            host.id = 't-more';
            host.append(secTable(['Path', 'What'], Array.from({ length: 30 }, (_, i) => [`/srv/file${i}`, i === 0 ? '<i>x</i>' : 'changed']), 20));
            document.body.append(host);
        }""")
        self.assertEqual(self.page.locator('#t-more .sec-row').count(), 20)
        self.assertEqual(self.page.inner_text('#t-more button'), 'Show 10 more')
        self.page.click('#t-more button')
        self.assertEqual(self.page.locator('#t-more .sec-row').count(), 30)
        self.assertEqual(self.page.locator('#t-more i').count(), 0)
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


    # ── the latest answer wins: UX-12 ────────────────────────────────────────────────────────────────────────────────────
    def hold_first(self, pattern):
        """Routes the requests matching `pattern` (a compiled regex): the first is left waiting, in the list this returns, and every later one goes straight through."""
        held = []
        self.page.route(pattern, lambda route: held.append(route) if not held else route.continue_())
        return held

    def answer(self, route, body):
        import json
        route.fulfill(body=json.dumps(body), content_type='application/json')

    def test_a_slow_search_does_not_land_on_top_of_a_newer_one(self):            # UX-12
        import re
        held = self.hold_first(re.compile(r'/api/search\?'))
        self.page.evaluate("() => { runSearch({q: 'one'}); runSearch({q: 'two'}); }")         # asked in this order, and the first answer is kept back
        self.page.wait_for_selector('#results li:has-text("No matches.")')
        self.answer(held[0], {'results': [{'host': 'nas', 'mount': '/', 'path': '/stale.txt', 'size': 1, 'type': 'file', 'modified_at': 1700000000}]})
        self.page.wait_for_timeout(400)
        self.assertNotIn('stale.txt', self.page.inner_text('#results'))
        self.assertEqual(self.page.inner_text('#nres'), '')
        self.assertEqual(self.errors, [])

    def test_slow_host_logs_do_not_land_on_top_of_a_newer_search(self):          # UX-12
        import re
        self.open_tab('hostlogs')
        self.page.wait_for_selector('#hl-lines li')
        held = self.hold_first(re.compile(r'/api/hostlogs\?'))
        self.page.evaluate("() => { hlSearch(false); hlSearch(false); }")
        self.page.wait_for_selector('#hl-lines li:has-text("No lines match")')
        self.answer(held[0], {'entries': [{'message': 'stale line', 'priority': 6, 'ts': 1700000000, 'host': 'nas', 'level': 'info', 'unit': 'x', 'pid': None, 'ident': None}], 'more': True})
        self.page.wait_for_timeout(400)
        self.assertNotIn('stale line', self.page.inner_text('#hl-lines'))
        self.assertTrue(self.page.is_hidden('#hl-more'))                          # nor did it bring a "load more" with it
        self.assertEqual(self.errors, [])

    def test_the_scan_picked_last_is_the_one_shown(self):                         # UX-12
        import re
        self.page.click('#viewmode button[data-mode="scan"]')
        self.page.wait_for_selector('.nscan')
        held = self.hold_first(re.compile(r'/api/netscan(\?|$)'))
        self.page.evaluate("() => { loadNetScan(); loadNetScan(); }")
        self.page.wait_for_selector('input[aria-label="Networks to scan"]')
        self.assertNotEqual(self.page.input_value('input[aria-label="Networks to scan"]'), '10.9.9.0/24')
        self.answer(held[0], {'settings': {'enabled': False, 'ranges': ['10.9.9.0/24'], 'every_hours': 0, 'nmap': True, 'top_ports': 100}, 'scans': [], 'results': {'scan': None, 'ranges': [], 'hosts': []}})
        self.page.wait_for_timeout(400)
        self.assertNotEqual(self.page.input_value('input[aria-label="Networks to scan"]'), '10.9.9.0/24')
        self.assertEqual(self.errors, [])
        self.page.click('#viewmode button[data-mode="topo"]')

    def test_a_slow_map_load_does_not_draw_over_a_newer_one(self):               # UX-12
        import re
        self.page.click('#viewmode button[data-mode="map"]')
        self.page.wait_for_selector('#mpsvg')
        held = self.hold_first(re.compile(r'/api/map\?'))
        self.page.evaluate("() => { loadMap(); loadMap(); }")
        self.page.wait_for_selector('#mpsvg')
        stale = held[0].fetch().json()
        for node in stale['nodes']:
            node['label'] = 'STALE ' + node['label']
        self.answer(held[0], stale)
        self.page.wait_for_timeout(400)
        self.assertNotIn('STALE', self.page.inner_text('#mpcanvas'))
        self.assertFalse(self.page.evaluate("MP.graph.nodes.some((n) => n.label.startsWith('STALE'))"))     # and it did not change what the page holds either
        self.assertEqual(self.errors, [])
        self.page.click('#viewmode button[data-mode="topo"]')

    def test_a_slow_infra_view_does_not_replace_the_one_chosen_after_it(self):    # UX-12
        """Safe because each load fills an element of its own, which a newer load has already replaced: this holds it that way."""
        import re
        self.page.click('.tabs button[data-tab="infra"]')
        self.page.wait_for_selector('#infrabox .seg button')
        self.page.click('#infrabox .seg button:has-text("Exposure")')
        self.page.wait_for_timeout(300)
        held = self.hold_first(re.compile(r'/api/workloads'))
        self.page.click('#infrabox .seg button:has-text("Workloads")')
        self.page.wait_for_selector('#infrabox >> text=Loading')
        self.page.click('#infrabox .seg button:has-text("Exposure")')
        self.page.wait_for_timeout(500)
        self.assertNotIn('containers read', self.page.inner_text('#infrabox'))
        held[0].continue_()                                                        # the slow Workloads answer arrives last
        self.page.wait_for_timeout(500)
        self.assertNotIn('containers read', self.page.inner_text('#infrabox'))
        self.assertEqual(self.errors, [])


    # ── the kernel: dialogs, errors, busy, the password and the host key: UX-10, UX-11 and UX-23 ───────────────────────
    def json_route(self, pattern, status=200, body=None, seen=None):
        """Answers requests matching `pattern` (a compiled regex) with JSON, and notes what each one sent."""
        import json

        def handle(route):
            if seen is not None:
                seen.append((route.request.method, route.request.post_data))
            route.fulfill(status=status, body=json.dumps(body if body is not None else {}), content_type='application/json')
        self.page.route(pattern, handle)

    def test_a_confirm_names_what_will_happen_and_cancel_does_nothing(self):       # UX-10
        import re
        seen = []
        self.json_route(re.compile(r'/api/keys/x$'), seen=seen)
        self.page.evaluate("() => { removeVaultItem('/api/keys/x', 'Remove key x? It cannot be recovered.'); }")
        self.page.wait_for_selector('dialog.sf-dialog[open]')
        self.assertEqual(self.page.inner_text('dialog.sf-dialog h2'), 'Remove key x? It cannot be recovered.')
        self.assertEqual(self.page.evaluate('document.activeElement.textContent'), 'Cancel')          # what cannot be undone starts on the safe button
        self.assertTrue(self.page.is_visible('dialog.sf-dialog .sf-btn.danger:has-text("Remove")'))
        self.page.keyboard.press('Escape')
        self.page.wait_for_selector('dialog.sf-dialog', state='detached')
        self.page.wait_for_timeout(200)
        self.assertEqual(seen, [])
        self.page.evaluate("() => { removeVaultItem('/api/keys/x', 'Remove key x?'); }")
        self.page.click('dialog.sf-dialog .sf-btn.danger')
        self.page.wait_for_selector('dialog.sf-dialog', state='detached')
        self.page.wait_for_timeout(300)
        self.assertEqual([m for m, _ in seen], ['DELETE'])
        self.assertEqual(self.page.locator('.sf-toast.error').count(), 0)

    def test_a_dialog_gives_focus_back_to_what_opened_it(self):                    # UX-10
        self.page.evaluate("""() => { const b = document.createElement('button'); b.id = 'opener'; b.textContent = 'Open'; document.body.append(b);
                                      b.addEventListener('click', () => { confirmDialog({ title: 'Sure?', confirm: 'Yes' }); }); }""")
        self.page.focus('#opener')
        self.page.keyboard.press('Enter')
        self.page.wait_for_selector('dialog.sf-dialog[open]')
        self.assertEqual(self.page.evaluate('document.activeElement.textContent'), 'Yes')             # a plain question starts on the answer
        self.page.keyboard.press('Escape')
        self.page.wait_for_selector('dialog.sf-dialog', state='detached')
        self.assertEqual(self.page.evaluate('document.activeElement.id'), 'opener')

    def test_what_cannot_be_undone_asks_for_the_name(self):                         # UX-10
        self.page.evaluate("() => { confirmDialog({ title: 'Retire nas?', body: 'Gone.', confirm: 'Retire host', danger: true, typed: 'nas' }).then((v) => { window.__answer = v; }); }")
        self.page.wait_for_selector('dialog.sf-dialog[open] input')
        self.assertEqual(self.page.evaluate('document.activeElement.tagName'), 'INPUT')
        ok = self.page.locator('dialog.sf-dialog .sf-btn.danger')
        self.assertTrue(ok.is_disabled())
        self.page.fill('dialog.sf-dialog input', 'na')
        self.assertTrue(ok.is_disabled())
        self.page.fill('dialog.sf-dialog input', 'nas')
        self.assertTrue(ok.is_enabled())
        self.page.keyboard.press('Enter')
        self.page.wait_for_selector('dialog.sf-dialog', state='detached')
        self.assertIs(self.page.evaluate('window.__answer'), True)

    def test_a_dialog_shows_text_and_never_markup(self):                             # UX-10
        evil = '<img src=x onerror=window.__pwned=1> /srv/<b>x</b>'
        self.page.evaluate("(t) => { confirmDialog({ title: t, body: t, items: [t], confirm: 'Go' }); }", evil)
        self.page.wait_for_selector('dialog.sf-dialog[open]')
        self.assertEqual(self.page.locator('dialog.sf-dialog img, dialog.sf-dialog b').count(), 0)
        self.assertIn(evil, self.page.inner_text('dialog.sf-dialog h2'))
        self.assertIsNone(self.page.evaluate('window.__pwned || null'))

    def test_retiring_a_host_asks_for_its_name_and_then_says_what_is_left_on_it(self):    # UX-10
        import re
        seen = []
        self.json_route(re.compile(r'/api/hosts/ghost$'), body={'removed': {'still_on_host': 'its scan key is still in authorized_keys'}}, seen=seen)
        self.page.evaluate("() => { retireHost('ghost'); }")
        self.page.wait_for_selector('dialog.sf-dialog input')
        self.page.fill('dialog.sf-dialog input', 'ghost')
        self.page.click('dialog.sf-dialog .sf-btn.danger')
        self.page.wait_for_selector('dialog.sf-dialog h2:has-text("ghost is retired")')      # api() gave a Response, so this never showed before
        self.assertIn('authorized_keys', self.page.inner_text('dialog.sf-dialog'))
        self.assertEqual([m for m, _ in seen], ['DELETE'])

    def test_a_schedule_is_edited_in_one_form_and_not_two_prompts(self):            # UX-10
        import json
        import re
        seen = []
        self.page.route(re.compile(r'/api/hosts/nas/schedule$'), lambda route: (seen.append(route.request.post_data), route.fulfill(status=200, body='{}', content_type='application/json'))
                        if route.request.method == 'PUT' else route.continue_())
        self.page.evaluate("() => { editSchedule('nas'); }")
        self.page.wait_for_selector('dialog.sf-dialog input')
        self.assertEqual(self.page.locator('dialog.sf-dialog input').count(), 2)
        self.page.locator('dialog.sf-dialog input').nth(0).fill('6h')
        self.page.locator('dialog.sf-dialog input').nth(1).fill('22-6')
        self.page.click('dialog.sf-dialog .sf-btn.pri')
        self.page.wait_for_selector('dialog.sf-dialog', state='detached')
        self.page.wait_for_timeout(200)
        self.assertEqual(json.loads(seen[0]), {'interval': '6h', 'quiet_hours': '22-6'})

    def test_retention_counts_are_checked_before_they_are_sent(self):                # UX-10
        import json
        import re
        seen = []
        self.json_route(re.compile(r'/api/deploy/jobs/7/retention$'), body={'output': 'ok'}, seen=seen)
        self.open_tab('deploy')
        self.page.evaluate("() => { editRetention({ id: 7, name: 'snaps', method: 'snapper', levels: { daily: 7 } }); }")
        self.page.wait_for_selector('dialog.sf-dialog input')
        self.assertEqual(self.page.input_value('dialog.sf-dialog input'), 'daily=7')
        self.page.fill('dialog.sf-dialog input', 'daily seven')
        self.page.click('dialog.sf-dialog .sf-btn.pri')
        self.assertIn('level=count', self.page.inner_text('dialog.sf-dialog .sf-err'))
        self.assertEqual(seen, [])                                                          # refused in the form, so nothing was sent
        self.page.fill('dialog.sf-dialog input', 'daily=3 weekly=2')
        self.page.click('dialog.sf-dialog .sf-btn.pri')
        self.page.wait_for_selector('dialog.sf-dialog', state='detached')
        self.page.wait_for_timeout(200)
        self.assertEqual(json.loads(seen[0][1]), {'keep': {'daily': 3, 'weekly': 2}})

    def test_an_error_stays_until_it_is_dismissed_and_a_notice_goes_by_itself(self):   # UX-10, UX-11
        self.page.evaluate("() => { notify('it broke', 'error'); notify('saved'); announce('Saved the design'); }")
        self.assertEqual(self.page.get_attribute('.sf-toast.error', 'role'), 'alert')
        self.assertEqual(self.page.get_attribute('.sf-toast:not(.error)', 'role'), 'status')
        self.page.wait_for_selector('.sf-live:has-text("Saved the design")')
        self.page.wait_for_selector('.sf-toast:not(.error)', state='detached', timeout=9000)
        self.assertEqual(self.page.locator('.sf-toast.error').count(), 1)                  # the notice went, and the error is still there
        self.page.click('.sf-toast.error button')
        self.assertEqual(self.page.locator('.sf-toast').count(), 0)

    def test_a_busy_button_says_so_while_its_call_is_out(self):                        # UX-11
        import re
        held = self.hold_first(re.compile(r'/api/search/hosts'))
        self.page.evaluate("""() => { const b = document.createElement('button'); b.id = 'busybtn'; b.textContent = 'Go'; document.body.append(b);
                                      api('/api/search/hosts', { busy: b }).then((r) => r.json()).then((j) => { window.__hosts = j.hosts; }); }""")
        self.page.wait_for_selector('#busybtn[aria-busy="true"]')
        self.assertEqual(self.page.get_attribute('#busybtn', 'aria-disabled'), 'true')
        self.assertIs(self.page.evaluate("document.getElementById('busybtn').disabled"), False)      # not `disabled`: it could not take focus back from a dialog
        held[0].continue_()
        self.page.wait_for_selector('#busybtn:not([aria-busy])')
        self.assertIsNone(self.page.get_attribute('#busybtn', 'aria-disabled'))
        self.assertIsInstance(self.page.evaluate('window.__hosts'), list)

    def test_a_button_whose_handler_is_slow_shows_it_and_ignores_a_second_click(self):  # UX-11
        self.page.evaluate("""() => { window.__calls = 0;
          const b = button('Slow', () => { __calls += 1; return new Promise((r) => { window.__release = r; }); }); b.id = 'slowbtn'; document.body.append(b); }""")
        self.page.focus('#slowbtn')
        self.page.keyboard.press('Enter')
        self.page.wait_for_selector('#slowbtn[aria-busy="true"]')
        self.page.keyboard.press('Enter')                                              # a keyboard user can press it again, and nothing starts twice
        self.assertEqual(self.page.evaluate('__calls'), 1)
        self.assertEqual(self.page.evaluate('document.activeElement.id'), 'slowbtn')    # and it keeps focus while it works
        self.page.evaluate('__release()')
        self.page.wait_for_selector('#slowbtn:not([aria-busy])')
        self.page.keyboard.press('Enter')
        self.assertEqual(self.page.evaluate('__calls'), 2)

    def test_the_planner_asks_for_the_password_in_place_and_goes_on(self):           # UX-23
        """It said "run the change from the main page". Now the kernel asks on the page, and the call that wanted it is retried."""
        import json
        import re
        seen = []

        def hosts(route):
            seen.append(1)
            if len(seen) == 1:
                route.fulfill(status=403, body=json.dumps({'error': 'confirm your password', 'reauth': True}), content_type='application/json')
            else:
                route.continue_()
        self.page.route(re.compile(r'/api/planner/hosts$'), hosts)
        self.page.goto(self.base + '/planner')
        try:
            self.page.wait_for_selector('#reauthpw', state='visible', timeout=15000)
        except Exception as exc:                      # say what the page showed: this test has failed only inside the whole run
            raise AssertionError(f'no password dialog at {self.page.url}; requests to the host list: {len(seen)}; the page says: {self.page.inner_text("body")[:300]!r}; errors: {self.errors}') from exc
        self.assertIn('/planner', self.page.url)
        self.page.fill('#reauthpw', PW)
        self.page.keyboard.press('Enter')
        try:
            self.page.wait_for_selector('#reauthpw', state='detached', timeout=15000)
        except Exception as exc:
            raise AssertionError(f'the dialog stayed: {self.page.inner_text("dialog.sf-dialog")[:300]!r}') from exc
        self.page.wait_for_selector('#hostpick option:has-text("nas")', state='attached')
        self.assertEqual(len(seen), 2)

    def test_a_host_key_is_shown_before_a_password_goes_to_it(self):                  # UX-23
        import json
        import re
        calls, confirmed = [], []

        def hosts(route):
            calls.append(1)
            if len(calls) % 2 == 1:
                route.fulfill(status=409, body=json.dumps({'error': 'host key not confirmed', 'hostkey': {'host': 'edge', 'port': 2222, 'keys': [{'fingerprint': 'SHA256:abcdef', 'type': 'ED25519'}]}}),
                              content_type='application/json')
            else:
                route.continue_()
        self.page.route(re.compile(r'/api/search/hosts$'), hosts)
        self.json_route(re.compile(r'/api/hostkey/confirm$'), seen=confirmed)
        ask = "() => { getJSON('/api/search/hosts').then((j) => { window.__hosts = j.hosts; }, (e) => { window.__err = e.message; }); }"
        self.page.evaluate(ask)
        self.page.wait_for_selector('dialog.sf-dialog:has-text("SHA256:abcdef")')
        self.assertIn('edge (port 2222)', self.page.inner_text('dialog.sf-dialog'))
        self.page.click('dialog.sf-dialog button:has-text("They match")')
        self.page.wait_for_selector('dialog.sf-dialog', state='detached')
        self.page.wait_for_timeout(300)
        self.assertEqual(json.loads(confirmed[0][1]), {'host': 'edge', 'port': 2222, 'fingerprint': 'SHA256:abcdef'})
        self.assertIsInstance(self.page.evaluate('window.__hosts'), list)
        self.page.evaluate(ask)                                                            # and with Cancel, nothing is confirmed and the call fails
        self.page.wait_for_selector('dialog.sf-dialog:has-text("SHA256:abcdef")')
        self.page.click('dialog.sf-dialog button:has-text("Cancel")')
        self.page.wait_for_timeout(300)
        self.assertIn('Host key not confirmed', self.page.evaluate('window.__err'))
        self.assertEqual(len(confirmed), 1)


    # ── shared chrome: the security chip and the way between the pages: UX-09 and UX-03 ───────────────────────────────
    def test_every_page_shows_the_security_chip_and_the_way_to_the_others(self):     # UX-09, UX-03
        """Only the main page had a line about security, though the changelog said "a line at the top of every page"."""
        for path, here in (('/planner', '/planner'), ('/manage', '/manage')):
            self.page.goto(self.base + path)
            self.page.wait_for_selector('.sf-chrome .threat:not([hidden])', timeout=9000)
            self.assertTrue(self.page.inner_text('.sf-chrome .threat').startswith('Security: '), path)
            self.assertIn('measured in the last day', self.page.inner_text('.sf-chrome .threat-detail'))
            self.assertEqual(self.page.eval_on_selector_all('.sf-chrome nav a', 'as => as.map((a) => a.textContent)'), ['Topology and map', 'Storage planner', 'Network management', 'Changes', 'Moves', 'Schedule'])
            self.assertEqual(self.page.get_attribute('.sf-chrome nav a[aria-current="page"]', 'href'), here)
            self.assertIn('admin', self.page.inner_text('.sf-user'))
        self.page.goto(self.base + '/search')
        self.page.wait_for_selector('.sf-chrome .threat:not([hidden])', timeout=9000)
        self.assertTrue(self.page.is_visible('.sf-user button:has-text("Sign out")'))
        self.assertEqual(self.errors, [])

    def test_the_chip_on_another_page_opens_the_security_panel(self):                 # UX-09
        self.page.goto(self.base + '/manage')
        self.page.wait_for_selector('.sf-chrome .threat:not([hidden])', timeout=9000)
        self.page.click('.sf-chrome .threat')
        self.page.wait_for_selector('.tabs button[data-tab="security"][aria-selected="true"]')
        self.assertEqual(self.errors, [])

    def test_the_planner_and_manage_can_sign_out(self):                               # UX-03
        for path in ('/planner', '/manage'):
            self.page.goto(self.base + path)
            self.page.wait_for_selector('.sf-user button')
            self.page.click('.sf-user button:has-text("Sign out")')
            self.page.wait_for_url(self.base + '/login*')
            self.page.goto(self.base + '/login')
            self.page.fill('input[type=text], input[name=username], #username', 'admin')           # the next pass needs a session again
            self.page.fill('input[type=password]', PW)
            self.page.press('input[type=password]', 'Enter')
            self.page.wait_for_selector('.tabs button')


    # ── one place for shortcuts: UX-20, UX-40 and UX-41 ──────────────────────────────────────────────────────────────
    def test_every_global_shortcut_is_declared_with_what_it_is_for(self):               # UX-20
        got = self.page.evaluate('sfShortcuts()')
        self.assertEqual({s['id'] for s in got}, {'search-focus', 'clear-focus', 'context-menu', 'context-menu-f10', 'panel-toggle', 'tasks-undo', 'file-map-dest'})
        for s in got:
            self.assertTrue(s['label'] and s['where'] and s['key'], s)             # what a help overlay would show

    def test_the_registry_keeps_a_shortcut_off_a_key_somebody_is_typing(self):            # UX-40, UX-41
        self.page.evaluate("""() => {
          window.__hits = [];
          const hit = (n) => () => { __hits.push(n); };
          sfShortcut({ id: 't-plain', key: 'q', label: 't', run: hit('plain') });
          sfShortcut({ id: 't-fields', key: 'w', label: 't', fields: true, run: hit('fields') });
          sfShortcut({ id: 't-dialogs', key: 'e', label: 't', dialogs: true, run: hit('dialogs') });
          sfShortcut({ id: 't-mod', key: 'y', mods: 'mod', label: 't', run: hit('mod') });
          sfShortcut({ id: 't-pass', key: 't', label: 't', run: () => false });
          sfShortcut({ id: 't-next', key: 't', label: 't', run: hit('next') });
          const i = document.createElement('input'); i.id = 'tf'; document.body.append(i);
        }""")
        hits = lambda: self.page.evaluate('__hits.splice(0)')
        press = lambda *keys: [self.page.keyboard.press(k) for k in keys]
        self.page.evaluate('document.activeElement.blur()')
        press('q', 'w', 'e', 't')
        self.assertEqual(hits(), ['plain', 'fields', 'dialogs', 'next'])               # on the page they all act, and a shortcut that finds nothing hands the key on
        press('Control+q', 'Alt+q', 'Control+y')
        self.assertEqual(hits(), ['mod'])                                                # Ctrl or Alt held is not a plain key; Ctrl is what a "mod" shortcut asks for
        self.page.focus('#tf')
        press('q', 'w', 'e', 'Control+y')
        self.assertEqual(hits(), ['fields'])                                             # in a text field only the one that says so acts
        self.page.evaluate('document.activeElement.blur()')
        self.page.evaluate("() => { confirmDialog({ title: 'Sure?', confirm: 'Yes' }); }")
        self.page.wait_for_selector('dialog.sf-dialog[open]')
        press('q', 'w', 'e')
        self.assertEqual(hits(), ['dialogs'])                                            # under a dialog, the same
        self.assertEqual(self.errors, [])


    # ── one way to show a time and a size: UX-16 ─────────────────────────────────────────────────────────────────────
    def test_a_time_is_local_with_its_utc_form_on_hover_and_a_size_has_one_unit_system(self):    # UX-16
        got = self.page.evaluate("""() => ({
          utc: fmtUtc(1700000000), local: fmtTime(1700000000), withSeconds: fmtTime(1700000000, { seconds: true }), day: fmtDate(1700000000), clock: fmtClock(1700000000),
          el: (() => { const t = timeEl(1700000000, { seconds: true }); return [t.tagName, t.title, t.dateTime, t.textContent]; })(),
          never: [fmtTime(null), fmtTime(0 || null), fmtAgo(0), fmtAgo(null, { never: 'no commits' })],
          ago: [fmtAgo(Date.now() / 1000 - 300), fmtAgo(Date.now() / 1000 - 7200), fmtAgo(Date.now() / 1000 + 7200), fmtAgo(Date.now() / 1000 - 86400 * 400), fmtAgo(Date.now() / 1000 - 86400 * 800)],
          bytes: [fmtBytes(null), fmtBytes(1536), fmtBytes(5 * 1024 ** 3), fmtBytes(0)],
          what: [typeof size, typeof secAgo, typeof hlWhen] })""")
        self.assertEqual(got['utc'], '2023-11-14 22:13:20 UTC')
        self.assertRegex(got['local'], r'^\d{4}-\d\d-\d\d \d\d:\d\d$')
        self.assertRegex(got['withSeconds'], r'^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d$')
        self.assertTrue(got['withSeconds'].startswith(got['local']))
        self.assertRegex(got['day'], r'^\d{4}-\d\d-\d\d$')
        self.assertEqual(got['el'][:3], ['TIME', '2023-11-14 22:13:20 UTC', '2023-11-14T22:13:20.000Z'])
        self.assertEqual(got['el'][3], got['withSeconds'])
        self.assertEqual(got['never'], ['', '', 'never', 'no commits'])
        self.assertEqual(got['ago'], ['5 min ago', '2 h ago', 'in 2 h', '13 months ago', '2 years ago'])
        self.assertEqual(got['bytes'], ['—', '2 KiB', '5.00 GiB', '0 B'])

    def test_a_log_line_shows_local_time_and_its_utc_form_on_hover(self):               # UX-16
        import re
        self.json_route(re.compile(r'/api/hostlogs\?'), body={'entries': [{'message': 'link is up', 'priority': 6, 'ts': 1700000000, 'host': 'nas', 'level': 'info', 'unit': 'x', 'pid': None, 'ident': None}], 'more': False})
        self.open_tab('hostlogs')
        self.page.wait_for_selector('#hl-lines li:has-text("link is up")')
        meta = self.page.locator('#hl-lines li span.m').first
        self.assertEqual(meta.get_attribute('title'), '2023-11-14 22:13:20 UTC')
        self.assertTrue(meta.inner_text().startswith(self.page.evaluate('fmtTime(1700000000, { seconds: true })')))
        self.assertEqual(self.errors, [])


    # ── work in progress: UX-15 ─────────────────────────────────────────────────────────────────────────────────────
    def test_compose_text_survives_a_reload_and_is_not_replaced_without_asking(self):       # UX-15
        self.page.goto(self.base + '/manage')
        self.page.click('#mgnav button[data-v="compose"]')
        self.page.wait_for_selector('textarea')
        self.page.fill('textarea', '/ip firewall filter add chain=input protocol=tcp dst-port=2222 action=accept')
        self.page.reload()
        self.page.click('#mgnav button[data-v="compose"]')
        self.page.wait_for_selector('textarea')
        self.assertIn('dst-port=2222', self.page.input_value('textarea'))                   # it was in memory only, so a reload threw it away
        self.page.click('button:has-text("Load what it runs")')
        self.page.wait_for_selector('dialog.sf-dialog h2:has-text("Replace what you have written?")')
        self.page.click('dialog.sf-dialog button:has-text("Cancel")')
        self.page.wait_for_selector('dialog.sf-dialog', state='detached')
        self.assertIn('dst-port=2222', self.page.input_value('textarea'))                   # and Load did not take it over without asking
        self.assertEqual(self.errors, [])

    def test_a_kept_draft_belongs_to_the_person_who_wrote_it(self):                          # UX-15
        self.page.goto(self.base + '/manage')
        self.page.wait_for_selector('#mgnav button')
        self.page.evaluate("""() => { localStorage.setItem('sf.compose.draft', JSON.stringify({ user: 'someone-else', value: 'their secret rules' })); }""")
        self.page.reload()
        self.page.click('#mgnav button[data-v="compose"]')
        self.page.wait_for_selector('textarea')
        self.assertNotIn('their secret rules', self.page.input_value('textarea'))
        self.assertEqual(self.errors, [])

    def test_the_maps_staged_steps_survive_a_reload(self):                                    # UX-15
        self.page.evaluate("""() => { MP.draft.push({ type: 'fw-rule', host: 'nas', params: { action: 'allow', proto: 'tcp', port: '8000', source: '10.0.0.0/8' } }); mapWhatIf(); }""")
        self.page.reload()
        self.page.wait_for_selector('.tabs button')
        self.page.click('#viewmode button[data-mode="map"]')
        self.page.wait_for_selector('#mpwhatif h4:has-text("What this would do")')
        self.assertIn('nas: fw-rule', self.page.inner_text('#mpwhatif'))
        self.page.click('#mpwhatif button:has-text("Forget it")')                           # forgetting them forgets the kept copy too
        self.page.reload()
        self.page.click('#viewmode button[data-mode="map"]')
        self.page.wait_for_selector('.mpmodes')
        self.assertEqual(self.page.locator('#mpwhatif h4').count(), 0)
        self.page.click('#viewmode button[data-mode="topo"]')

    def test_one_rule_asks_before_work_that_would_be_lost_is_closed(self):                   # UX-15
        ids = self.page.evaluate('SF_UNSAVED.map((u) => u.id)')
        self.assertEqual(set(ids), {'designs', 'task', 'changes', 'moves', 'map-steps'})
        asks = lambda: self.page.evaluate("() => { const ev = new Event('beforeunload', { cancelable: true }); window.dispatchEvent(ev); return ev.defaultPrevented; }")
        self.assertFalse(asks())
        self.page.evaluate('CH.dirty = true')                                                 # a change plan keeps a draft in the browser: nothing is lost
        self.assertFalse(asks())
        self.page.evaluate('TK.dirty = true')                                                 # a task being edited is not kept anywhere
        self.assertTrue(asks())
        self.page.evaluate('TK.dirty = false; CH.dirty = false')
        self.assertFalse(asks())

    def test_a_lost_session_says_what_was_kept_and_what_could_not_be(self):                  # UX-15
        self.page.evaluate("""() => { CH.dirty = true; TK.dirty = true; MP.draft.push({ type: 'net-mtu', host: 'nas', params: { iface: 'eth0', mtu: '1400', rollback: '10' } });
                                      fetch('/api/logout', { method: 'POST', credentials: 'same-origin' }).then(() => sfSignedOut('ended')); }""")      # the session really is gone, so /login stays
        self.page.wait_for_url(self.base + '/login*')
        msg = self.page.inner_text('#loginmsg')
        self.assertIn('Your session ended.', msg)
        self.assertIn('Kept in this browser until you sign in again: the change plan you were editing, the steps staged on the map.', msg)
        self.assertIn('Could not be kept: the task you were editing.', msg)
        self.page.goto(self.base + '/login')                                                  # said once, then forgotten
        self.assertNotIn('Kept in this browser', self.page.inner_text('#loginmsg'))


    # ── a router: UX-08 ──────────────────────────────────────────────────────────────────────────────────────────────
    def view_and_panel(self):
        return self.page.evaluate("[document.querySelector('#viewmode button[aria-pressed=true]').dataset.mode, document.querySelector('.tabs button.on').dataset.tab]")

    def test_back_and_forward_go_where_the_person_was(self):                         # UX-08
        """The page kept its place in memory, so Back left it: a person who looked at Graph, then the map, and pressed Back was somewhere else."""
        self.assertEqual(self.view_and_panel(), ['topo', 'details'])
        self.page.click('#viewmode button[data-mode="graph"]')
        self.page.click('#viewmode button[data-mode="map"]')
        self.page.click('.tabs button[data-tab="search"]')
        self.assertIn('#/map/search', self.page.url)
        self.page.go_back()
        self.assertEqual(self.view_and_panel(), ['map', 'details'])
        self.page.go_back()
        self.assertEqual(self.view_and_panel(), ['graph', 'details'])
        self.page.go_forward()
        self.assertEqual(self.view_and_panel(), ['map', 'details'])
        self.assertEqual(self.errors, [])
        self.page.click('#viewmode button[data-mode="topo"]')

    def test_a_copied_url_lands_where_it_was_copied(self):                           # UX-08
        self.page.goto(self.base + '/manage')
        self.page.goto(self.base + '/#/graph/changes?host=nas')
        self.page.wait_for_selector('.tabs button[data-tab="changes"].on')
        self.assertEqual(self.view_and_panel(), ['graph', 'changes'])
        self.assertEqual(self.page.input_value('#host'), 'nas')
        self.assertEqual(self.errors, [])

    def test_the_security_sub_panel_is_part_of_the_url(self):                        # UX-08
        self.page.goto(self.base + '/manage')
        self.page.goto(self.base + '/#/topo/security?host=nas&sec=firewall')
        self.page.wait_for_selector('#sec-subnav button[data-sub="firewall"][aria-pressed="true"]')
        self.page.click('#sec-subnav button[data-sub="worm"]')
        self.assertIn('sec=worm', self.page.url)
        self.assertIn('host=nas', self.page.url)
        self.page.go_back()
        self.page.wait_for_selector('#sec-subnav button[data-sub="firewall"][aria-pressed="true"]')
        self.assertEqual(self.errors, [])

    def test_the_old_links_still_work_and_are_tidied_into_the_new_form(self):        # UX-08
        self.page.goto(self.base + '/manage')
        self.page.goto(self.base + '/#host=nas&tab=audit')
        self.page.wait_for_selector('.tabs button[data-tab="audit"].on')
        self.assertEqual(self.page.input_value('#host'), 'nas')
        self.assertIn('#/topo/audit?host=nas', self.page.url)
        self.page.goto(self.base + '/manage')
        self.page.goto(self.base + '/#view=map&mode=storage')                           # what the map's own links wrote
        self.page.wait_for_selector('.mpmodes button[aria-pressed="true"]:has-text("Storage only")')
        self.assertEqual(self.view_and_panel()[0], 'map')
        self.assertIn('mode=storage', self.page.url)

    def test_a_link_inside_the_page_changes_the_hash_and_not_the_page(self):          # UX-08
        self.page.evaluate("() => { window.__same = 42; location.hash = '#/graph/rebuild?host=nas'; }")
        self.page.wait_for_selector('.tabs button[data-tab="rebuild"].on')
        self.assertEqual(self.page.evaluate('window.__same'), 42)                       # nothing reloaded
        self.assertEqual(self.view_and_panel(), ['graph', 'rebuild'])
        self.page.evaluate("() => { location.hash = '#host=nas&tab=schedule'; }")        # the old form, the same way
        self.page.wait_for_selector('.tabs button[data-tab="schedule"].on')
        self.assertEqual(self.page.evaluate('window.__same'), 42)
        self.assertEqual(self.errors, [])
        self.page.click('#viewmode button[data-mode="topo"]')

    def test_choosing_a_host_is_a_step_in_the_history(self):                          # UX-08
        self.page.select_option('#host', 'nas')
        self.assertIn('host=nas', self.page.url)
        self.page.go_back()
        self.assertEqual(self.page.input_value('#host'), '')
        self.assertNotIn('host=', self.page.url)
        self.assertEqual(self.errors, [])

    def test_the_map_says_its_layers_in_the_url_when_no_preset_does(self):            # UX-08
        self.page.click('#viewmode button[data-mode="map"]')
        self.page.wait_for_selector('.mplayers')
        self.page.click('.mpmodes button:has-text("Storage only")')
        self.page.wait_for_selector('.mpmodes button[aria-pressed="true"]:has-text("Storage only")')
        self.assertIn('mode=storage', self.page.url)
        self.page.click('.mplayers label:has-text("Network") input')
        self.assertIn('layers=', self.page.url)
        self.assertNotIn('mode=', self.page.url)
        self.assertEqual(self.errors, [])
        self.page.click('#viewmode button[data-mode="topo"]')


    def test_the_planner_and_manage_keep_their_place_in_the_url_too(self):             # UX-08
        self.page.goto(self.base + '/planner#devices@nas')                              # the old form still opens on that view and design
        self.page.wait_for_selector('#nav button[data-view="devices"].on')
        self.page.wait_for_selector('#hostpick option:has-text("nas")', state='attached')
        self.page.click('#nav button[data-view="mounts"]')
        self.assertIn('#/mounts', self.page.url)
        self.assertIn('host=nas', self.page.url)
        self.page.go_back()
        self.page.wait_for_selector('#nav button[data-view="devices"].on')
        self.assertIn('#/devices', self.page.url)
        self.page.goto(self.base + '/manage#/compose')
        self.page.wait_for_selector('#mgnav button[data-v="compose"][aria-current="page"]')
        self.page.click('#mgnav button[data-v="traffic"]')
        self.assertIn('#/traffic', self.page.url)
        self.page.go_back()
        self.page.wait_for_selector('#mgnav button[data-v="compose"][aria-current="page"]')
        self.page.goto(self.base + '/manage#device=gw')                                  # and the old form of a device link
        self.page.wait_for_selector('#mgnav button[data-v="devices"][aria-current="page"]')
        self.assertEqual(self.errors, [])


    # ── the rail as a tab list: UX-05 and UX-20 ──────────────────────────────────────────────────────────────────────
    def test_every_rail_tab_names_its_panel_and_every_panel_names_its_tab(self):        # UX-20
        got = self.page.evaluate("""() => [...document.querySelectorAll('.tabs button[role=tab]')].map((b) => {
          const p = document.getElementById(b.getAttribute('aria-controls'));
          return [b.dataset.tab, !!p, p && p.getAttribute('role'), p && p.getAttribute('aria-labelledby') === b.id]; })""")
        self.assertEqual(len(got), 18)
        for tab, found, role, back in got:
            self.assertEqual((found, role, back), (True, 'tabpanel', True), tab)

    def test_the_rail_is_one_tab_stop_and_takes_arrow_keys(self):                        # UX-20
        stops = lambda: self.page.evaluate("[...document.querySelectorAll('.tabs button[role=tab]')].filter((b) => b.tabIndex === 0).map((b) => b.dataset.tab)")
        self.assertEqual(stops(), ['details'])                                            # one stop, and it is the selected tab
        self.page.focus('.tabs button[data-tab="details"]')
        focused = lambda: self.page.evaluate('document.activeElement.dataset.tab')
        self.page.keyboard.press('ArrowDown')
        self.assertEqual(focused(), 'search')
        self.page.keyboard.press('ArrowDown')
        self.assertEqual(focused(), 'changes')
        self.assertEqual(stops(), ['details'])                                            # moving does not open: Enter or Space does
        self.page.keyboard.press('Enter')
        self.page.wait_for_selector('.tabs button[data-tab="changes"][aria-selected="true"]')
        self.assertEqual(stops(), ['changes'])
        self.page.keyboard.press('Home')
        self.assertEqual(focused(), 'details')
        self.page.keyboard.press('End')
        self.assertEqual(focused(), self.page.evaluate("[...document.querySelectorAll('.tabs button[role=tab]')].filter((b) => !b.hidden).pop().dataset.tab"))
        self.page.keyboard.press('ArrowDown')                                             # and the end wraps to the start
        self.assertEqual(focused(), 'details')
        self.assertEqual(self.errors, [])

    def test_a_skip_link_is_first_and_moves_focus_into_the_page(self):                    # UX-20
        self.page.evaluate('document.activeElement.blur()')
        self.page.keyboard.press('Tab')
        self.assertEqual(self.page.evaluate('document.activeElement.textContent'), 'Skip to the view')
        self.assertTrue(self.page.is_visible('.skip:focus'))                               # it shows itself when it has focus
        self.page.keyboard.press('Enter')
        self.assertEqual(self.page.evaluate('document.activeElement.id'), 'stage')
        self.page.focus('.skip[data-skip="panel"]')
        self.page.keyboard.press('Enter')
        self.assertEqual(self.page.evaluate('document.activeElement.id'), 'panel')
        self.assertNotIn('#stage', self.page.url)                                          # the router owns the hash: a skip does not write it
        self.assertEqual(self.errors, [])

    def test_the_group_that_held_the_inventory_is_called_the_estate(self):               # UX-05
        groups = self.page.eval_on_selector_all('.tabs .rgroup', 'gs => gs.map((g) => g.textContent)')
        self.assertEqual(groups, ['Inspect', 'Plan', 'Estate', 'Security', 'Admin'])


    # ── Security and the settings with room: UX-04 ───────────────────────────────────────────────────────────────────
    def wide(self):
        return self.page.evaluate("document.querySelector('.layout').classList.contains('wide')")

    def test_security_and_the_settings_panels_open_with_the_whole_page(self):            # UX-04
        """Sixteen security panels and the accounts, roles and invites were laid out in a 380 px column."""
        self.assertFalse(self.wide())
        for tab in ('security', 'audit', 'keys', 'jobs', 'access', 'hostlogs'):
            self.open_tab(tab)
            self.page.wait_for_selector(f'#tab-{tab}', state='visible')
            self.assertTrue(self.wide(), tab)
            self.assertEqual(self.page.evaluate("getComputedStyle(document.querySelector('#stage')).display"), 'none', tab)
            self.assertGreater(self.page.evaluate(f"document.getElementById('tab-{tab}').getBoundingClientRect().width"), 800, tab)
        self.open_tab('changes')
        self.assertFalse(self.wide())
        self.assertTrue(self.page.is_visible('#stage'))                                  # the view is back, and it kept its place
        self.assertEqual(self.errors, [])

    def test_any_panel_can_take_the_page_and_the_choice_is_remembered_per_panel(self):    # UX-04
        self.open_tab('changes')
        self.assertFalse(self.wide())
        self.page.click('#pwide')
        self.assertTrue(self.wide())
        self.assertEqual(self.page.get_attribute('#pwide', 'aria-pressed'), 'true')
        self.page.reload()
        self.page.wait_for_selector('.tabs button')
        self.open_tab('changes')
        self.assertTrue(self.wide())                                                      # after a reload
        self.open_tab('moves')
        self.assertFalse(self.wide())                                                     # another panel is its own choice
        self.open_tab('security')
        self.assertTrue(self.wide())
        self.page.click('#pwide')                                                         # and the default can be undone
        self.assertFalse(self.wide())
        self.assertEqual(self.errors, [])
        self.page.evaluate("localStorage.removeItem('sf.wide.changes'); localStorage.removeItem('sf.wide.security')")

    def test_hiding_the_panel_gives_the_view_back(self):                                  # UX-04
        self.open_tab('security')
        self.assertTrue(self.wide())
        self.page.click('#pclose')
        self.assertFalse(self.wide())
        self.assertTrue(self.page.is_visible('#stage'))
        self.page.click('.tabs button[data-tab="security"]')
        self.assertTrue(self.wide())

    def test_the_security_panels_are_grouped_by_what_a_person_is_doing(self):           # UX-04
        self.open_tab('security')
        self.page.wait_for_selector('#sec-subnav .sec-navgroup')
        groups = self.page.eval_on_selector_all('#sec-subnav .sec-navgroup', 'gs => gs.map((g) => g.getAttribute("aria-label"))')
        self.assertEqual(groups, ['Overview', 'Prepare', 'Detect', 'Respond', 'Prove'])
        subs = self.page.eval_on_selector_all('#sec-subnav button', 'bs => bs.map((b) => b.dataset.sub)')
        self.assertEqual(len(subs), 16)
        self.assertEqual(len(set(subs)), 16)                                              # every panel once, none lost in the regrouping
        self.page.click('#sec-subnav button[data-sub="firewall"]')
        self.page.wait_for_selector('#sec-subnav button[data-sub="firewall"][aria-pressed="true"]')
        self.assertEqual(self.errors, [])


    # ── the map by keyboard: UX-17 ───────────────────────────────────────────────────────────────────────────────────
    def test_every_map_node_is_a_button_in_reading_order(self):                          # UX-17
        """The map was an image to a keyboard and a screen reader: nothing on it could be reached, and it said only "Infrastructure map"."""
        self.page.click('#viewmode button[data-mode="map"]')
        self.page.wait_for_selector('#mpsvg g.k-listener')
        self.assertEqual(self.page.get_attribute('#mpsvg', 'role'), 'group')
        self.assertIn('items', self.page.get_attribute('#mpsvg', 'aria-label'))
        got = self.page.evaluate("""() => [...document.querySelectorAll('#mpsvg [data-id]')].map((e) => [e.getAttribute('role'), e.getAttribute('tabindex'), !!e.getAttribute('aria-label')])""")
        self.assertGreaterEqual(len(got), 5)
        self.assertTrue(all(g == ['button', '0', True] for g in got), got)
        order = self.page.evaluate("[...document.querySelectorAll('#mpsvg [role=button]')].map((e) => e.getAttribute('aria-label'))")
        header = next(i for i, x in enumerate(order) if x.startswith('nas, open'))
        self.assertTrue(any(x.startswith('Listener: ') for x in order[header + 1:]))             # the host's header comes before what is in its frame
        self.assertFalse(any(x.startswith('Listener: ') for x in order[:header]))
        self.assertEqual(self.errors, [])
        self.page.click('#viewmode button[data-mode="topo"]')

    def test_enter_opens_a_nodes_details_and_a_hosts_header_closes_and_opens_it(self):   # UX-17
        self.page.click('#viewmode button[data-mode="map"]')
        self.page.wait_for_selector('#mpsvg g.k-listener')
        self.page.focus('#mpsvg g.k-listener')
        self.page.keyboard.press('Enter')
        self.page.wait_for_selector('#mpdetail h4, #mpdetail b, #mpdetail p')
        self.assertTrue(self.page.inner_text('#mpdetail').strip())
        self.assertEqual(self.page.evaluate('document.activeElement.getAttribute("role")'), 'button')       # it keeps focus where it was
        self.page.wait_for_selector('.sf-live:has-text("selected")')
        self.page.focus('#mpsvg rect.mphit')
        self.page.keyboard.press('Enter')
        self.page.wait_for_selector('#mpsvg g.k-listener', state='detached')                      # closed: what was in the frame is gone
        self.assertEqual(self.page.evaluate('document.activeElement.dataset.frame'), 'nas')        # and focus is still on the header
        self.page.keyboard.press('Enter')
        self.page.wait_for_selector('#mpsvg g.k-listener')
        self.assertEqual(self.page.evaluate('document.activeElement.dataset.frame'), 'nas')
        self.assertEqual(self.errors, [])
        self.page.click('#viewmode button[data-mode="topo"]')


    # ── a host where a panel needs one, one way into the plan, which view for what: UX-07, UX-03 and UX-06 ───────────
    def test_a_panel_about_one_host_carries_its_own_picker(self):                          # UX-07
        """It said "pick a host at the top of the page", which is a dead end for a person looking at the panel."""
        self.assertEqual(self.page.input_value('#host'), '')
        self.open_tab('security')
        self.page.wait_for_selector('#sec-subnav')
        self.page.click('#sec-subnav button[data-sub="decoys"]')
        self.page.wait_for_selector('#sec-content select[aria-label="Host"]')
        self.assertNotIn('top of the page', self.page.inner_text('#sec-content'))
        self.assertEqual(self.page.input_value('#sec-content select[aria-label="Host"]'), 'nas')
        self.page.click('#sec-content button:has-text("Open")')
        self.page.wait_for_selector('#sec-content select[aria-label="Host"]', state='detached')
        self.assertEqual(self.page.input_value('#host'), 'nas')                             # the page's own host moved with it
        self.assertIn('host=nas', self.page.url)
        self.assertEqual(self.errors, [])

    def test_the_infra_views_that_need_a_host_say_the_same(self):                            # UX-07
        self.open_tab('infra')
        self.page.wait_for_selector('#infrabox .seg button')
        self.page.click('#infrabox .seg button:has-text("Network")')
        self.page.wait_for_selector('#infrabox select[aria-label="Host"]')
        self.assertNotIn('Select a host', self.page.inner_text('#infrabox'))
        self.page.click('#infrabox button:has-text("Open")')
        self.page.wait_for_selector('#infrabox select[aria-label="Host"]', state='detached')
        self.assertEqual(self.page.input_value('#host'), 'nas')
        self.assertEqual(self.errors, [])

    def test_the_views_say_what_each_is_for(self):                                           # UX-06
        tips = self.page.eval_on_selector_all('#viewmode button', 'bs => bs.map((b) => [b.dataset.mode, b.title])')
        self.assertEqual([m for m, _ in tips], ['topo', 'graph', 'tasks', 'map', 'scan'])
        self.assertTrue(all(len(t) > 40 for _, t in tips), tips)
        self.assertIn('Edit', dict(tips)['topo'])
        self.assertIn('edit in Topology', dict(tips)['graph'])                               # three canvases draw the same storage: this says which to use for what

    def test_the_planner_and_manage_lead_into_the_steps_of_a_plan(self):                  # UX-03
        self.page.goto(self.base + '/manage')
        self.page.wait_for_selector('.sf-chrome nav a:has-text("Changes")')
        self.page.click('.sf-chrome nav a:has-text("Changes")')
        self.page.wait_for_selector('.tabs button[data-tab="changes"].on')
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

