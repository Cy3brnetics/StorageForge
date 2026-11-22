"""The Toolbox in a real browser: a deep link (#host=box&tab=toolbox&tool=...) opens the tool on its host; the plan and its report are shown
before anything is saved; staging saves a change plan and says nothing ran; a cancelled action or removal dialog sends nothing and does
not redraw the page; the WireGuard peer manager's action saves a wg-peer step; the custom entry editor checks an entry and shows the
command that signs it on the operator's own machine."""
import threading
import time
import unittest

try:
    from test_toolbox import CUSTOM, Base
except ImportError:      # run as tests.test_x from the project folder
    from tests.test_toolbox import CUSTOM, Base
from storageforge_index import security, server, toolbox, users

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sync_playwright = None

PW = 'a long enough password'


@unittest.skipUnless(sync_playwright, 'needs playwright (CI has it)')
class BrowserToolbox(Base):
    def test_deep_link_plan_cancel_and_editor(self):
        from werkzeug.serving import make_server
        self.host('box', 'apt', ['podman', 'wg'])
        security._save_measurement(self.conn, 'box', 'infra', int(time.time()), 'measure',
                                   {'tools': ['podman', 'wg'], 'access': {'wireguard': [{'name': 'wg0', 'public_key': 'A' * 43 + '=', 'listen_port': 51820, 'peers': []}]}})
        users.create(self.conn, 'admin', PW, 'admin')
        http = make_server('127.0.0.1', 0, server.create_app(server.App(self.db), 's' * 48), threaded=True)
        threading.Thread(target=http.serve_forever, daemon=True).start()
        self.addCleanup(http.shutdown)
        pw = sync_playwright().start()
        self.addCleanup(pw.stop)
        browser = pw.chromium.launch()
        self.addCleanup(browser.close)
        page, errors = browser.new_page(), []
        page.on('pageerror', lambda e: errors.append(str(e)))
        base = f'http://127.0.0.1:{http.server_port}'
        page.goto(base + '/login')
        page.fill('input[type=text], input[name=username], #username', 'admin')
        page.fill('input[type=password]', PW)
        page.press('input[type=password]', 'Enter')
        page.wait_for_url(base + '/**')
        page.wait_for_selector('html[data-route-ready]', state='attached')
        page.goto(base + '/#host=box&tab=toolbox&tool=uptime-kuma')
        page.wait_for_selector('#tbtool h3:has-text("Uptime Kuma")')
        self.assertIn('tool=uptime-kuma', page.url)
        self.assertIn('not lab-tested', page.inner_text('#tbtool'))
        self.assertIn('holds credentials', page.inner_text('#tbtool'))
        page.click('#tbinstall button:has-text("Show the plan and its report")')
        page.wait_for_selector('#tbreport li:has-text("ssh -L 3001:127.0.0.1:3001 box")')
        self.assertIn('rootless container', page.inner_text('#tbreport'))
        self.assertEqual(self.conn.scalar('SELECT COUNT(*) FROM change_plans'), 0, 'the report saves nothing')
        page.click('#tbinstall button:has-text("Save as a change plan")')
        page.wait_for_selector('#toolboxmsg:has-text("Nothing has run")')
        self.assertEqual(toolbox.install_of(self.conn, 'box', 'uptime-kuma')['status'], 'staged')
        page.wait_for_selector('#tbhosts li[data-host="box"] [data-tool="uptime-kuma"]:has-text("staged")')
        # a cancelled removal: nothing sent, the same section stays
        page.wait_for_selector('#tbtool button:has-text("Remove from box")')
        page.evaluate("window.sfMark = document.querySelector('#tbtool')")
        page.click('#tbtool button:has-text("Remove from box")')
        page.wait_for_selector('dialog[open]')
        self.assertIn('kept: /srv/toolbox/uptime-kuma/data', page.inner_text('dialog[open]'))
        page.click('dialog[open] button:has-text("Cancel")')
        page.wait_for_selector('dialog[open]', state='detached')
        self.assertTrue(page.evaluate("window.sfMark === document.querySelector('#tbtool') && document.body.contains(window.sfMark)"))
        self.assertEqual(toolbox.install_of(self.conn, 'box', 'uptime-kuma')['status'], 'staged')
        # the WireGuard peer manager: a cancelled action changes nothing, a saved one is a wg-peer step
        page.goto(base + '/#host=box&tab=toolbox&tool=wireguard')
        page.wait_for_selector('#tbtool h3:has-text("WireGuard")')
        page.wait_for_selector('#tbtool button:has-text("Add a peer")')
        plans = self.conn.scalar('SELECT COUNT(*) FROM change_plans')
        page.evaluate("window.sfMark = document.querySelector('#tbtool')")
        page.click('#tbtool button:has-text("Add a peer")')
        page.wait_for_selector('dialog[open]')
        page.click('dialog[open] button:has-text("Cancel")')
        page.wait_for_selector('dialog[open]', state='detached')
        self.assertTrue(page.evaluate("window.sfMark === document.querySelector('#tbtool')"))
        self.assertEqual(self.conn.scalar('SELECT COUNT(*) FROM change_plans'), plans)
        page.click('#tbtool button:has-text("Add a peer")')
        inputs = page.locator('dialog[open] input')
        inputs.nth(1).fill('B' * 43 + '=')
        inputs.nth(2).fill('10.8.0.2/32')
        page.click('dialog[open] button[type=submit]')
        page.wait_for_selector('#toolboxmsg:has-text("Add a peer: saved as the change plan")')
        self.assertEqual(self.conn.scalar('SELECT COUNT(*) FROM change_plans'), plans + 1)
        self.assertIn('wg-peer', self.conn.scalar('SELECT body_json FROM change_plans ORDER BY plan_id DESC LIMIT 1'))
        # the editor: checked, with the command that signs it where the key is
        page.click('#tbcustom summary')
        page.fill('#tbyaml', CUSTOM)
        page.click('#tbcustom button:has-text("Check it")')
        page.wait_for_selector('#tbedout:has-text("passes the schema")')
        self.assertIn('ssh-keygen -Y sign -f ~/.ssh/id_ed25519 -n storageforge-catalog whoami.yaml', page.inner_text('#tbedout'))
        page.fill('#tbyaml', CUSTOM.replace('format: 1', 'format: 2'))
        page.click('#tbcustom button:has-text("Check it")')
        page.wait_for_selector('#tbedout li:has-text("format is 1")')
        page.fill('#tbyaml', CUSTOM)
        page.click('#tbcustom button:has-text("Dry run on the host")')
        page.wait_for_selector('#tbedout:has-text("Nothing was saved")')
        # bundles, role profiles with per-host exclusions, and tool dashboard tile
        page.wait_for_selector('#tbdash h3:has-text("Tool dashboard")')
        page.click('#tbbundles summary')
        page.click('#tbbundles li[data-bundle="observability"] button:has-text("Preview bundle")')
        page.wait_for_selector('#tbbundlereport:has-text("Observability on box")')
        page.click('#tbprofiles summary')
        page.select_option('#tbrolepick', 'nas')
        page.uncheck('#tbroleexcl input[value="samba"]')
        page.click('#tbprofiles button:has-text("Save role")')
        page.wait_for_selector('#toolboxmsg:has-text("Saved role nas for box")')
        self.assertEqual(errors, [])


if __name__ == '__main__':
    unittest.main()
