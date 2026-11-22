"""Keys, Platform connections, in a real browser against a real TLS platform on 127.0.0.1 (apifake.py): the guide comes first, then the
token, then the certificate; a cancelled certificate dialog sends nothing and does not redraw the page; a test reads the token back; the
token is never on the page after it is sent; the connection is removed."""
import threading
import unittest

try:
    from test_apiconn import TOKEN, TOKEN_ID, Base
    from test_apipve import pve_routes
except ImportError:      # run as tests.test_x from the project folder
    from tests.test_apiconn import TOKEN, TOKEN_ID, Base
    from tests.test_apipve import pve_routes
from storageforge_index import apiconn, server, users

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sync_playwright = None

PW = 'a long enough password'


@unittest.skipUnless(sync_playwright, 'needs playwright (CI has it)')
class BrowserPlatforms(Base):
    def test_guide_then_token_then_certificate(self):
        from werkzeug.serving import make_server
        self.fake.routes.update(pve_routes())
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
        page.goto(base + '/admin#/secrets')
        page.wait_for_selector('#platformbox li:has-text("No platform connections yet.")')
        page.click('#platadd summary')
        self.assertTrue(page.is_hidden('#plattokenform'), 'the token is not asked for before the guide is shown')
        page.select_option('#platkind', 'pve')
        page.click('#platadd button:has-text("Show what the token needs")')
        page.wait_for_selector('#platformguide')
        guide = page.inner_text('#platformguide')
        self.assertIn('PVEAuditor', guide)
        self.assertIn('pveum user token add storageforge@pve storageforge -privsep 1', guide)
        self.assertIn('not lab-tested', guide)
        page.fill('#platname', 'lab')
        page.fill('#platurl', self.fake.url)
        page.fill('#plattokenid', TOKEN_ID)
        page.fill('#plattoken', TOKEN)
        page.click('#plattokenform button[type=submit]')
        page.wait_for_selector('dialog[open]')
        self.assertIn(self.fake.fingerprint, page.inner_text('dialog[open]'))
        page.click('dialog[open] button:has-text("Cancel")')
        page.wait_for_selector('#platformbox li[data-platform="lab"]:has-text("certificate not accepted yet")')
        self.assertEqual(self.fake.requests, [], 'nothing was sent before the certificate was accepted')
        self.assertNotIn(TOKEN, page.content())
        # a cancelled dialog changes nothing on the page: the same list element stays, and nothing is sent
        page.evaluate("window.sfMark = document.querySelector('#platformlist')")
        page.click('#platformbox li[data-platform="lab"] button:has-text("Accept the certificate")')
        page.wait_for_selector('dialog[open]')
        page.click('dialog[open] button:has-text("Cancel")')
        page.wait_for_selector('dialog[open]', state='detached')
        self.assertTrue(page.evaluate("window.sfMark === document.querySelector('#platformlist') && document.body.contains(window.sfMark)"))
        self.assertIsNone(apiconn.by_name(self.conn, 'lab')['cert_sha256'])
        page.click('#platformbox li[data-platform="lab"] button:has-text("Accept the certificate")')
        page.click('dialog[open] button[type=submit]')
        page.wait_for_selector('#platformbox li[data-platform="lab"]:has-text("not read yet")')
        page.click('#platformbox li[data-platform="lab"] button:has-text("Test")')
        page.wait_for_selector('#platformbox li[data-platform="lab"]:has-text("exactly what the guide asks")')
        self.assertIn('Read ', page.inner_text('#platformmsg'))
        self.assertTrue(self.fake.requests and all(r['method'] == 'GET' for r in self.fake.requests))
        self.assertNotIn(TOKEN, page.content())
        page.click('#platformbox li[data-platform="lab"] button:has-text("Remove")')
        page.fill('dialog[open] input[type=text]', 'lab')
        page.click('dialog[open] button[type=submit]')
        page.wait_for_selector('#platformbox li:has-text("No platform connections yet.")')
        self.assertEqual(apiconn.listing(self.conn), [])
        self.assertEqual(errors, [])


if __name__ == '__main__':
    unittest.main()
