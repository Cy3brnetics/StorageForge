"""The key enclave in a real browser (roadmap section 14): the Keys page and the security view say whether the extra layer is there, a
locked enclave is unlocked by typing the vault secret, and once someone has enrolled the page asks for the password that the enclave
itself checks before a key is made. The real enclave program on a socket file. Needs playwright with its chromium, and cargo."""
import os
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sync_playwright = None

from storageforge_index import enclave, server, users, vault
from storageforge_index.db import Database
from test_enclave import SECRET, build

PW = 'correct horse battery staple'


@unittest.skipUnless(sync_playwright, 'needs playwright (CI has it)')
@unittest.skipUnless(shutil.which('cargo'), 'needs cargo to build the enclave (CI builds it)')
class BrowserEnclave(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from werkzeug.serving import make_server
        cls.tmp = tempfile.TemporaryDirectory()
        tmp = Path(cls.tmp.name)
        cls.db = Database(f'sqlite:///{tmp}/idx.db')
        conn = cls.db.connect()
        cls.db.migrate(conn)
        users.create(conn, 'admin', PW, 'admin')
        with vault.Vault(cls.db, conn, SECRET) as made:
            made.init()
        conn.close()
        cls.address = f'unix:{tmp}/enclave.sock'
        cls.proc = subprocess.Popen([str(build()), '--unix', f'{tmp}/enclave.sock'], stderr=subprocess.DEVNULL)
        cls.env = mock.patch.dict(os.environ, {'STORAGEFORGE_ENCLAVE': cls.address, 'XDG_RUNTIME_DIR': str(tmp), 'STORAGEFORGE_ENCLAVE_RUN_DIR': str(tmp)})
        cls.env.start()
        for name in ('STORAGEFORGE_VAULT_SECRET', 'STORAGEFORGE_VAULT_SECRET_FILE'):
            os.environ.pop(name, None)
        until = time.time() + 15
        while True:
            try:
                enclave.Enclave(cls.address).status()
                break
            except enclave.EnclaveError:
                if time.time() > until:
                    raise
                time.sleep(0.05)
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
        cls.proc.kill()
        cls.proc.wait()
        cls.env.stop()
        cls.tmp.cleanup()

    def setUp(self):
        self.page = self.browser.new_page()
        self.addCleanup(self.page.close)
        self.page.set_default_timeout(30000)
        self.errors, self.sent = [], []
        self.page.on('request', lambda r: self.sent.append((r.method, r.url.split('/', 3)[3])) if r.method != 'GET' else None)
        self.page.on('pageerror', lambda e: self.errors.append(str(e)))
        self.page.on('console', lambda m: self.errors.append(m.text) if 'Content Security Policy' in m.text else None)
        self.page.goto(self.base + '/login')
        self.page.fill('input[type=text], input[name=username], #username', 'admin')
        self.page.fill('input[type=password]', PW)
        self.page.press('input[type=password]', 'Enter')
        self.page.wait_for_url(self.base + '/**')
        self.page.wait_for_selector('.tabs button')
        self.page.wait_for_selector('html[data-route-ready]', state='attached')

    def keys(self):
        self.page.goto(self.base + '/admin#/enclave')
        self.page.wait_for_selector('#enclavebox:not([hidden]) b')
        return self.page.inner_text('#enclavebox')

    def wait_for_label(self, label):
        self.page.wait_for_function('(want) => (document.querySelector("#enclavebox b") || {}).textContent === want', arg=label)

    def test_a_locked_enclave_is_unlocked_from_the_keys_page_and_then_checks_the_person_itself(self):
        said = self.keys()
        self.assertIn('Key enclave: locked', said)
        self.assertIn('for development and tests only', said, 'a program on a socket file is not passed off as the micro VM')
        self.page.fill('#enclavebox input[aria-label="Vault secret"]', 'w' * 48)
        self.page.click('#enclavebox button[type=submit]')
        self.page.wait_for_selector('.sf-toast.error')
        self.assertIn('wrong vault secret', self.page.inner_text('.sf-toast.error'))
        self.page.click('.sf-toast.error button')
        self.wait_for_label('Key enclave: locked')
        self.page.fill('#enclavebox input[aria-label="Vault secret"]', SECRET.decode())
        self.page.click('#enclavebox button[type=submit]')
        self.wait_for_label('Key enclave: on')
        self.assertIn('Step-up is off', self.page.inner_text('#enclavebox'))
        # a key is made on the web app's word, until someone enrolls
        self.page.click('#adnav button[data-sec="keys"]')
        self.page.fill('#genname', 'before')
        self.page.click('#genform button[type=submit]')
        self.page.wait_for_function('() => [...document.querySelectorAll("#keys li")].some((li) => li.textContent.includes("before"))')
        self.page.click('#adnav button[data-sec="enclave"]')
        self.page.click('#enclavebox button:has-text("Enroll your password with the enclave")')
        self.page.fill('dialog[open] input[type=password]', PW)
        self.page.click('dialog[open] button[type=submit]')
        self.page.wait_for_function('() => document.querySelector("#enclavebox").textContent.includes("Step-up is on")')
        self.assertIn('Your password is enrolled', self.page.inner_text('#enclavebox'))
        # now the enclave wants the person: the page asks, the enclave checks, and the key is made
        self.page.click('#adnav button[data-sec="keys"]')
        self.page.fill('#genname', 'after')
        self.page.click('#genform button[type=submit]')
        self.page.wait_for_selector('dialog[open] #stepuptitle')
        self.page.fill('dialog[open] input[type=password]', 'not the password at all')
        self.page.click('dialog[open] button[type=submit]')
        self.page.wait_for_function('() => /wrong password/.test((document.querySelector("dialog[open] .sf-err") || {}).textContent || "")')
        self.assertEqual(self.page.locator('#keys li', has_text='after').count(), 0)
        self.page.fill('dialog[open] input[type=password]', PW)
        self.page.click('dialog[open] button[type=submit]')
        self.page.wait_for_function('() => [...document.querySelectorAll("#keys li")].some((li) => li.textContent.includes("after"))')
        self.assertEqual(self.errors, [])
        # every one of those requests carried the code of the moment in its path, made in the page and checked by the server (routecode.py)
        paths = [p for m, p in self.sent if m == 'POST' and 'login' not in p and 'reauth' not in p]
        self.assertTrue(paths)
        for path in paths:
            self.assertRegex(path, r'^api/~[0-9a-f]{8}/(keys|enclave/unlock|enclave/stepup(/enroll)?)$')
        # the security view says the same thing in its own words
        self.page.goto(self.base + '/security#/overview')
        self.page.wait_for_selector('#sec-enclave b')
        self.assertEqual(self.page.inner_text('#sec-enclave b'), 'Key enclave: on')

    def test_where_the_enclave_is_off_both_pages_say_the_extra_layer_is_not_there(self):
        from storageforge_index import enclave_vm
        with mock.patch.dict(os.environ), mock.patch.object(enclave_vm, 'missing', lambda which=None: '/dev/kvm is not here or not usable by this account'):
            del os.environ['STORAGEFORGE_ENCLAVE']
            said = self.keys()
            self.assertIn('Key enclave: off', said)
            self.assertIn('the extra layer is not there', said)
            self.assertIn('/dev/kvm is not here', said)
            self.assertEqual(self.page.locator('#enclavebox input').count(), 0, 'nothing to unlock')
            self.page.goto(self.base + '/security#/overview')
            self.page.wait_for_selector('#sec-enclave b')
            self.assertIn('Key enclave: off', self.page.inner_text('#sec-enclave'))
        self.assertEqual(self.errors, [])
